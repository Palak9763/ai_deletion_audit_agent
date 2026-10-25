"""
loaders/media_loader.py — PDF and PNG evidence handlers.

Design constraints (from Phase 1 instructions):
- Attach media files to a user ONLY through explicit link events in system_activity.csv
  (LINK_RESOURCE_IDENTITY event type). Never guess by fuzzy text match.
- Extract text via OCR (pytesseract) or PyMuPDF for PDFs.
- Store OCR text and confidence in extras.
- State words (paused, blocked, redacted, etc.) are candidate signals, not facts.
- If no OCR library is available, mark as unlinked with a warning.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from code.models import MediaLink, ParseReject, ParseResult, ParseWarning

# Optional imports — graceful degradation
try:
    import fitz  # PyMuPDF
    _PYMUPDF_OK = True
except ImportError:
    _PYMUPDF_OK = False

try:
    from PIL import Image
    import pytesseract
    _TESSERACT_OK = True
except ImportError:
    _TESSERACT_OK = False


# ---------------------------------------------------------------------------
# Candidate signal keywords (OCR output treated as noisy)
# ---------------------------------------------------------------------------

_STATE_KEYWORDS = re.compile(
    r"\b(deleted|absent|redacted|anonymized|anonymised|blocked|disabled|"
    r"active|present|found|not.?found|enabled|stopped|paused|pending|"
    r"retained|legal.?hold|restore.?blocked)\b",
    re.IGNORECASE,
)


def _extract_candidate_signals(text: str) -> list[str]:
    """Return unique state-word tokens found in OCR text."""
    found = [m.group(0).lower() for m in _STATE_KEYWORDS.finditer(text)]
    # Deduplicate while preserving order
    seen: set[str] = set()
    result = []
    for f in found:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result


# ---------------------------------------------------------------------------
# PDF text extraction
# ---------------------------------------------------------------------------

def _extract_pdf_text(path: Path) -> tuple[Optional[str], Optional[float]]:
    """
    Extract text from a PDF.
    Returns (text, confidence) where confidence is 1.0 for native PDF text,
    0.0–1.0 for OCR, or None if extraction failed.
    """
    # Try PyMuPDF (native text layer first)
    if _PYMUPDF_OK:
        try:
            doc = fitz.open(str(path))
            pages = []
            for page in doc:
                pages.append(page.get_text())
            doc.close()
            text = "\n".join(pages).strip()
            if text:
                return text, 1.0
        except Exception:
            pass

    # Try pytesseract on rendered pages (OCR fallback)
    if _PYMUPDF_OK and _TESSERACT_OK:
        try:
            doc = fitz.open(str(path))
            pages = []
            confs = []
            for page in doc:
                pix = page.get_pixmap(dpi=150)
                import io
                img_bytes = pix.tobytes("png")
                img = Image.open(io.BytesIO(img_bytes))
                data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
                page_text = " ".join(
                    w for w, c in zip(data["text"], data["conf"])
                    if w.strip() and int(c) >= 0
                )
                conf_vals = [int(c) for c in data["conf"] if int(c) >= 0]
                pages.append(page_text)
                if conf_vals:
                    confs.append(sum(conf_vals) / len(conf_vals))
            doc.close()
            text = "\n".join(pages).strip()
            avg_conf = sum(confs) / len(confs) if confs else 0.5
            return text, avg_conf / 100.0
        except Exception:
            pass

    return None, None


# ---------------------------------------------------------------------------
# PNG / image text extraction
# ---------------------------------------------------------------------------

def _extract_image_text(path: Path) -> tuple[Optional[str], Optional[float]]:
    """Extract text from a PNG screenshot via pytesseract."""
    if not _TESSERACT_OK:
        return None, None
    try:
        img = Image.open(str(path))
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        text = " ".join(
            w for w, c in zip(data["text"], data["conf"])
            if w.strip() and int(c) >= 0
        )
        conf_vals = [int(c) for c in data["conf"] if int(c) >= 0]
        avg_conf = (sum(conf_vals) / len(conf_vals) / 100.0) if conf_vals else 0.5
        return text, avg_conf
    except Exception:
        return None, None


# ---------------------------------------------------------------------------
# Media link builder
# ---------------------------------------------------------------------------

def build_media_link(
    file_id: str,
    file_path: str,
    path: Path,
    activity_links: dict[str, dict],  # file_id -> {user_id, activity_id} from system_activity
) -> tuple[MediaLink, list[ParseWarning]]:
    """
    Build a MediaLink for one PDF or PNG file.

    activity_links: pre-built mapping from evidence file_id to link info.
    Populated by the pipeline from LINK_RESOURCE_IDENTITY events in system_activity.csv.
    If no link exists, the file is marked unlinked.
    """
    warnings: list[ParseWarning] = []
    link_info = activity_links.get(file_id, {})

    # Extract text
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        ocr_text, ocr_conf = _extract_pdf_text(path)
        if ocr_text is None:
            warnings.append(ParseWarning(file_id, "pdf_extraction",
                                          "No text extracted — pytesseract/PyMuPDF unavailable or failed"))
    elif suffix in (".png", ".jpg", ".jpeg"):
        ocr_text, ocr_conf = _extract_image_text(path)
        if ocr_text is None:
            warnings.append(ParseWarning(file_id, "image_extraction",
                                          "No text extracted — pytesseract unavailable or failed"))
    else:
        ocr_text, ocr_conf = None, None
        warnings.append(ParseWarning(file_id, "media_extraction",
                                      f"Unknown media suffix {suffix!r}"))

    candidate_signals = _extract_candidate_signals(ocr_text) if ocr_text else []

    media_link = MediaLink(
        file_id=file_id,
        file_path=file_path,
        linked_user_id=link_info.get("user_id"),
        linked_via_activity_id=link_info.get("activity_id"),
        ocr_text=ocr_text,
        ocr_confidence=ocr_conf,
        candidate_signals=candidate_signals,
        is_linked=bool(link_info),
    )
    return media_link, warnings


# ---------------------------------------------------------------------------
# Build activity_links map from system_activity records
# ---------------------------------------------------------------------------

def build_activity_links_from_records(activity_records: list) -> dict[str, dict]:
    """
    Scan system_activity Records for LINK_RESOURCE_IDENTITY events and build
    a mapping: evidence file_id -> {user_id, activity_id}.

    Per Phase 1 spec: only LINK_RESOURCE_IDENTITY events may link media to a user.
    If that event type is absent (as it appears to be in this dataset), the
    mapping will be empty and all media files will be unlinked.
    """
    links: dict[str, dict] = {}
    for rec in activity_records:
        event_type = rec.extras.get("event_type", "")
        if event_type != "LINK_RESOURCE_IDENTITY":
            continue
        # Expected fields: resource_id contains the file_id of the media evidence,
        # details contains the user_id
        file_id = rec.extras.get("resource_id", "")
        user_id = rec.extras.get("details", "")
        if file_id and user_id:
            links[file_id] = {
                "user_id": user_id,
                "activity_id": rec.record_id,
            }
    return links
