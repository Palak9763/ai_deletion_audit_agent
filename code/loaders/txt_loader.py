"""
loaders/txt_loader.py — Parser for plain-text record files.

Observed format: customer_account_handover_*.txt
Lines:
  - <ISO-timestamp> | <system> | <resource_id> | <record_type> | <result/state> | <subject_reference>

Non-blank lines that do not match the data format go to rejects with a descriptive reason.
Zero silent drops: total_rows = records + rejects.
"""
from __future__ import annotations

import re
from pathlib import Path

from code.models import (
    Identifier, ParseReject, ParseResult, ParseWarning, Record,
    infer_category,
)
from code.normalizers import (
    classify_and_normalize,
    normalize_email,
    normalize_phone,
    normalize_user_id,
    parse_timestamp,
)

# Pattern for data lines:
# - 2026-10-01T12:00:00Z | account_service | account_146 | USER_PROFILE | NOT_FOUND | e.lindberg18@yahoo.com
_DATA_LINE_RE = re.compile(
    r"^-\s+(\d{4}-\d{2}-\d{2}T[\d:Z.+\-]+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*(.+?)\s*$"
)

_RESULT_TO_STATE = {
    "FOUND": "PRESENT",
    "NOT_FOUND": "ABSENT",
    "IDENTIFIABLE": "PRESENT",
    "ANONYMIZED": "ANONYMIZED",
    "REDACTED": "REDACTED",
    "ACTIVE": "ACTIVE",
    "DISABLED": "DISABLED",
    "BLOCKED": "BLOCKED",
}


def parse_txt_evidence(path: Path, file_id: str) -> ParseResult:
    """
    Parse a customer_account_handover_*.txt file.
    Returns one Record per data line, with headers/unparseable lines preserved in rejects.
    """
    result = ParseResult()
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        result.rejects.append(ParseReject(file_id, "file", str(path), f"Cannot read: {e}"))
        return result

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        if not line.startswith("-"):
            result.rejects.append(
                ParseReject(file_id, line_no, raw_line, "Header / narrative text line")
            )
            continue

        m = _DATA_LINE_RE.match(line)
        if not m:
            result.rejects.append(
                ParseReject(
                    file_id,
                    line_no,
                    raw_line,
                    "Line matches '-' prefix but not full data pattern",
                )
            )
            continue

        ts_raw, system, resource_id, record_type, result_val, subject_ref = m.groups()
        system = system.strip()
        resource_id = resource_id.strip()
        record_type = record_type.strip()
        result_val = result_val.strip()
        subject_ref = subject_ref.strip()

        try:
            ts = parse_timestamp(ts_raw)
        except ValueError as e:
            result.rejects.append(
                ParseReject(file_id, line_no, raw_line, f"Bad timestamp {ts_raw!r}: {e}")
            )
            continue

        category = infer_category(system, record_type)
        state = _RESULT_TO_STATE.get(result_val.upper(), result_val)

        identifiers = []
        if subject_ref and subject_ref.lower() not in (
            "null",
            "none",
            "",
            "no direct identifier",
        ):
            itype, norm = classify_and_normalize(subject_ref)
            identifiers.append(Identifier(itype, subject_ref, norm))

        rec = Record(
            source=file_id,
            record_id=resource_id,
            timestamp=ts,
            system=system,
            data_category=category,
            identifiers=identifiers,
            state=state,
            raw_ref={"file": str(path), "row_or_offset": line_no},
            extras={
                "record_type": record_type,
                "result_raw": result_val,
                "subject_reference_raw": subject_ref,
            },
        )
        result.records.append(rec)

    return result
