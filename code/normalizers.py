"""
normalizers.py — Deterministic normalization for timestamps, emails, phones,
hashes, and other identifier types.

Rules derived from problem_statement.md and deletion_rules.csv:
- Emails: lowercase + strip whitespace only. Do NOT strip plus-tags or dots
  (neither the problem statement nor deletion_rules.csv says to treat them as
  equivalent). Case-insensitive matching is handled at lookup time.
- Timestamps: parse all ISO-8601 variants found in the data; always emit a
  UTC-aware datetime. The original string is preserved by callers in extras.
- Phones: strip all non-digit/+ characters, keep leading '+' for E.164.
- Hashes and IDs: kept verbatim; tagged by type.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from typing import Optional


# ---------------------------------------------------------------------------
# Timestamp normalization
# ---------------------------------------------------------------------------

# Patterns observed in the dataset (all ISO-8601 subsets):
#   2026-09-15T08:51:43Z
#   2026-09-15T08:51:43+05:30
#   2026-09-15T08:51:43.123Z
#   2026-09-15T08:51:43.123456Z

_ISO_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%SZ",
    "%Y-%m-%d",
]


def parse_timestamp(raw: str) -> datetime:
    """
    Parse any timestamp string found in the dataset.
    Returns a timezone-aware UTC datetime.
    Raises ValueError if the string cannot be parsed.
    """
    if not raw or not isinstance(raw, str):
        raise ValueError(f"Cannot parse timestamp: {raw!r}")

    s = raw.strip()

    # Fast path: trailing Z means UTC
    if s.endswith("Z"):
        s_no_z = s[:-1]
        for fmt in _ISO_FORMATS:
            if fmt.endswith("Z"):
                try:
                    dt = datetime.strptime(s, fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

    # Try format strings that include %z (handles +HH:MM offsets)
    for fmt in _ISO_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                # Assume UTC when no tz info
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    # Last resort: use fromisoformat (Python 3.11+ handles Z)
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass

    raise ValueError(f"Unrecognised timestamp format: {raw!r}")


# ---------------------------------------------------------------------------
# Email normalization
# ---------------------------------------------------------------------------

def normalize_email(raw: str) -> str:
    """
    Lowercase and strip surrounding whitespace.
    Do NOT strip plus-tags, dots, or sub-addresses.
    """
    if not raw or not isinstance(raw, str):
        return ""
    return raw.strip().lower()


def is_email(value: str) -> bool:
    """Heuristic: contains '@' and a dot in the domain part."""
    if "@" not in value:
        return False
    parts = value.rsplit("@", 1)
    return len(parts) == 2 and "." in parts[1]


# ---------------------------------------------------------------------------
# Phone normalization
# ---------------------------------------------------------------------------

# Remove everything except digits and a leading '+'
_NON_PHONE_RE = re.compile(r"[^\d+]")
_MULTI_PLUS_RE = re.compile(r"\++")


def normalize_phone(raw: str) -> str:
    """
    Strip spaces, dashes, parentheses; keep single leading '+' if present.
    Result is a canonical digit string like '+15555550100' or '15555550100'.
    """
    if not raw or not isinstance(raw, str):
        return ""
    s = raw.strip()
    has_plus = s.startswith("+")
    digits = re.sub(r"\D", "", s)
    if not digits:
        return ""
    return ("+" + digits) if has_plus else digits


# ---------------------------------------------------------------------------
# Hash / device ID normalization
# ---------------------------------------------------------------------------

def normalize_hash(raw: str) -> str:
    """Hashes are kept verbatim (case-folded to lowercase for sha256)."""
    if not raw or not isinstance(raw, str):
        return ""
    return raw.strip().lower()


# ---------------------------------------------------------------------------
# user_id normalization
# ---------------------------------------------------------------------------

def normalize_user_id(raw: str) -> str:
    """user_id values are kept as-is (e.g. 'user_01')."""
    if not raw or not isinstance(raw, str):
        return ""
    return raw.strip()


# ---------------------------------------------------------------------------
# Generic identifier classifier
# ---------------------------------------------------------------------------

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_USER_ID_RE = re.compile(r"^user_\d+$", re.IGNORECASE)
_RESOURCE_ID_RE = re.compile(
    r"^(account|search|analytics|support|export|backup|audit_record|"
    r"tombstone|data_flow|marketing|cache|email_delivery|"
    r"connector|connector_config)_\w+$",
    re.IGNORECASE,
)


def classify_and_normalize(value: str) -> tuple[str, str]:
    """
    Returns (id_type, normalized_value) for a raw string.
    id_type one of: email, email_hash, phone, user_id, resource_id, name, unknown
    """
    if not value or not isinstance(value, str):
        return "unknown", str(value or "")
    v = value.strip()
    if _USER_ID_RE.match(v):
        return "user_id", normalize_user_id(v)
    if _SHA256_RE.match(v):
        return "email_hash", normalize_hash(v)
    if is_email(v):
        return "email", normalize_email(v)
    if _RESOURCE_ID_RE.match(v):
        return "resource_id", v
    # Phone heuristic: starts with + or mostly digits
    digits = re.sub(r"\D", "", v)
    if len(digits) >= 7 and (v.startswith("+") or len(digits) / max(len(v), 1) > 0.6):
        return "phone", normalize_phone(v)
    return "unknown", v
