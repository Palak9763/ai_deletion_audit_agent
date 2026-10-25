"""
loaders/log_loader.py — Parser for structured service logs across all formats.

Handles:
  1. Standard key=value logs (service_events, support_replica, readback logs)
  2. Bracketed trace logs: <ts> [LEVEL] [SERVICE] [TRACE] EVENT: key=val ...
  3. Pipe-delimited stream logs: <ts> | LEVEL | SERVICE | TRACE | EVENT | key=val ...
  4. Structured JSON lines logs: <ts> {"severity": ..., "event": ..., ...}
  5. Cloud runtime logs: <ts> requestId=... level=... message="key=\"val\" ..."
  6. Syslog RFC 5424 logs: <ts> <PRI>1 host service procid - - level=... key=val ...
  7. Diagnostic / notification delivery logs: <ts> LEVEL service=... event=... key=val ...

Ensures zero silent drops: every line in a log file produces either a Record or a ParseReject.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from code.models import (
    Identifier, ParseReject, ParseResult, ParseWarning, Record,
)
from code.normalizers import (
    classify_and_normalize,
    normalize_email,
    normalize_hash,
    normalize_phone,
    normalize_user_id,
    parse_timestamp,
)


# ---------------------------------------------------------------------------
# Tokenizers & Patterns
# ---------------------------------------------------------------------------

_ISO_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)")
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s"]+)')
_BRACKET_RE = re.compile(r"^\[([A-Z]+)\]\s*\[([a-zA-Z0-9_\-]+)\]\s*\[([a-zA-Z0-9_\-]+)\]\s*([a-zA-Z0-9_]+):\s*(.*)$")
_SYSLOG_RE = re.compile(r"^<\d+>1\s+\S+\s+(\S+)\s+\S+\s+-\s+-\s+(.*)$")

_NULL_VALS = {"", "null", "none", "nil", "undefined"}


def _parse_line_to_kv(line: str) -> tuple[str, dict[str, str]]:
    """
    Extract timestamp and key=value dict from any log line format.
    Returns (raw_timestamp, kv_dict).
    """
    ts_match = _ISO_TS_RE.match(line)
    if not ts_match:
        return "", {}
    ts_raw = ts_match.group(1)
    rest = line[len(ts_raw):].strip()

    # 1. JSON lines
    if rest.startswith("{") and rest.endswith("}"):
        try:
            parsed = json.loads(rest)
            if isinstance(parsed, dict):
                return ts_raw, {str(k): str(v) for k, v in parsed.items()}
        except Exception:
            pass

    kv: dict[str, str] = {}

    # 2. Pipe-delimited format
    if rest.startswith("|"):
        parts = [p.strip() for p in rest.split("|") if p.strip()]
        if len(parts) >= 4:
            kv["level"] = parts[0]
            kv["service"] = parts[1]
            kv["trace_id"] = parts[2]
            kv["event"] = parts[3]
            if len(parts) >= 5:
                for m in _KV_RE.finditer(parts[4]):
                    k, v = m.group(1), m.group(2)
                    if v.startswith('"') and v.endswith('"'):
                        v = v[1:-1].replace('\\"', '"')
                    kv[k] = v
            return ts_raw, kv

    # 3. Bracketed trace format
    bm = _BRACKET_RE.match(rest)
    if bm:
        kv["level"] = bm.group(1)
        kv["service"] = bm.group(2)
        kv["trace_id"] = bm.group(3)
        kv["event"] = bm.group(4)
        for m in _KV_RE.finditer(bm.group(5)):
            k, v = m.group(1), m.group(2)
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1].replace('\\"', '"')
            kv[k] = v
        return ts_raw, kv

    # 4. Syslog format
    sm = _SYSLOG_RE.match(rest)
    if sm:
        kv["service"] = sm.group(1)
        rest = sm.group(2)

    # 5. Diagnostic / notification (starts with LEVEL without '=')
    level_match = re.match(r"^([A-Z]{3,5})\s+(.*)$", rest)
    if level_match and "=" not in level_match.group(1):
        kv["level"] = level_match.group(1)
        rest = level_match.group(2)

    # General KV parse
    for m in _KV_RE.finditer(rest):
        k, v = m.group(1), m.group(2)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('\\"', '"')
        kv[k] = v

    # Nested message="..." unpacking (cloud runtime)
    if "message" in kv and ("=" in kv["message"]):
        inner = kv["message"]
        for m in _KV_RE.finditer(inner):
            k, v = m.group(1), m.group(2)
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1].replace('\\"', '"')
            if k not in kv or k in ("event", "resource_id", "instance"):
                kv[k] = v

    return ts_raw, kv


# ---------------------------------------------------------------------------
# Events that determine record state
# ---------------------------------------------------------------------------

_OUTCOME_EVENTS = {
    # Account
    "profile_lookup_completed",
    "profile_lookup_started",
    # Search
    "index_query_completed",
    "index_query_started",
    # Analytics
    "analytics_profile_scan_started",
    "analytics_identity_scan",
    "analytics_profile_read",
    "analytics_profile_read_started",
    "analytics_profile_read_completed",
    # Support
    "message_pii_scan",
    "attachment_pii_scan",
    "message_read",
    "support_ticket_read_started",
    "support_ticket_read_completed",
    "contact_query_completed",
    "contact_lookup_completed",
    "attachment_scan_completed",
    # Backup
    "restore_policy_check_completed",
    "restore_policy_read_started",
    "restore_policy_read_completed",
    "restore_candidate_evaluated",
    "restore_authorization_completed",
    # Integration / connector
    "connector_config_read_started",
    "connector_config_read_completed",
    "connector_config_loaded",
    "connector_heartbeat",
    # Security
    "audit_record_read_started",
    "audit_record_read_completed",
    # Generic record diagnostic / delivery
    "record_lookup",
    "export_download_check_completed",
    "export_metadata_read_started",
    "export_metadata_read_completed",
    "retained_order_loaded",
    "deletion_marker_check",
    "thumbnail_failed",
}


def _infer_state_from_log(event: str, kv: dict[str, str]) -> str:
    # Explicit result field
    res = kv.get("result", "").strip().upper()
    if res in ("FOUND", "HIT"):
        return "PRESENT"
    if res in ("NOT_FOUND", "MISS"):
        return "ABSENT"

    if event == "profile_lookup_completed":
        rows = kv.get("rows", "")
        status = kv.get("http_status", "")
        if rows == "0" or status == "404":
            return "ABSENT"
        if status == "200" or rows == "1":
            return "PRESENT"

    if event == "index_query_completed":
        result = kv.get("result", "")
        return "PRESENT" if result == "hit" else "ABSENT"

    if event in ("analytics_identity_scan", "message_pii_scan", "attachment_pii_scan"):
        return "PRESENT"

    if event in ("analytics_profile_read", "analytics_profile_read_completed"):
        pii_fields = [kv.get("email", "null"), kv.get("phone", "null"),
                      kv.get("customer_reference", "null"), kv.get("email_hash", "null")]
        if all(v in _NULL_VALS or v is None for v in pii_fields):
            return "ANONYMIZED"
        return "PRESENT"

    if event in ("restore_policy_check_completed", "restore_policy_read_completed",
                 "restore_authorization_completed", "restore_candidate_evaluated"):
        restore_allowed = kv.get("restore_allowed", "")
        if restore_allowed in ("true", "1"):
            return "ACTIVE"
        if restore_allowed in ("false", "0"):
            return "BLOCKED"

    if event in ("connector_config_read_completed", "connector_config_loaded", "connector_heartbeat"):
        enabled = kv.get("enabled", "")
        if enabled in ("true", "1"):
            return "ACTIVE"
        if enabled in ("false", "0"):
            return "DISABLED"

    if event == "audit_record_read_completed":
        rows = kv.get("rows", "")
        return "PRESENT" if rows and rows != "0" else "ABSENT"

    if event == "support_ticket_read_completed":
        pii = any(kv.get(f) and kv[f] not in _NULL_VALS
                  for f in ("requester_email", "requester_name", "requester_phone"))
        return "PRESENT" if pii else "REDACTED"

    return "PRESENT"


# ---------------------------------------------------------------------------
# System / Category inference
# ---------------------------------------------------------------------------

_RESOURCE_PREFIX_MAP = {
    "account_": ("account_service", "USER_PROFILE"),
    "search_": ("search_service", "SEARCH_INDEX_ENTRY"),
    "analytics_": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_": ("support_platform", "SUPPORT_MESSAGE"),
    "export_": ("export_service", "USER_EXPORT"),
    "backup_": ("backup_service", "BACKUP_ARCHIVE"),
    "data_flow_": ("integration_service", "DATA_FLOW"),
    "audit_record_": ("security_service", "SECURITY_AUDIT_LOG"),
    "tombstone_": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "cache_": ("cache_service", "CACHE_ENTRY"),
    "marketing_": ("marketing_platform", "MARKETING_PROFILE"),
    "email_delivery_": ("notification_service", "EMAIL_DELIVERY_LOG"),
}


def _infer_system_category(resource_id: str, service: str, system_override: str = "") -> tuple[str, str]:
    if system_override:
        sys = system_override.lower().strip()
        rid = resource_id.lower()
        for prefix, (_, cat) in _RESOURCE_PREFIX_MAP.items():
            if rid.startswith(prefix):
                return sys, cat
        return sys, "UNKNOWN"

    rid = resource_id.lower()
    for prefix, (sys, cat) in _RESOURCE_PREFIX_MAP.items():
        if rid.startswith(prefix):
            return sys, cat

    svc = service.lower()
    if "account" in svc or "profile" in svc:
        return "account_service", "USER_PROFILE"
    if "search" in svc:
        return "search_service", "SEARCH_INDEX_ENTRY"
    if "analytics" in svc:
        return "analytics_platform", "ANALYTICS_PROFILE"
    if "support" in svc:
        return "support_platform", "SUPPORT_MESSAGE"
    if "backup" in svc:
        return "backup_service", "BACKUP_ARCHIVE"
    if "integration" in svc or "connector" in svc:
        return "integration_service", "DATA_FLOW"
    if "security" in svc:
        return "security_service", "SECURITY_AUDIT_LOG"
    if "notification" in svc or "delivery" in svc:
        return "notification_service", "EMAIL_DELIVERY_LOG"
    return service or "unknown_service", "UNKNOWN"


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------

_IDENTITY_LOG_KEYS = {
    "lookup_key": "auto",
    "subject_key": "auto",
    "correlation_key": "auto",
    "matched_value": "auto",
    "email": "email",
    "customer_email": "email",
    "customer_reference": "user_id",
    "subject_reference": "user_id",
    "subject_ref": "user_id",
    "user_id": "user_id",
    "phone": "phone",
    "requester_phone": "phone",
    "to_address": "email",
    "recipient": "email",
}


def _extract_identifiers_from_log(kv: dict[str, str]) -> list[Identifier]:
    identifiers: list[Identifier] = []
    seen: set[tuple[str, str]] = set()

    for key, id_type in _IDENTITY_LOG_KEYS.items():
        val = kv.get(key, "")
        if not val or val.lower() in _NULL_VALS or val.lower() == "no direct identifier":
            continue
        if id_type == "auto":
            itype, norm = classify_and_normalize(val)
        else:
            itype = id_type
            if itype == "email":
                norm = normalize_email(val)
            elif itype == "phone":
                norm = normalize_phone(val)
            elif itype == "email_hash":
                norm = normalize_hash(val)
            elif itype == "user_id":
                norm = normalize_user_id(val)
            else:
                norm = val
        k = (itype, norm)
        if k not in seen:
            seen.add(k)
            identifiers.append(Identifier(itype, val, norm))
    return identifiers


# ---------------------------------------------------------------------------
# Main log parser
# ---------------------------------------------------------------------------

def parse_log_evidence(path: Path, file_id: str) -> ParseResult:
    """
    Parse a structured service log file.
    Every non-empty line produces either a Record or a ParseReject (zero silent drops).
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

        ts_raw, kv = _parse_line_to_kv(line)
        if not ts_raw:
            result.rejects.append(
                ParseReject(file_id, line_no, raw_line, "Line missing ISO timestamp")
            )
            continue

        try:
            ts = parse_timestamp(ts_raw)
        except ValueError as e:
            result.rejects.append(
                ParseReject(file_id, line_no, raw_line, f"Bad timestamp {ts_raw!r}: {e}")
            )
            continue

        resource_id = kv.get("resource_id", "").strip()
        event = kv.get("event", "").strip()
        service = kv.get("service", "").strip()
        system_override = kv.get("system", "").strip()

        # If line does not have a resource_id, it is an operational / trace line
        if not resource_id:
            result.rejects.append(
                ParseReject(
                    file_id,
                    line_no,
                    raw_line,
                    f"Operational log line without resource_id (event={event or 'none'})",
                )
            )
            continue

        system, category = _infer_system_category(resource_id, service, system_override)
        identifiers = _extract_identifiers_from_log(kv)
        state = _infer_state_from_log(event, kv)

        rec = Record(
            source=file_id,
            record_id=resource_id,
            timestamp=ts,
            system=system,
            data_category=category,
            identifiers=identifiers,
            state=state,
            raw_ref={"file": str(path), "row_or_offset": line_no},
            extras={**kv, "_raw_line": raw_line},
        )
        result.records.append(rec)

    return result
