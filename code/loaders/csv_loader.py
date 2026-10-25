"""
loaders/csv_loader.py — Parsers for all CSV dataset files.

Handles:
  - user_identities.csv
  - user_audit_log.csv
  - system_activity.csv
  - deletion_requests.csv / sample_deletion_requests.csv
  - deletion_rules.csv         (policy, not evidence records)
  - evidence_files.csv         (manifest, not evidence records)

Each parser returns ParseResult (records + warnings + rejects).
"""
from __future__ import annotations

import csv
import io
from datetime import timezone
from pathlib import Path
from typing import Optional

from code.models import (
    Identifier, ParseReject, ParseResult, ParseWarning, Record,
    infer_category,
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
# Helpers
# ---------------------------------------------------------------------------

def _make_ident(id_type: str, raw: str) -> Optional[Identifier]:
    """Return an Identifier or None if value is empty/null."""
    if not raw or raw.lower() in ("null", "none", ""):
        return None
    id_type_inf, norm = classify_and_normalize(raw)
    # If caller provides an explicit type, trust it; otherwise use inferred
    actual_type = id_type if id_type != "auto" else id_type_inf
    return Identifier(id_type=actual_type, raw_value=raw, norm_value=norm)


def _safe_ts(raw: str, source: str, row_num: int, warnings: list) -> Optional[object]:
    try:
        return parse_timestamp(raw)
    except ValueError as e:
        warnings.append(ParseWarning(source, row_num, f"bad timestamp {raw!r}: {e}"))
        return None


# ---------------------------------------------------------------------------
# user_identities.csv
# ---------------------------------------------------------------------------

def parse_user_identities(path: Path, source_id: str = "user_identities") -> ParseResult:
    """
    Columns: user_id,name,email,phone,email_hash,updated_at
    Produces one USER_PROFILE record per row.
    """
    result = ParseResult()
    try:
        text = path.read_text(encoding="utf-8-sig")
    except Exception as e:
        result.rejects.append(ParseReject(source_id, "file", str(path), f"Cannot read file: {e}"))
        return result

    reader = csv.DictReader(io.StringIO(text))
    required = {"user_id", "name", "email", "phone", "email_hash", "updated_at"}
    for row_num, row in enumerate(reader, start=2):
        missing = {k for k in required if k not in row or row[k] is None}
        if missing:
            result.rejects.append(ParseReject(source_id, row_num, dict(row),
                                               f"Missing columns: {missing}"))
            continue
        ts = _safe_ts(row.get("updated_at", ""), source_id, row_num, result.warnings)
        if ts is None:
            result.rejects.append(ParseReject(source_id, row_num, dict(row),
                                               "Unparseable updated_at"))
            continue
        uid = row["user_id"].strip()
        identifiers = []
        for id_type, raw in [
            ("user_id", uid),
            ("name", row.get("name", "").strip()),
            ("email", row.get("email", "").strip()),
            ("phone", row.get("phone", "").strip()),
            ("email_hash", row.get("email_hash", "").strip()),
        ]:
            ident = _make_ident(id_type, raw)
            if ident:
                if id_type == "email":
                    ident.norm_value = normalize_email(raw)
                elif id_type == "phone":
                    ident.norm_value = normalize_phone(raw)
                elif id_type == "email_hash":
                    ident.norm_value = normalize_hash(raw)
                elif id_type == "user_id":
                    ident.norm_value = normalize_user_id(raw)
                identifiers.append(ident)
        rec = Record(
            source=source_id,
            record_id=uid,
            timestamp=ts,
            system="account_service",
            data_category="USER_PROFILE",
            identifiers=identifiers,
            state="PRESENT",
            raw_ref={"file": str(path), "row": row_num},
            extras={"raw_row": dict(row)},
        )
        result.records.append(rec)
    return result


# ---------------------------------------------------------------------------
# user_audit_log.csv
# ---------------------------------------------------------------------------

def parse_user_audit_log(path: Path, source_id: str = "user_audit_log") -> ParseResult:
    """
    Columns: audit_id,user_id,event_time,field_name,old_value,new_value
    Produces one record per audit entry.  data_category = SECONDARY_IDENTIFIER
    (it tracks identifier change history).
    """
    result = ParseResult()
    try:
        text = path.read_text(encoding="utf-8-sig")
    except Exception as e:
        result.rejects.append(ParseReject(source_id, "file", str(path), f"Cannot read file: {e}"))
        return result

    reader = csv.DictReader(io.StringIO(text))
    required = {"audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"}
    for row_num, row in enumerate(reader, start=2):
        missing = {k for k in required if k not in row or row[k] is None}
        if missing:
            result.rejects.append(ParseReject(source_id, row_num, dict(row),
                                               f"Missing columns: {missing}"))
            continue
        ts = _safe_ts(row.get("event_time", ""), source_id, row_num, result.warnings)
        if ts is None:
            result.rejects.append(ParseReject(source_id, row_num, dict(row),
                                               "Unparseable event_time"))
            continue
        field = row["field_name"].strip()
        uid = row["user_id"].strip()
        old_val = row.get("old_value", "").strip()
        new_val = row.get("new_value", "").strip()
        identifiers = [Identifier("user_id", uid, normalize_user_id(uid))]
        # Tag old and new values with their type
        for val in [old_val, new_val]:
            if val:
                itype = field if field in ("email", "phone", "email_hash") else "unknown"
                norm = normalize_email(val) if itype == "email" else (
                    normalize_phone(val) if itype == "phone" else
                    normalize_hash(val) if itype == "email_hash" else val)
                identifiers.append(Identifier(itype, val, norm))
        rec = Record(
            source=source_id,
            record_id=row["audit_id"].strip(),
            timestamp=ts,
            system="identity_service",
            data_category="SECONDARY_IDENTIFIER",
            identifiers=identifiers,
            state="PRESENT",
            raw_ref={"file": str(path), "row": row_num},
            extras={"field_name": field, "old_value": old_val, "new_value": new_val},
        )
        result.records.append(rec)
    return result


# ---------------------------------------------------------------------------
# system_activity.csv
# ---------------------------------------------------------------------------

def parse_system_activity(path: Path, source_id: str = "system_activity") -> ParseResult:
    """
    Columns: activity_id,event_time,event_type,source_system,target_system,
             resource_id,reported_result,details
    """
    result = ParseResult()
    try:
        text = path.read_text(encoding="utf-8-sig")
    except Exception as e:
        result.rejects.append(ParseReject(source_id, "file", str(path), f"Cannot read file: {e}"))
        return result

    reader = csv.DictReader(io.StringIO(text))
    required = {"activity_id", "event_time", "event_type", "source_system",
                "target_system", "resource_id", "reported_result", "details"}
    for row_num, row in enumerate(reader, start=2):
        missing = {k for k in required if k not in row or row[k] is None}
        if missing:
            result.rejects.append(ParseReject(source_id, row_num, dict(row),
                                               f"Missing columns: {missing}"))
            continue
        ts = _safe_ts(row.get("event_time", ""), source_id, row_num, result.warnings)
        if ts is None:
            result.rejects.append(ParseReject(source_id, row_num, dict(row),
                                               "Unparseable event_time"))
            continue

        target_sys = row.get("target_system", "").strip()
        event_type = row.get("event_type", "").strip()
        resource_id = row.get("resource_id", "").strip()

        # Infer data category from target system + resource_id prefix
        category = _infer_category_from_activity(target_sys, resource_id, event_type)

        identifiers = []
        if resource_id:
            identifiers.append(Identifier("resource_id", resource_id, resource_id))

        # State from reported_result
        result_map = {
            "SUCCESS": "PRESENT", "FAILED": "UNKNOWN",
            "PARTIAL": "UNKNOWN", "": "UNKNOWN",
        }
        state = result_map.get(row.get("reported_result", "").strip().upper(), "UNKNOWN")

        rec = Record(
            source=source_id,
            record_id=row["activity_id"].strip(),
            timestamp=ts,
            system=target_sys,
            data_category=category,
            identifiers=identifiers,
            state=state,
            raw_ref={"file": str(path), "row": row_num},
            extras={
                "event_type": event_type,
                "source_system": row.get("source_system", "").strip(),
                "reported_result": row.get("reported_result", "").strip(),
                "details": row.get("details", "").strip(),
            },
        )
        result.records.append(rec)
    return result


def _infer_category_from_activity(system: str, resource_id: str, event_type: str) -> str:
    """Infer data_category from target system and resource_id prefix."""
    rid = resource_id.lower()
    sys = system.lower()
    if rid.startswith("account_"):
        return "USER_PROFILE"
    if rid.startswith("search_"):
        return "SEARCH_INDEX_ENTRY"
    if rid.startswith("analytics_"):
        return "ANALYTICS_PROFILE"
    if rid.startswith("support_"):
        return "SUPPORT_MESSAGE"
    if rid.startswith("export_"):
        return "USER_EXPORT"
    if rid.startswith("backup_"):
        return "BACKUP_ARCHIVE"
    if rid.startswith("data_flow_"):
        return "DATA_FLOW"
    if rid.startswith("audit_record_"):
        return "SECURITY_AUDIT_LOG"
    if rid.startswith("tombstone_"):
        return "ACCOUNT_TOMBSTONE"
    if rid.startswith("cache_"):
        return "CACHE_ENTRY"
    if rid.startswith("marketing_"):
        return "MARKETING_PROFILE"
    if rid.startswith("email_delivery_"):
        return "EMAIL_DELIVERY_LOG"
    # Fallback to system heuristic
    if "security" in sys:
        return "SECURITY_AUDIT_LOG"
    if "backup" in sys:
        return "BACKUP_ARCHIVE"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# deletion_requests.csv (and sample variant)
# ---------------------------------------------------------------------------

def parse_deletion_requests(path: Path, source_id: str = "deletion_requests") -> ParseResult:
    """
    Columns: case_id,email,requested_at,reported_status,reported_at,audit_at,request_text
    Produces one record per deletion request.
    data_category = USER_PROFILE (the subject of the request).
    """
    result = ParseResult()
    try:
        text = path.read_text(encoding="utf-8-sig")
    except Exception as e:
        result.rejects.append(ParseReject(source_id, "file", str(path), f"Cannot read file: {e}"))
        return result

    reader = csv.DictReader(io.StringIO(text))
    required = {"case_id", "email", "requested_at", "reported_status",
                "reported_at", "audit_at", "request_text"}
    for row_num, row in enumerate(reader, start=2):
        missing = {k for k in required if k not in row or row[k] is None}
        if missing:
            result.rejects.append(ParseReject(source_id, row_num, dict(row),
                                               f"Missing columns: {missing}"))
            continue
        # audit_at is the canonical timestamp for filtering
        ts = _safe_ts(row.get("audit_at", ""), source_id, row_num, result.warnings)
        if ts is None:
            result.rejects.append(ParseReject(source_id, row_num, dict(row),
                                               "Unparseable audit_at"))
            continue
        email_raw = row.get("email", "").strip()
        identifiers = []
        if email_raw:
            identifiers.append(Identifier("email", email_raw, normalize_email(email_raw)))
        # Also parse requested_at and reported_at but don't fail on them
        extras: dict = {
            "reported_status": row.get("reported_status", "").strip(),
            "request_text": row.get("request_text", "").strip(),
        }
        for field_name, col in [("requested_at", "requested_at"), ("reported_at", "reported_at")]:
            raw_ts = row.get(col, "").strip()
            try:
                extras[field_name] = parse_timestamp(raw_ts).isoformat() if raw_ts else None
            except ValueError:
                extras[field_name] = raw_ts
                result.warnings.append(ParseWarning(source_id, row_num,
                                                     f"bad {col}: {raw_ts!r}"))
        rec = Record(
            source=source_id,
            record_id=row["case_id"].strip(),
            timestamp=ts,
            system="deletion_workflow",
            data_category="USER_PROFILE",
            identifiers=identifiers,
            state=row.get("reported_status", "UNKNOWN").strip(),
            raw_ref={"file": str(path), "row": row_num},
            extras=extras,
        )
        result.records.append(rec)
    return result
