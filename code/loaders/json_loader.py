"""
loaders/json_loader.py — Parsers for all JSON evidence formats.

Handles these distinct schemas:
  1. customer_data_snapshot_bundle_*.json   — snapshots[] with data_store/collection/records
  2. service_resource_export_*.json         — service_exports{} with per-service sub-schemas
  3. connector_configurations_*.json        — flat records[] with system/resource_id/result
  4. security_audit_ledger_*.json           — flat records[] (same schema as connector_configurations)
  5. customer_export_manifest_*.json        — flat records[] (same schema)
  6. customer_export_jobs_*.json            — flat records[] (owner_email, resource_id, etc.)
  7. customer_analytics_report_*.json       — flat records[] with analytics fields
"""
from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path
from typing import Any, Optional

from code.models import (
    Identifier, ParseReject, ParseResult, ParseWarning, Record,
    SYSTEM_COLLECTION_TO_CATEGORY, infer_category,
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
# Helper: build an Identifier from a raw value, auto-classifying the type
# ---------------------------------------------------------------------------

def _ident(raw: Optional[str], id_type: str = "auto") -> Optional[Identifier]:
    if not raw or str(raw).strip().lower() in ("null", "none", ""):
        return None
    raw_s = str(raw).strip()
    if id_type == "auto":
        itype, norm = classify_and_normalize(raw_s)
    else:
        itype = id_type
        if itype == "email":
            norm = normalize_email(raw_s)
        elif itype == "phone":
            norm = normalize_phone(raw_s)
        elif itype == "email_hash":
            norm = normalize_hash(raw_s)
        elif itype == "user_id":
            norm = normalize_user_id(raw_s)
        else:
            norm = raw_s
    return Identifier(id_type=itype, raw_value=raw_s, norm_value=norm)


def _safe_ts(raw: Any, source: str, ctx: str, warnings: list) -> Optional[object]:
    if not raw:
        return None
    try:
        return parse_timestamp(str(raw))
    except ValueError as e:
        warnings.append(ParseWarning(source, ctx, f"bad timestamp {raw!r}: {e}"))
        return None


# ---------------------------------------------------------------------------
# Schema 1: customer_data_snapshot_bundle_*.json
# ---------------------------------------------------------------------------

def parse_snapshot_bundle(path: Path, file_id: str) -> ParseResult:
    """
    Top-level: {exported_at, source, snapshots:[{data_store, collection, captured_at, records:[…]}]}
    Each record in a snapshot has varying fields depending on the collection.
    """
    result = ParseResult()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        result.rejects.append(ParseReject(file_id, "file", str(path), f"JSON parse error: {e}"))
        return result

    file_ts_raw = data.get("exported_at", "")
    file_ts = _safe_ts(file_ts_raw, file_id, "exported_at", result.warnings)

    for snap_idx, snap in enumerate(data.get("snapshots", [])):
        data_store = snap.get("data_store", "unknown")
        collection = snap.get("collection", "unknown")
        cap_raw = snap.get("captured_at", file_ts_raw)
        cap_ts = _safe_ts(cap_raw, file_id, f"snap[{snap_idx}].captured_at", result.warnings)
        ts = cap_ts or file_ts

        category = infer_category(data_store, collection)

        for rec_idx, rec_raw in enumerate(snap.get("records", [])):
            ctx = f"snap[{snap_idx}].rec[{rec_idx}]"
            if not isinstance(rec_raw, dict):
                result.rejects.append(ParseReject(file_id, ctx, rec_raw, "Not a dict"))
                continue
            resource_id = rec_raw.get("resource_id")
            if not resource_id:
                result.rejects.append(ParseReject(file_id, ctx, rec_raw, "Missing resource_id"))
                continue

            if ts is None:
                result.rejects.append(ParseReject(file_id, ctx, rec_raw, "No usable timestamp"))
                continue

            identifiers = _extract_identifiers_from_record(rec_raw)
            state = _infer_state_from_record(rec_raw, collection)
            rec = Record(
                source=file_id,
                record_id=str(resource_id),
                timestamp=ts,
                system=data_store,
                data_category=category,
                identifiers=identifiers,
                state=state,
                raw_ref={"file": str(path), "row_or_offset": ctx},
                extras=rec_raw,
            )
            result.records.append(rec)
    return result


# ---------------------------------------------------------------------------
# Schema 2: service_resource_export_*.json
# ---------------------------------------------------------------------------

def parse_service_resource_export(path: Path, file_id: str) -> ParseResult:
    """
    {exported_at, region, service_exports: {
       account_service: {profile_lookups:[{observed_at, resource_id, profile, status_code}]},
       analytics_platform: {profiles:[{resource_id, customer_reference, email, phone, …}]},
       search_service: {documents:[{resource_id, email, customer_reference, …}]},
       integration_service: {connectors:[{resource_id, enabled, customer_email, …}]},
       backup_service: {catalog:[{resource_id, restore_allowed, …}]},
       support_platform: {tickets:[{resource_id, customer_reference, requester_email, …}]},
       security_service: {audit_records:[{resource_id, subject_reference, …}]},
       identity_service: {tombstones:[{resource_id, subject_reference, name, email, …}]},
    }}
    """
    result = ParseResult()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        result.rejects.append(ParseReject(file_id, "file", str(path), f"JSON parse error: {e}"))
        return result

    file_ts_raw = data.get("exported_at", "")
    file_ts = _safe_ts(file_ts_raw, file_id, "exported_at", result.warnings)

    service_exports = data.get("service_exports", {})
    for system_name, system_data in service_exports.items():
        if not isinstance(system_data, dict):
            continue
        # Iterate all lists inside the system block
        for sub_key, items in system_data.items():
            if not isinstance(items, list):
                continue
            category = infer_category(system_name, sub_key)
            for item_idx, item in enumerate(items):
                ctx = f"{system_name}.{sub_key}[{item_idx}]"
                if not isinstance(item, dict):
                    result.rejects.append(ParseReject(file_id, ctx, item, "Not a dict"))
                    continue
                resource_id = item.get("resource_id")
                if not resource_id:
                    result.rejects.append(ParseReject(file_id, ctx, item, "Missing resource_id"))
                    continue
                ts_raw = item.get("observed_at", file_ts_raw)
                ts = _safe_ts(ts_raw, file_id, ctx, result.warnings) or file_ts
                if ts is None:
                    result.rejects.append(ParseReject(file_id, ctx, item, "No usable timestamp"))
                    continue

                identifiers = _extract_identifiers_from_record(item)
                state = _infer_state_from_record(item, sub_key)
                rec = Record(
                    source=file_id,
                    record_id=str(resource_id),
                    timestamp=ts,
                    system=system_name,
                    data_category=category,
                    identifiers=identifiers,
                    state=state,
                    raw_ref={"file": str(path), "row_or_offset": ctx},
                    extras=item,
                )
                result.records.append(rec)
    return result


# ---------------------------------------------------------------------------
# Schema 3/4/5: flat records[] with system/resource_id/record_type/result
# (connector_configurations, security_audit_ledger, customer_export_manifest)
# ---------------------------------------------------------------------------

def parse_flat_records(path: Path, file_id: str) -> ParseResult:
    """
    {exported_at/captured_at, origin, record_count, records:[
       {recorded_at, system, resource_id, record_type, result, subject_reference}
    ]}
    """
    result = ParseResult()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        result.rejects.append(ParseReject(file_id, "file", str(path), f"JSON parse error: {e}"))
        return result

    file_ts_raw = data.get("exported_at") or data.get("captured_at", "")
    file_ts = _safe_ts(file_ts_raw, file_id, "exported_at/captured_at", result.warnings)

    for rec_idx, rec_raw in enumerate(data.get("records", [])):
        ctx = f"records[{rec_idx}]"
        if not isinstance(rec_raw, dict):
            result.rejects.append(ParseReject(file_id, ctx, rec_raw, "Not a dict"))
            continue
        resource_id = rec_raw.get("resource_id")
        if not resource_id:
            result.rejects.append(ParseReject(file_id, ctx, rec_raw, "Missing resource_id"))
            continue
        ts_raw = rec_raw.get("recorded_at", file_ts_raw)
        ts = _safe_ts(ts_raw, file_id, ctx, result.warnings) or file_ts
        if ts is None:
            result.rejects.append(ParseReject(file_id, ctx, rec_raw, "No usable timestamp"))
            continue

        system = rec_raw.get("system", data.get("origin", "unknown"))
        record_type = rec_raw.get("record_type", "")
        category = infer_category(system, record_type)

        identifiers = []
        subj = rec_raw.get("subject_reference", "")
        if subj:
            itype, norm = classify_and_normalize(subj)
            identifiers.append(Identifier(itype, subj, norm))
        identifiers += _extract_identifiers_from_record(rec_raw)
        identifiers = _dedup_identifiers(identifiers)

        result_val = rec_raw.get("result", "")
        state = "PRESENT" if result_val == "FOUND" else (
            "ABSENT" if result_val == "NOT_FOUND" else result_val)

        rec = Record(
            source=file_id,
            record_id=str(resource_id),
            timestamp=ts,
            system=system,
            data_category=category,
            identifiers=identifiers,
            state=state,
            raw_ref={"file": str(path), "row_or_offset": ctx},
            extras=rec_raw,
        )
        result.records.append(rec)
    return result


# ---------------------------------------------------------------------------
# Schema 6: customer_export_jobs_*.json
# ---------------------------------------------------------------------------

def parse_export_jobs(path: Path, file_id: str) -> ParseResult:
    """
    {captured_at, source, collection, records:[
       {resource_id, owner_email, file_name, created_at, expires_at, download_available, …}
    ]}
    """
    result = ParseResult()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        result.rejects.append(ParseReject(file_id, "file", str(path), f"JSON parse error: {e}"))
        return result

    file_ts_raw = data.get("captured_at", "")
    file_ts = _safe_ts(file_ts_raw, file_id, "captured_at", result.warnings)

    for rec_idx, rec_raw in enumerate(data.get("records", [])):
        ctx = f"records[{rec_idx}]"
        if not isinstance(rec_raw, dict):
            result.rejects.append(ParseReject(file_id, ctx, rec_raw, "Not a dict"))
            continue
        resource_id = rec_raw.get("resource_id")
        if not resource_id:
            result.rejects.append(ParseReject(file_id, ctx, rec_raw, "Missing resource_id"))
            continue
        ts_raw = rec_raw.get("created_at", file_ts_raw)
        ts = _safe_ts(ts_raw, file_id, ctx, result.warnings) or file_ts
        if ts is None:
            result.rejects.append(ParseReject(file_id, ctx, rec_raw, "No usable timestamp"))
            continue

        identifiers = []
        owner = rec_raw.get("owner_email", "")
        if owner:
            identifiers.append(Identifier("email", owner, normalize_email(owner)))

        download_ok = rec_raw.get("download_available", False)
        state = "PRESENT" if download_ok else "ABSENT"

        rec = Record(
            source=file_id,
            record_id=str(resource_id),
            timestamp=ts,
            system=data.get("source", "export_service"),
            data_category="USER_EXPORT",
            identifiers=identifiers,
            state=state,
            raw_ref={"file": str(path), "row_or_offset": ctx},
            extras=rec_raw,
        )
        result.records.append(rec)
    return result


# ---------------------------------------------------------------------------
# Schema 7: customer_analytics_report_*.json
# ---------------------------------------------------------------------------

def parse_analytics_report(path: Path, file_id: str) -> ParseResult:
    """
    {captured_at, source, collection, records:[
       {resource_id, user_id, email, phone, email_hash, reporting_window, metrics, …}
    ]}
    """
    result = ParseResult()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        result.rejects.append(ParseReject(file_id, "file", str(path), f"JSON parse error: {e}"))
        return result

    file_ts_raw = data.get("captured_at", "")
    file_ts = _safe_ts(file_ts_raw, file_id, "captured_at", result.warnings)

    for rec_idx, rec_raw in enumerate(data.get("records", [])):
        ctx = f"records[{rec_idx}]"
        if not isinstance(rec_raw, dict):
            result.rejects.append(ParseReject(file_id, ctx, rec_raw, "Not a dict"))
            continue
        resource_id = rec_raw.get("resource_id")
        if not resource_id:
            result.rejects.append(ParseReject(file_id, ctx, rec_raw, "Missing resource_id"))
            continue
        ts = file_ts
        if ts is None:
            result.rejects.append(ParseReject(file_id, ctx, rec_raw, "No usable timestamp"))
            continue

        identifiers = _extract_identifiers_from_record(rec_raw)
        # Determine if record is anonymized (all identity fields null)
        identity_fields = [rec_raw.get("user_id"), rec_raw.get("email"),
                           rec_raw.get("phone"), rec_raw.get("email_hash")]
        all_null = all(v is None or str(v).lower() in ("null", "none", "") for v in identity_fields)
        state = "ANONYMIZED" if all_null else "PRESENT"

        rec = Record(
            source=file_id,
            record_id=str(resource_id),
            timestamp=ts,
            system=data.get("source", "analytics_platform"),
            data_category="ANALYTICS_PROFILE",
            identifiers=identifiers,
            state=state,
            raw_ref={"file": str(path), "row_or_offset": ctx},
            extras=rec_raw,
        )
        result.records.append(rec)
    return result


# ---------------------------------------------------------------------------
# Dispatch: choose the right parser based on file content
# ---------------------------------------------------------------------------

def parse_json_evidence(path: Path, file_id: str) -> ParseResult:
    """
    Auto-detect the JSON schema and dispatch to the appropriate parser.
    """
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as e:
        r = ParseResult()
        r.rejects.append(ParseReject(file_id, "file", str(path), f"JSON parse error: {e}"))
        return r

    # Detect schema by key presence
    if "snapshots" in data:
        return parse_snapshot_bundle(path, file_id)
    if "service_exports" in data:
        return parse_service_resource_export(path, file_id)
    if "records" in data:
        records = data["records"]
        if not records:
            # Empty records list — still valid
            return parse_flat_records(path, file_id)
        first = records[0] if isinstance(records, list) and records else {}
        if isinstance(first, dict):
            # Distinguish by keys present
            if "system" in first and "record_type" in first:
                return parse_flat_records(path, file_id)
            if "owner_email" in first or "download_available" in first:
                return parse_export_jobs(path, file_id)
            if "reporting_window" in first or "metrics" in first:
                return parse_analytics_report(path, file_id)
            # Fallback to flat records parser (security_audit_ledger, etc.)
            return parse_flat_records(path, file_id)
    # Unrecognised schema
    r = ParseResult()
    r.rejects.append(ParseReject(file_id, "file", str(path),
                                  f"Unrecognised JSON schema: top-level keys={list(data.keys())}"))
    return r


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_IDENTITY_FIELD_MAP = {
    "user_id": "user_id",
    "customer_reference": "user_id",
    "subject_reference": "user_id",
    "email": "email",
    "owner_email": "email",
    "customer_email": "email",
    "requester_email": "email",
    "phone": "phone",
    "requester_phone": "phone",
    "email_hash": "email_hash",
    "name": "name",
    "full_name": "name",
    "display_name": "name",
    "requester_name": "name",
}


def _extract_identifiers_from_record(rec: dict) -> list[Identifier]:
    identifiers = []
    seen = set()
    for field, id_type in _IDENTITY_FIELD_MAP.items():
        val = rec.get(field)
        if val is None or str(val).strip().lower() in ("null", "none", ""):
            continue
        raw_s = str(val).strip()
        if id_type == "email":
            norm = normalize_email(raw_s)
        elif id_type == "phone":
            norm = normalize_phone(raw_s)
        elif id_type == "email_hash":
            norm = normalize_hash(raw_s)
        elif id_type == "user_id":
            norm = normalize_user_id(raw_s)
        else:
            norm = raw_s
        key = (id_type, norm)
        if key not in seen:
            seen.add(key)
            identifiers.append(Identifier(id_type=id_type, raw_value=raw_s, norm_value=norm))
    return identifiers


def _infer_state_from_record(rec: dict, collection: str) -> str:
    """Infer state from record fields."""
    # Account status
    acct_status = rec.get("account_status", "")
    if acct_status == "DELETED":
        return "ABSENT"
    if acct_status == "ACTIVE":
        return "PRESENT"
    # Restore policy
    restore = rec.get("restore_allowed")
    if restore is False or restore == 0:
        return "BLOCKED"
    if restore is True or restore == 1:
        return "ACTIVE"
    # Connector enabled
    enabled = rec.get("enabled")
    if enabled is False or enabled == 0:
        return "DISABLED"
    if enabled is True or enabled == 1:
        return "ACTIVE"
    # HTTP status
    status_code = rec.get("status_code")
    if status_code == 404:
        return "ABSENT"
    if status_code == 200:
        return "PRESENT"
    # Tombstone: check if all PII fields are null
    if "account_status" in rec and rec.get("account_status") == "DELETED":
        pii_null = all(rec.get(f) is None for f in ["name", "email", "phone", "email_hash"])
        return "REDACTED" if pii_null else "PRESENT"
    return "PRESENT"


def _dedup_identifiers(identifiers: list[Identifier]) -> list[Identifier]:
    seen = set()
    out = []
    for i in identifiers:
        key = (i.id_type, i.norm_value)
        if key not in seen:
            seen.add(key)
            out.append(i)
    return out
