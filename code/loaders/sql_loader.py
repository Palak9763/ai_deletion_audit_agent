"""
loaders/sql_loader.py — Parser for SQLite-compatible SQL snapshot files.

Two schemas observed:

Schema A (customer_data_read_replica / regional / reporting / failover):
  Two tables: customer_data_primary, customer_data_<type>
  Each row: (resource_id, origin_system, collection_name, record_json, updated_at)
  record_json is a nested JSON blob.

Schema B (customer_data_inventory_*.sql):
  Multiple typed tables per system:
    customer_profiles, customer_search_documents, customer_analytics_profiles,
    support_records, customer_exports, connector_subscriptions,
    backup_restore_entries, security_audit_records, snapshot_scope

Schema C (customer_accounts_failover_replica_*.sql):
  Similar to Schema A but accounts-only.

Schema D (customer_search_primary_*.sql):
  Search-specific primary table.

Strategy: use sqlite3 (standard library) to execute the SQL in memory,
then query all known tables.
"""
from __future__ import annotations

import json
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Optional

from code.models import (
    Identifier, ParseReject, ParseResult, ParseWarning, Record,
    infer_category,
)
from code.normalizers import (
    normalize_email, normalize_hash, normalize_phone, normalize_user_id,
    parse_timestamp,
)
from code.loaders.json_loader import (
    _extract_identifiers_from_record,
    _infer_state_from_record,
    _dedup_identifiers,
)


# ---------------------------------------------------------------------------
# Schema A/C: customer_data_primary / customer_data_<replica>
# Each row has (resource_id, origin_system, collection_name, record_json, updated_at)
# ---------------------------------------------------------------------------

_SCHEMA_A_TABLE_RE = re.compile(
    r"CREATE TABLE (customer_data_\w+)\s*\(", re.IGNORECASE
)


def _load_schema_a(conn: sqlite3.Connection, file_id: str, path: Path,
                   table_names: list[str]) -> ParseResult:
    result = ParseResult()
    for table in table_names:
        try:
            rows = conn.execute(
                f"SELECT resource_id, origin_system, collection_name, record_json, updated_at "
                f"FROM \"{table}\""
            ).fetchall()
        except sqlite3.OperationalError as e:
            result.warnings.append(ParseWarning(file_id, table, f"Cannot query table: {e}"))
            continue

        for row_idx, (resource_id, origin_system, collection_name, record_json_s, updated_at) in enumerate(rows):
            ctx = f"{table}[{row_idx}]"
            try:
                rec_data = json.loads(record_json_s)
            except (json.JSONDecodeError, TypeError) as e:
                result.rejects.append(ParseReject(file_id, ctx, record_json_s,
                                                   f"record_json parse error: {e}"))
                continue
            try:
                ts = parse_timestamp(updated_at)
            except ValueError as e:
                result.rejects.append(ParseReject(file_id, ctx, record_json_s,
                                                   f"Bad updated_at {updated_at!r}: {e}"))
                continue

            category = infer_category(origin_system, collection_name)
            identifiers = _extract_identifiers_from_record(rec_data)
            identifiers = _dedup_identifiers(identifiers)
            state = _infer_state_from_record(rec_data, collection_name)

            # Mark which table type this came from (primary vs replica)
            replica_type = table.replace("customer_data_", "")

            rec = Record(
                source=file_id,
                record_id=str(resource_id),
                timestamp=ts,
                system=origin_system,
                data_category=category,
                identifiers=identifiers,
                state=state,
                raw_ref={"file": str(path), "row_or_offset": ctx},
                extras={**rec_data, "_sql_table": table, "_replica_type": replica_type},
            )
            result.records.append(rec)
    return result


# ---------------------------------------------------------------------------
# Schema B: customer_data_inventory_*.sql — typed tables
# ---------------------------------------------------------------------------

# Maps table name -> (system, category, column list)
_INVENTORY_TABLE_MAP: dict[str, tuple[str, str, list[str]]] = {
    "customer_profiles": (
        "account_service", "USER_PROFILE",
        ["resource_id", "customer_reference", "full_name", "email", "phone",
         "email_hash", "account_status", "updated_at"],
    ),
    "customer_search_documents": (
        "search_service", "SEARCH_INDEX_ENTRY",
        ["resource_id", "customer_reference", "display_name", "email",
         "phone", "email_hash", "index_name", "updated_at"],
    ),
    "customer_analytics_profiles": (
        "analytics_platform", "ANALYTICS_PROFILE",
        ["resource_id", "customer_reference", "email", "phone",
         "email_hash", "audience_cohort", "updated_at"],
    ),
    "support_records": (
        "support_platform", "SUPPORT_MESSAGE",
        ["resource_id", "customer_reference", "requester_name",
         "requester_email", "requester_phone", "message_excerpt", "updated_at"],
    ),
    "customer_exports": (
        "export_service", "USER_EXPORT",
        ["resource_id", "customer_reference", "owner_email", "owner_phone",
         "object_key", "updated_at"],
    ),
    "connector_subscriptions": (
        "integration_service", "DATA_FLOW",
        ["resource_id", "customer_reference", "customer_email",
         "connector_name", "enabled", "last_delivery_status", "updated_at"],
    ),
    "backup_restore_entries": (
        "backup_service", "BACKUP_ARCHIVE",
        ["resource_id", "customer_reference", "customer_email",
         "archive_key", "restore_allowed", "updated_at"],
    ),
    "security_audit_records": (
        "security_service", "SECURITY_AUDIT_LOG",
        ["resource_id", "subject_reference", "event_code",
         "retention_until", "updated_at"],
    ),
}


def _load_schema_b(conn: sqlite3.Connection, file_id: str, path: Path) -> ParseResult:
    result = ParseResult()

    # Determine snapshot time from snapshot_scope
    snap_ts = None
    try:
        row = conn.execute(
            "SELECT captured_at FROM snapshot_scope LIMIT 1"
        ).fetchone()
        if row:
            try:
                snap_ts = parse_timestamp(row[0])
            except ValueError:
                pass
    except sqlite3.OperationalError:
        pass

    for table, (system, category, _cols) in _INVENTORY_TABLE_MAP.items():
        try:
            rows = conn.execute(f"SELECT * FROM \"{table}\"").fetchall()
            col_names = [desc[0] for desc in conn.execute(
                f"SELECT * FROM \"{table}\" LIMIT 0"
            ).description]
        except sqlite3.OperationalError:
            continue  # table doesn't exist in this file, skip silently

        for row_idx, row_data in enumerate(rows):
            ctx = f"{table}[{row_idx}]"
            row_dict = dict(zip(col_names, row_data))
            resource_id = row_dict.get("resource_id")
            if not resource_id:
                result.rejects.append(ParseReject(file_id, ctx, row_dict, "Missing resource_id"))
                continue

            updated_at = row_dict.get("updated_at", "")
            try:
                ts = parse_timestamp(updated_at) if updated_at else snap_ts
            except ValueError as e:
                ts = snap_ts
                result.warnings.append(ParseWarning(file_id, ctx, f"bad updated_at: {e}"))
            if ts is None:
                result.rejects.append(ParseReject(file_id, ctx, row_dict, "No usable timestamp"))
                continue

            identifiers = _extract_identifiers_from_inventory_row(row_dict, table)
            state = _infer_state_from_inventory_row(row_dict, table)

            rec = Record(
                source=file_id,
                record_id=str(resource_id),
                timestamp=ts,
                system=system,
                data_category=category,
                identifiers=identifiers,
                state=state,
                raw_ref={"file": str(path), "row_or_offset": ctx},
                extras={**row_dict, "_sql_table": table},
            )
            result.records.append(rec)
    return result


def _extract_identifiers_from_inventory_row(row: dict, table: str) -> list[Identifier]:
    identifiers = []
    seen = set()

    def add(id_type: str, raw: Any, norm: str) -> None:
        key = (id_type, norm)
        if key not in seen and norm:
            seen.add(key)
            identifiers.append(Identifier(id_type, str(raw), norm))

    for field in ("customer_reference", "subject_reference"):
        v = row.get(field)
        if v:
            add("user_id", v, normalize_user_id(str(v)))
    for field in ("email", "owner_email", "customer_email", "requester_email"):
        v = row.get(field)
        if v:
            add("email", v, normalize_email(str(v)))
    for field in ("phone", "owner_phone", "requester_phone"):
        v = row.get(field)
        if v:
            add("phone", v, normalize_phone(str(v)))
    for field in ("email_hash",):
        v = row.get(field)
        if v:
            add("email_hash", v, normalize_hash(str(v)))
    for field in ("full_name", "display_name", "requester_name"):
        v = row.get(field)
        if v:
            add("name", v, str(v).strip())
    return identifiers


def _infer_state_from_inventory_row(row: dict, table: str) -> str:
    if table == "customer_profiles":
        status = row.get("account_status", "")
        if status == "DELETED":
            return "ABSENT"
        if status == "DELETION_PENDING":
            return "PRESENT"
        return "PRESENT" if any(row.get(f) for f in ["email", "full_name", "phone"]) else "PRESENT"
    if table == "connector_subscriptions":
        enabled = row.get("enabled", 1)
        return "ACTIVE" if enabled in (1, True) else "DISABLED"
    if table == "backup_restore_entries":
        restore = row.get("restore_allowed", 1)
        return "ACTIVE" if restore in (1, True) else "BLOCKED"
    if table == "customer_analytics_profiles":
        pii = any(row.get(f) for f in ["customer_reference", "email", "phone", "email_hash"])
        return "PRESENT" if pii else "ANONYMIZED"
    return "PRESENT"


# ---------------------------------------------------------------------------
# Schema D: customer_search_primary_*.sql
# ---------------------------------------------------------------------------

def _load_schema_d(conn: sqlite3.Connection, file_id: str, path: Path) -> ParseResult:
    result = ParseResult()
    # Try to find any table with search-like columns
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    for (tbl_name,) in tables:
        if tbl_name in ("sqlite_master", "snapshot_scope"):
            continue
        try:
            col_names = [desc[0] for desc in conn.execute(
                f"SELECT * FROM \"{tbl_name}\" LIMIT 0"
            ).description]
            rows = conn.execute(f"SELECT * FROM \"{tbl_name}\"").fetchall()
        except sqlite3.OperationalError as e:
            result.warnings.append(ParseWarning(file_id, tbl_name, f"Cannot query: {e}"))
            continue

        for row_idx, row_data in enumerate(rows):
            row_dict = dict(zip(col_names, row_data))
            resource_id = row_dict.get("resource_id")
            if not resource_id:
                result.rejects.append(ParseReject(file_id, f"{tbl_name}[{row_idx}]",
                                                   row_dict, "Missing resource_id"))
                continue
            updated = row_dict.get("updated_at", "")
            try:
                ts = parse_timestamp(updated) if updated else None
            except ValueError:
                ts = None
            if ts is None:
                result.rejects.append(ParseReject(file_id, f"{tbl_name}[{row_idx}]",
                                                   row_dict, "No usable timestamp"))
                continue
            identifiers = _extract_identifiers_from_inventory_row(row_dict, tbl_name)
            if "profile" in tbl_name or "account" in tbl_name:
                system = "account_service"
                data_category = "USER_PROFILE"
            elif "search" in tbl_name:
                system = "search_service"
                data_category = "SEARCH_INDEX_ENTRY"
            elif "analytics" in tbl_name:
                system = "analytics_platform"
                data_category = "ANALYTICS_PROFILE"
            elif "support" in tbl_name:
                system = "support_platform"
                data_category = "SUPPORT_MESSAGE"
            else:
                system = "account_service"
                data_category = "USER_PROFILE"

            acct_status = row_dict.get("account_status", "").upper()
            if acct_status == "DELETED":
                state = "ABSENT"
            elif acct_status == "ACTIVE":
                state = "PRESENT"
            else:
                state = "PRESENT"

            rec = Record(
                source=file_id,
                record_id=str(resource_id),
                timestamp=ts,
                system=system,
                data_category=data_category,
                identifiers=identifiers,
                state=state,
                raw_ref={"file": str(path), "row_or_offset": f"{tbl_name}[{row_idx}]"},
                extras=row_dict,
            )
            result.records.append(rec)
    return result


# ---------------------------------------------------------------------------
# Main entry: parse a .sql file
# ---------------------------------------------------------------------------

def parse_sql_evidence(path: Path, file_id: str) -> ParseResult:
    """
    Load SQL into an in-memory SQLite DB, then dispatch to the right schema handler.
    """
    result = ParseResult()
    try:
        sql_text = path.read_text(encoding="utf-8")
    except Exception as e:
        result.rejects.append(ParseReject(file_id, "file", str(path), f"Cannot read: {e}"))
        return result

    try:
        conn = sqlite3.connect(":memory:")
        conn.executescript(sql_text)
    except sqlite3.Error as e:
        # Some files may have minor syntax issues — report but try to proceed
        result.warnings.append(ParseWarning(file_id, "executescript", f"SQL error: {e}"))
        try:
            conn = sqlite3.connect(":memory:")
            # Try line-by-line
            for line in sql_text.splitlines():
                line = line.strip()
                if line and not line.startswith("--"):
                    try:
                        conn.execute(line)
                    except sqlite3.Error:
                        pass
            conn.commit()
        except Exception as e2:
            result.rejects.append(ParseReject(file_id, "file", str(path),
                                               f"Cannot load SQL: {e2}"))
            return result

    # Detect schema
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}

    if "customer_data_primary" in tables or any(
        t.startswith("customer_data_") for t in tables
    ):
        schema_a_tables = [t for t in tables if t.startswith("customer_data_")]
        sub = _load_schema_a(conn, file_id, path, schema_a_tables)
    elif "customer_profiles" in tables or "snapshot_scope" in tables:
        sub = _load_schema_b(conn, file_id, path)
    else:
        sub = _load_schema_d(conn, file_id, path)

    result.merge(sub)
    conn.close()
    return result
