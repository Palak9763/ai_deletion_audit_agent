"""
models.py — Common data model for the deletion-audit loader pipeline.
All timestamps are timezone-aware UTC datetimes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Identifier
# ---------------------------------------------------------------------------

@dataclass
class Identifier:
    """A single identity token found in a record."""
    id_type: str          # email | email_hash | phone | user_id | name | resource_id
    raw_value: str        # exactly as found in the source
    norm_value: str       # normalized form (see normalizers.py)

    def to_dict(self) -> dict:
        return {"type": self.id_type, "value": self.raw_value, "normalized_value": self.norm_value}


# ---------------------------------------------------------------------------
# Record
# ---------------------------------------------------------------------------

@dataclass
class Record:
    """
    One logical record extracted from any evidence source.

    Fields
    ------
    source        : evidence file_id (e.g. "evidence_01") or dataset key
                    (e.g. "user_identities", "system_activity")
    record_id     : resource_id from the evidence (e.g. "account_001")
    timestamp     : timezone-aware UTC datetime representing when this
                    record was captured / last updated
    system        : originating system (e.g. "account_service")
    data_category : deletion_rules.csv category (e.g. "USER_PROFILE")
                    or "UNKNOWN" when ambiguous
    identifiers   : list of Identifier objects
    state         : observed state string (e.g. "PRESENT", "ABSENT",
                    "ANONYMIZED", "REDACTED", "ACTIVE", "BLOCKED",
                    "DISABLED", "FOUND", "NOT_FOUND")
    raw_ref       : dict with keys "file" and "row_or_offset"
    extras        : source-specific fields (raw JSON / parsed dict)
    """
    source: str
    record_id: str
    timestamp: datetime                      # always UTC-aware
    system: str
    data_category: str
    identifiers: list[Identifier] = field(default_factory=list)
    state: str = "UNKNOWN"
    raw_ref: dict[str, Any] = field(default_factory=dict)
    extras: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError(
                f"Record {self.record_id}: timestamp must be timezone-aware, "
                f"got {self.timestamp!r}"
            )

    def identifier_values(self, id_type: str) -> list[str]:
        """Return normalized values for identifiers of the given type."""
        return [i.norm_value for i in self.identifiers if i.id_type == id_type]

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "record_id": self.record_id,
            "timestamp": self.timestamp.isoformat(),
            "system": self.system,
            "data_category": self.data_category,
            "identifiers": [i.to_dict() for i in self.identifiers],
            "state": self.state,
            "raw_ref": self.raw_ref,
            "extras": self.extras,
        }


# ---------------------------------------------------------------------------
# Parse warnings and rejects
# ---------------------------------------------------------------------------

@dataclass
class ParseWarning:
    """Non-fatal issue encountered while parsing."""
    source: str
    row_or_offset: Any
    message: str

    def __str__(self) -> str:
        return f"[WARN] {self.source} @ {self.row_or_offset}: {self.message}"


@dataclass
class ParseReject:
    """
    A row/entry that could not be turned into a valid Record.
    The row is preserved here — nothing is silently dropped.
    """
    source: str
    row_or_offset: Any
    raw_content: Any
    reason: str

    def __str__(self) -> str:
        return f"[REJECT] {self.source} @ {self.row_or_offset}: {self.reason}"


# ---------------------------------------------------------------------------
# Parse result bundle
# ---------------------------------------------------------------------------

@dataclass
class ParseResult:
    """Return type of every loader/parser function."""
    records: list[Record] = field(default_factory=list)
    warnings: list[ParseWarning] = field(default_factory=list)
    rejects: list[ParseReject] = field(default_factory=list)

    def merge(self, other: "ParseResult") -> None:
        self.records.extend(other.records)
        self.warnings.extend(other.warnings)
        self.rejects.extend(other.rejects)

    def total_rows(self) -> int:
        """records + rejects == total rows consumed (zero silent drops)."""
        return len(self.records) + len(self.rejects)


# ---------------------------------------------------------------------------
# Media link registry  (PDFs / screenshots)
# ---------------------------------------------------------------------------

@dataclass
class MediaLink:
    """Maps a media file (PDF/image) to a user via an activity event."""
    file_id: str            # evidence_NN
    file_path: str
    linked_user_id: Optional[str]
    linked_via_activity_id: Optional[str]
    ocr_text: Optional[str]
    ocr_confidence: Optional[float]   # 0.0–1.0, None if no OCR ran
    candidate_signals: list[str] = field(default_factory=list)
    is_linked: bool = False

    def to_dict(self) -> dict:
        return {
            "file_id": self.file_id,
            "file_path": self.file_path,
            "linked_user_id": self.linked_user_id,
            "linked_via_activity_id": self.linked_via_activity_id,
            "ocr_text_length": len(self.ocr_text) if self.ocr_text else 0,
            "ocr_confidence": self.ocr_confidence,
            "candidate_signals": self.candidate_signals,
            "is_linked": self.is_linked,
        }


# ---------------------------------------------------------------------------
# Constants: data categories from deletion_rules.csv
# ---------------------------------------------------------------------------

DATA_CATEGORIES = {
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT",
    "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY",
    "USER_EXPORT",
    "MARKETING_PROFILE",
    "EMAIL_DELIVERY_LOG",
    "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD",
    "BACKUP_ARCHIVE",
    "ACCOUNT_TOMBSTONE",
    "DATA_FLOW",           # integration_service connector (maps to DISABLE_DATA_FLOW)
}

# Map system + collection/record_type -> data_category
SYSTEM_COLLECTION_TO_CATEGORY: dict[tuple[str, str], str] = {
    ("account_service", "customer_profiles"): "USER_PROFILE",
    ("account_service", "USER_PROFILE"): "USER_PROFILE",
    ("identity_service", "deleted_customer_references"): "ACCOUNT_TOMBSTONE",
    ("identity_service", "ACCOUNT_TOMBSTONE"): "ACCOUNT_TOMBSTONE",
    ("search_service", "customer_search_documents"): "SEARCH_INDEX_ENTRY",
    ("search_service", "SEARCH_INDEX_ENTRY"): "SEARCH_INDEX_ENTRY",
    ("analytics_platform", "customer_analytics_reports"): "ANALYTICS_PROFILE",
    ("analytics_platform", "customer_analytics_profiles"): "ANALYTICS_PROFILE",
    ("analytics_platform", "ANALYTICS_PROFILE"): "ANALYTICS_PROFILE",
    ("support_platform", "support_conversations"): "SUPPORT_MESSAGE",
    ("support_platform", "SUPPORT_MESSAGE"): "SUPPORT_MESSAGE",
    ("support_platform", "SUPPORT_ATTACHMENT"): "SUPPORT_ATTACHMENT",
    ("integration_service", "connector_configurations"): "DATA_FLOW",
    ("integration_service", "connector_subscriptions"): "DATA_FLOW",
    ("integration_service", "DATA_FLOW"): "DATA_FLOW",
    ("export_service", "export_manifest"): "USER_EXPORT",
    ("export_service", "export_jobs"): "USER_EXPORT",
    ("export_service", "customer_export_jobs"): "USER_EXPORT",
    ("export_service", "USER_EXPORT"): "USER_EXPORT",
    ("backup_service", "backup_catalog"): "BACKUP_ARCHIVE",
    ("backup_service", "backup_restore_entries"): "BACKUP_ARCHIVE",
    ("backup_service", "BACKUP_ARCHIVE"): "BACKUP_ARCHIVE",
    ("security_service", "security_audit_events"): "SECURITY_AUDIT_LOG",
    ("security_service", "security_audit_records"): "SECURITY_AUDIT_LOG",
    ("security_service", "SECURITY_AUDIT_LOG"): "SECURITY_AUDIT_LOG",
    ("marketing_platform", "marketing_profiles"): "MARKETING_PROFILE",
    ("marketing_platform", "MARKETING_PROFILE"): "MARKETING_PROFILE",
    ("cache_service", "profile_cache"): "CACHE_ENTRY",
    ("cache_service", "CACHE_ENTRY"): "CACHE_ENTRY",
    ("notification_service", "email_delivery_log"): "EMAIL_DELIVERY_LOG",
    ("email_delivery_service", "email_delivery_log"): "EMAIL_DELIVERY_LOG",
    ("email_delivery_service", "EMAIL_DELIVERY_LOG"): "EMAIL_DELIVERY_LOG",
    ("legal_retention_service", "legal_holds"): "LEGAL_HOLD_RECORD",
    ("legal_retention_service", "LEGAL_HOLD_RECORD"): "LEGAL_HOLD_RECORD",
}


def infer_category(system: str, collection: str) -> str:
    key = (system.lower().strip(), collection.strip())
    # exact match
    result = SYSTEM_COLLECTION_TO_CATEGORY.get(key)
    if result:
        return result
    # try uppercase collection
    result = SYSTEM_COLLECTION_TO_CATEGORY.get((key[0], collection.upper()))
    if result:
        return result
    return "UNKNOWN"
