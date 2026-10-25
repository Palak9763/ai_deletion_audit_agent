"""
timeline/models.py — Data models for event timeline, copy states, recreate paths,
and resurrection tracking.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class TimelineEntry:
    """An event or record in the chronological timeline of a user's data."""
    timestamp: datetime               # UTC-aware
    source: str                       # evidence file_id (e.g. "evidence_54") or dataset name
    record_id: str                    # resource_id or event key
    system: str                       # e.g. "account_service", "search_service"
    data_category: str                # from deletion_rules.csv (e.g. "USER_PROFILE")
    event_type: str                   # e.g. "DELETE_RECORD", "SYNC_RECORD", "profile_lookup_completed"
    state: str                        # "PRESENT", "ABSENT", "ANONYMIZED", "REDACTED", "ACTIVE", "BLOCKED", "DISABLED"
    raw_ref: dict[str, Any] = field(default_factory=dict)
    extras: dict[str, Any] = field(default_factory=dict)
    matched_identifiers: list[str] = field(default_factory=list)
    is_ocr_signal: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "record_id": self.record_id,
            "system": self.system,
            "data_category": self.data_category,
            "event_type": self.event_type,
            "state": self.state,
            "raw_ref": self.raw_ref,
            "matched_identifiers": self.matched_identifiers,
            "is_ocr_signal": self.is_ocr_signal,
        }


@dataclass
class CopyState:
    """The computed state of a single location/copy holding user data AT audit_at."""
    system: str                       # e.g. "account_service"
    resource_id: str                  # e.g. "account_001"
    data_category: str                # e.g. "USER_PROFILE"
    state: str                        # "PRESENT", "ABSENT", "ANONYMIZED", "REDACTED", "ACTIVE", "BLOCKED", "DISABLED", "unconfirmed"
    last_evidence_id: str             # evidence file_id (e.g. "evidence_54")
    last_timestamp: datetime          # timestamp of decisive evidence
    is_unconfirmed: bool = False      # True if only OCR candidate words exist
    resurrected: bool = False         # True if deleted then written again before audit_at
    resurrected_by: Optional[str] = None # job/source that resurrected it
    resurrected_at: Optional[datetime] = None
    history: list[TimelineEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "system": self.system,
            "resource_id": self.resource_id,
            "data_category": self.data_category,
            "state": self.state,
            "last_evidence_id": self.last_evidence_id,
            "last_timestamp": self.last_timestamp.isoformat(),
            "is_unconfirmed": self.is_unconfirmed,
            "resurrected": self.resurrected,
            "resurrected_by": self.resurrected_by,
            "resurrected_at": self.resurrected_at.isoformat() if self.resurrected_at else None,
            "event_count": len(self.history),
        }


@dataclass
class RecreatePath:
    """A data sync, import, restore, or connector path that could recreate deleted data."""
    path_id: str                      # e.g. "data_flow_9522", "backup_4978"
    source_system: str                # Origin system
    target_system: str                # Destination system
    job_type: str                     # "connector", "backup_restore", "sync_job", "replication"
    is_active: bool                   # True if active/enabled (not disabled/blocked/paused)
    in_scope: bool                    # True if touches or can reach this user's data
    can_recreate: bool                # True only if BOTH is_active AND in_scope
    evidence_source: str              # evidence file_id
    record_id: str
    timestamp: datetime
    schedule: str = "continuous"
    scope_description: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "source_system": self.source_system,
            "target_system": self.target_system,
            "job_type": self.job_type,
            "is_active": self.is_active,
            "in_scope": self.in_scope,
            "can_recreate": self.can_recreate,
            "evidence_source": self.evidence_source,
            "record_id": self.record_id,
            "timestamp": self.timestamp.isoformat(),
            "schedule": self.schedule,
            "scope_description": self.scope_description,
            "details": self.details,
        }


@dataclass
class TimelineResult:
    """Full timeline and state audit output for a deletion request."""
    case_id: str
    requester: str
    audit_at: datetime
    timeline: list[TimelineEntry]
    copy_states: dict[tuple[str, str], CopyState]    # (system, resource_id) -> CopyState
    recreate_paths: list[RecreatePath]
    resurrections: list[dict[str, Any]]
    after_audit: list[TimelineEntry]
    unconfirmed_signals: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "requester": self.requester,
            "audit_at": self.audit_at.isoformat(),
            "timeline": [t.to_dict() for t in self.timeline],
            "copy_states": {f"{sys}:{rid}": cs.to_dict() for (sys, rid), cs in self.copy_states.items()},
            "recreate_paths": [p.to_dict() for p in self.recreate_paths],
            "resurrections": self.resurrections,
            "after_audit": [t.to_dict() for t in self.after_audit],
            "unconfirmed_signals": self.unconfirmed_signals,
        }
