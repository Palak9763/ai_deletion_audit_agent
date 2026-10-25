"""
identity/graph.py — Identity resolution engine using an explicit link graph.

Core principles (Phase 2):
1. Nodes are typed, normalized identity tokens: (id_type, norm_value).
2. Edges represent explicit, evidence-backed links only (direct, change, derivation,
   alias, merge, media_link).
3. Temporal validity: only edges with timestamp <= audit_at are active.
   Reassigned identifiers are bound to valid time windows (never carry across reassignment).
4. Anti-over-merging: ambiguous links (one identifier concurrently pointing to multiple
   users) are flagged and NEVER merged.
5. Explainability: every resolved identifier includes the shortest path of edges
   from the requester's primary identifier.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from code.models import Identifier, Record
from code.normalizers import (
    classify_and_normalize,
    normalize_email,
    normalize_hash,
    normalize_phone,
    normalize_user_id,
    parse_timestamp,
)


@dataclass(frozen=True)
class IdentityNode:
    """A canonical identity token."""
    id_type: str        # email | phone | user_id | email_hash | name | resource_id
    norm_value: str     # normalized representation

    def __str__(self) -> str:
        return f"{self.id_type}:{self.norm_value}"


@dataclass
class IdentityEdge:
    """
    An explicit link between two identity tokens.
    """
    source: IdentityNode
    target: IdentityNode
    evidence_source: str     # e.g. "user_identities", "user_audit_log", "system_activity"
    record_id: str           # e.g. "user_01", "audit_12", "activity_4007"
    timestamp: datetime      # UTC-aware
    edge_type: str           # "direct", "change", "derivation", "alias", "merge", "media_link"
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None  # for reassignment / recycling
    details: dict[str, Any] = field(default_factory=dict)

    def is_active_at(self, cutoff: datetime) -> bool:
        """Edge must have been created <= cutoff and not expired before cutoff."""
        if self.timestamp > cutoff:
            return False
        if self.valid_from and self.valid_from > cutoff:
            return False
        if self.valid_until and self.valid_until <= cutoff:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": str(self.source),
            "target": str(self.target),
            "evidence_source": self.evidence_source,
            "record_id": self.record_id,
            "timestamp": self.timestamp.isoformat(),
            "edge_type": self.edge_type,
            "details": self.details,
        }


@dataclass
class ResolutionResult:
    """The complete result of resolving an identity request as of audit_at."""
    requester: IdentityNode
    primary_user_id: Optional[str]
    audit_at: datetime
    # Map each resolved node to the shortest list of IdentityEdge connecting from requester
    identifiers: dict[IdentityNode, list[IdentityEdge]]
    ambiguous_links: list[dict[str, Any]]

    def get_values(self, id_type: str) -> list[str]:
        """Return all resolved values for a given identifier type."""
        return [node.norm_value for node in self.identifiers.keys() if node.id_type == id_type]

    def all_nodes(self) -> list[IdentityNode]:
        return list(self.identifiers.keys())


class IdentityGraph:
    """
    Graph of identity tokens connected by explicit evidence edges.
    """

    def __init__(self) -> None:
        self.nodes: set[IdentityNode] = set()
        self.edges: list[IdentityEdge] = []
        self._adj: dict[IdentityNode, list[IdentityEdge]] = defaultdict(list)
        # Tracking explicit assignments of non-user IDs to user_ids over time
        # { (id_type, val): [ (user_id, start_time, end_time, edge) ] }
        self._timeline: dict[IdentityNode, list[dict[str, Any]]] = defaultdict(list)

    def add_edge(
        self,
        source: IdentityNode,
        target: IdentityNode,
        evidence_source: str,
        record_id: str,
        timestamp: datetime,
        edge_type: str,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> IdentityEdge:
        """Add an undirected edge (both forward and backward) between two nodes."""
        if timestamp.tzinfo is None:
            raise ValueError(f"Edge timestamp must be timezone-aware: {timestamp}")

        edge = IdentityEdge(
            source=source,
            target=target,
            evidence_source=evidence_source,
            record_id=record_id,
            timestamp=timestamp,
            edge_type=edge_type,
            valid_from=valid_from or timestamp,
            valid_until=valid_until,
            details=details or {},
        )
        # Symmetrical reverse edge
        rev_edge = IdentityEdge(
            source=target,
            target=source,
            evidence_source=evidence_source,
            record_id=record_id,
            timestamp=timestamp,
            edge_type=edge_type,
            valid_from=valid_from or timestamp,
            valid_until=valid_until,
            details=details or {},
        )

        self.nodes.add(source)
        self.nodes.add(target)
        self.edges.append(edge)
        self._adj[source].append(edge)
        self._adj[target].append(rev_edge)

        # Record timeline if one side is a user_id
        if source.id_type == "user_id" and target.id_type != "user_id":
            self._timeline[target].append({
                "user_id": source.norm_value,
                "start": valid_from or timestamp,
                "end": valid_until,
                "edge": edge,
            })
        elif target.id_type == "user_id" and source.id_type != "user_id":
            self._timeline[source].append({
                "user_id": target.norm_value,
                "start": valid_from or timestamp,
                "end": valid_until,
                "edge": edge,
            })

        return edge

    def register_reassignment(
        self,
        ident: IdentityNode,
        old_user_id: str,
        new_user_id: str,
        reassigned_at: datetime,
        evidence_source: str,
        record_id: str,
    ) -> None:
        """
        Mark that an identifier was reassigned from old_user_id to new_user_id at reassigned_at.
        Edges to old_user_id terminate at reassigned_at; edges to new_user_id begin at reassigned_at.
        """
        old_u = IdentityNode("user_id", normalize_user_id(old_user_id))
        new_u = IdentityNode("user_id", normalize_user_id(new_user_id))

        # Terminate any existing edges between ident and old_u at reassigned_at
        for e in self._adj[ident]:
            if e.target == old_u:
                e.valid_until = reassigned_at
        for e in self._adj[old_u]:
            if e.target == ident:
                e.valid_until = reassigned_at

        # Add new edge starting at reassigned_at
        self.add_edge(
            source=new_u,
            target=ident,
            evidence_source=evidence_source,
            record_id=record_id,
            timestamp=reassigned_at,
            edge_type="reassignment",
            valid_from=reassigned_at,
            valid_until=None,
            details={"reassigned_from": old_user_id},
        )

    def load_user_identities(self, records: list[Record]) -> None:
        """Load baseline records from user_identities.csv."""
        for rec in records:
            uid = rec.record_id
            uid_node = IdentityNode("user_id", normalize_user_id(uid))
            ts = rec.timestamp

            for ident in rec.identifiers:
                if ident.id_type == "user_id":
                    continue
                node = IdentityNode(ident.id_type, ident.norm_value)
                edge_type = "derivation" if ident.id_type == "email_hash" else "direct"
                self.add_edge(
                    source=uid_node,
                    target=node,
                    evidence_source=rec.source,
                    record_id=rec.record_id,
                    timestamp=ts,
                    edge_type=edge_type,
                    details={"raw_value": ident.raw_value},
                )
                # Link email directly to email_hash as derivation
                if ident.id_type == "email_hash":
                    email_vals = rec.identifier_values("email")
                    if email_vals:
                        email_node = IdentityNode("email", email_vals[0])
                        self.add_edge(
                            source=email_node,
                            target=node,
                            evidence_source=rec.source,
                            record_id=rec.record_id,
                            timestamp=ts,
                            edge_type="derivation",
                            details={"raw_value": ident.raw_value},
                        )

    def load_user_audit_log(self, records: list[Record]) -> None:
        """Load change history from user_audit_log.csv."""
        for rec in records:
            uid_vals = rec.identifier_values("user_id")
            if not uid_vals:
                continue
            uid_node = IdentityNode("user_id", normalize_user_id(uid_vals[0]))
            field_name = rec.extras.get("field_name", "")
            old_val = rec.extras.get("old_value", "").strip()
            new_val = rec.extras.get("new_value", "").strip()
            ts = rec.timestamp

            # Determine identifier type
            itype = field_name if field_name in ("email", "phone", "email_hash") else "unknown"

            if old_val:
                norm_old = (
                    normalize_email(old_val) if itype == "email" else (
                        normalize_phone(old_val) if itype == "phone" else (
                            normalize_hash(old_val) if itype == "email_hash" else old_val
                        )
                    )
                )
                old_node = IdentityNode(itype, norm_old)
                self.add_edge(
                    source=uid_node,
                    target=old_node,
                    evidence_source=rec.source,
                    record_id=rec.record_id,
                    timestamp=ts,
                    edge_type="change",
                    details={"field": field_name, "change": "old_value", "raw_value": old_val},
                )

            if new_val:
                norm_new = (
                    normalize_email(new_val) if itype == "email" else (
                        normalize_phone(new_val) if itype == "phone" else (
                            normalize_hash(new_val) if itype == "email_hash" else new_val
                        )
                    )
                )
                new_node = IdentityNode(itype, norm_new)
                self.add_edge(
                    source=uid_node,
                    target=new_node,
                    evidence_source=rec.source,
                    record_id=rec.record_id,
                    timestamp=ts,
                    edge_type="change",
                    details={"field": field_name, "change": "new_value", "raw_value": new_val},
                )

    def load_activity_links(self, records: list[Record]) -> None:
        """Load LINK_RESOURCE_IDENTITY events from system_activity.csv."""
        # Pattern to extract target resource, email, and user_id from details:
        # e.g., "Data catalog linked account_5762 (account_5762) to haruka.s1838@zoho.com and user_11."
        # e.g., "Attachment catalog confirmed object_19 (delivery_confirmation_19.pdf) belongs only to priya.raman@gmail.com and user_07"
        email_re = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
        user_re = re.compile(r"\b(user_\d+)\b", re.IGNORECASE)
        resource_re = re.compile(r"\b(account_\w+|search_\w+|data_flow_\w+|analytics_\w+|export_\w+|support_\w+|backup_\w+|audit_record_\w+|tombstone_\w+|marketing_\w+|object_\w+|[\w-]+\.pdf)\b", re.IGNORECASE)

        for rec in records:
            event_type = rec.extras.get("event_type", "")
            if event_type != "LINK_RESOURCE_IDENTITY":
                continue

            details = rec.extras.get("details", "")
            ts = rec.timestamp
            rec_id = rec.record_id

            emails = email_re.findall(details)
            users = user_re.findall(details)
            resources = resource_re.findall(details)

            # Include explicit resource_id from record if present
            if rec.extras.get("resource_id"):
                resources.append(rec.extras["resource_id"])

            for u in users:
                u_node = IdentityNode("user_id", normalize_user_id(u))
                for e in emails:
                    e_node = IdentityNode("email", normalize_email(e))
                    self.add_edge(
                        source=u_node,
                        target=e_node,
                        evidence_source=rec.source,
                        record_id=rec_id,
                        timestamp=ts,
                        edge_type="alias",
                        details={"details": details},
                    )
                for r in resources:
                    r_node = IdentityNode("resource_id", r.strip())
                    self.add_edge(
                        source=u_node,
                        target=r_node,
                        evidence_source=rec.source,
                        record_id=rec_id,
                        timestamp=ts,
                        edge_type="media_link",
                        details={"details": details},
                    )

    def detect_ambiguities_as_of(
        self, cutoff: datetime
    ) -> tuple[set[tuple[IdentityNode, IdentityNode]], list[dict[str, Any]]]:
        """
        Scan active edges <= cutoff.
        Find non-user_id tokens that connect to multiple different user_ids without
        a distinct temporal reassignment.
        Returns:
          blocked_pairs: set of (node, user_node) pairs that must NOT be traversed.
          ambiguous_links: list of conflict reports.
        """
        # Map non-user_id node -> dict of user_id -> list of active edges
        user_links: dict[IdentityNode, dict[str, list[IdentityEdge]]] = defaultdict(lambda: defaultdict(list))

        for edge in self.edges:
            if not edge.is_active_at(cutoff):
                continue
            src, tgt = edge.source, edge.target
            if src.id_type == "user_id" and tgt.id_type != "user_id":
                user_links[tgt][src.norm_value].append(edge)
            elif tgt.id_type == "user_id" and src.id_type != "user_id":
                user_links[src][tgt.norm_value].append(edge)

        blocked_pairs: set[tuple[IdentityNode, IdentityNode]] = set()
        ambiguous_links: list[dict[str, Any]] = []

        for ident, u_dict in user_links.items():
            if len(u_dict) > 1:
                # Connected to multiple user_ids!
                # Check if it was explicitly merged or clean sequential reassignment
                users = list(u_dict.keys())
                evidence_list = []
                for uid, edgelist in u_dict.items():
                    evidence_list.extend([e.to_dict() for e in edgelist])
                    u_node = IdentityNode("user_id", uid)
                    blocked_pairs.add((ident, u_node))
                    blocked_pairs.add((u_node, ident))

                ambiguous_links.append({
                    "identifier": str(ident),
                    "conflicting_users": users,
                    "evidence": evidence_list,
                    "reason": f"Identifier {ident} concurrently references multiple users: {users}",
                })

        return blocked_pairs, ambiguous_links

    def resolve(
        self,
        requester_ident: IdentityNode,
        as_of: datetime,
    ) -> ResolutionResult:
        """
        Perform BFS from requester_ident to find all connected identifiers as of audit_at.
        Enforces shortest paths, ignores edges after audit_at, respects reassignments,
        and avoids merging ambiguous links.
        """
        if as_of.tzinfo is None:
            raise ValueError(f"as_of must be timezone-aware UTC: {as_of}")

        blocked_pairs, ambiguous_links = self.detect_ambiguities_as_of(as_of)

        # BFS queue: (current_node, list_of_edges_from_start)
        queue: deque[tuple[IdentityNode, list[IdentityEdge]]] = deque([(requester_ident, [])])
        visited: dict[IdentityNode, list[IdentityEdge]] = {requester_ident: []}
        primary_user_id: Optional[str] = (
            requester_ident.norm_value if requester_ident.id_type == "user_id" else None
        )

        while queue:
            curr, path = queue.popleft()

            if curr.id_type == "user_id" and primary_user_id is None:
                primary_user_id = curr.norm_value

            # Anti-over-merging rule: never link across name similarity or shared device/IP
            if curr.id_type in ("name", "device_id", "ip_address"):
                continue

            for edge in self._adj[curr]:
                neighbor = edge.target

                # 1. Temporal filter: must be active at or before as_of
                if not edge.is_active_at(as_of):
                    continue

                # 2. Ambiguity filter: do not traverse blocked ambiguous user edges
                if (curr, neighbor) in blocked_pairs or (neighbor, curr) in blocked_pairs:
                    continue

                # 3. Shortest path (unweighted BFS ensures minimum edge count)
                if neighbor not in visited:
                    new_path = path + [edge]
                    visited[neighbor] = new_path
                    queue.append((neighbor, new_path))

        return ResolutionResult(
            requester=requester_ident,
            primary_user_id=primary_user_id,
            audit_at=as_of,
            identifiers=visited,
            ambiguous_links=ambiguous_links,
        )
