"""
identity/resolver.py — High-level interface for identity resolution.

Provides:
  build_graph(dataset_dir) -> IdentityGraph
  resolve_case(case_id, dataset_dir) -> ResolutionResult
  resolve_request(req_dict, graph) -> ResolutionResult
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Optional

from code.models import Record
from code.normalizers import normalize_email, normalize_user_id, parse_timestamp
from code.loaders.csv_loader import (
    parse_deletion_requests,
    parse_system_activity,
    parse_user_audit_log,
    parse_user_identities,
)
from code.identity.graph import IdentityGraph, IdentityNode, ResolutionResult


_CACHED_GRAPH: Optional[IdentityGraph] = None
_CACHED_DIR: Optional[Path] = None


def build_graph(dataset_dir: Path = Path("dataset"), force_reload: bool = False) -> IdentityGraph:
    """Build and populate IdentityGraph from baseline dataset files."""
    global _CACHED_GRAPH, _CACHED_DIR
    if _CACHED_GRAPH is not None and _CACHED_DIR == dataset_dir and not force_reload:
        return _CACHED_GRAPH

    graph = IdentityGraph()

    # 1. user_identities.csv
    ident_path = dataset_dir / "user_identities.csv"
    if ident_path.exists():
        res_ident = parse_user_identities(ident_path, "user_identities")
        graph.load_user_identities(res_ident.records)

    # 2. user_audit_log.csv
    audit_path = dataset_dir / "user_audit_log.csv"
    if audit_path.exists():
        res_audit = parse_user_audit_log(audit_path, "user_audit_log")
        graph.load_user_audit_log(res_audit.records)

    # 3. system_activity.csv
    activity_path = dataset_dir / "system_activity.csv"
    if activity_path.exists():
        res_activity = parse_system_activity(activity_path, "system_activity")
        graph.load_activity_links(res_activity.records)

    _CACHED_GRAPH = graph
    _CACHED_DIR = dataset_dir
    return graph


def resolve_case(case_id: str, dataset_dir: Path = Path("dataset")) -> ResolutionResult:
    """Resolve identity for a case_id from sample_deletion_requests.csv or deletion_requests.csv."""
    graph = build_graph(dataset_dir)

    # Look up request details
    req_file = None
    for candidate in ["deletion_requests.csv", "sample_deletion_requests.csv"]:
        p = dataset_dir / candidate
        if p.exists():
            with p.open("r", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):
                    if row["case_id"].strip() == case_id:
                        req_file = row
                        break
        if req_file:
            break

    if not req_file:
        raise KeyError(f"Case ID '{case_id}' not found in deletion_requests datasets.")

    email_raw = req_file["email"].strip()
    norm_email = normalize_email(email_raw)
    audit_at = parse_timestamp(req_file["audit_at"])

    start_node = IdentityNode("email", norm_email)
    return graph.resolve(start_node, as_of=audit_at)


def resolve(
    identifier_type: str,
    raw_value: str,
    audit_at_str: str,
    dataset_dir: Path = Path("dataset"),
) -> ResolutionResult:
    """Resolve an identity token as of a specific audit_at timestamp."""
    graph = build_graph(dataset_dir)
    audit_at = parse_timestamp(audit_at_str)

    if identifier_type == "email":
        norm_val = normalize_email(raw_value)
    elif identifier_type == "phone":
        norm_val = raw_value  # normalizer will handle
    elif identifier_type == "user_id":
        norm_val = normalize_user_id(raw_value)
    else:
        norm_val = raw_value.strip()

    start_node = IdentityNode(identifier_type, norm_val)
    return graph.resolve(start_node, as_of=audit_at)
