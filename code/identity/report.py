"""
identity/report.py — CLI report for identity resolution.

Usage:
  python -m code.identity.report <case_id_or_user_id> [--dataset-dir PATH]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from code.identity.resolver import build_graph, resolve_case, resolve
from code.identity.graph import IdentityNode, ResolutionResult


def format_edge(edge) -> str:
    """Format an edge in human-readable notation."""
    return (
        f"[{edge.edge_type}] --({edge.evidence_source}:{edge.record_id} @ {edge.timestamp.strftime('%Y-%m-%d %H:%M:%SZ')})--> {edge.target}"
    )


def print_resolution_report(res: ResolutionResult, case_id: str = "") -> None:
    print("=" * 80)
    print("                     IDENTITY RESOLUTION AUDIT REPORT")
    print("=" * 80)
    if case_id:
        print(f"Case ID           : {case_id}")
    print(f"Requester Token   : {res.requester}")
    print(f"Primary User ID   : {res.primary_user_id or 'UNLINKED'}")
    print(f"Audit Cutoff Time : {res.audit_at.isoformat()}")
    print(f"Resolved Count    : {len(res.identifiers)} identifiers")
    print("-" * 80)

    # Group identifiers by type
    by_type: dict[str, list[tuple[IdentityNode, list]]] = {}
    for node, path in res.identifiers.items():
        by_type.setdefault(node.id_type, []).append((node, path))

    print("\n[1] RESOLVED IDENTIFIERS BY TYPE:")
    for id_type, items in sorted(by_type.items()):
        print(f"\n  * {id_type.upper()} ({len(items)}):")
        for node, path in items:
            hop_count = len(path)
            hops_str = f"{hop_count} hop{'s' if hop_count != 1 else ''}"
            print(f"    - {node.norm_value:<45} ({hops_str})")

    print("\n[2] EXPLAINABILITY & PROVENANCE PATHS:")
    for node, path in res.identifiers.items():
        if node == res.requester:
            print(f"\n  * {node} (ORIGIN / REQUESTER)")
            continue
        print(f"\n  * Path to {node}:")
        curr = str(res.requester)
        for i, edge in enumerate(path, 1):
            arrow = "-->"
            print(f"    Step {i}: {edge.source} {arrow} {edge.target}")
            print(f"            type     : {edge.edge_type}")
            print(f"            evidence : {edge.evidence_source} (record: {edge.record_id})")
            print(f"            linked_at: {edge.timestamp.isoformat()}")

    if res.ambiguous_links:
        print("\n[3] AMBIGUOUS LINKS (HELD UNMERGED):")
        for amb in res.ambiguous_links:
            print(f"  [!] {amb['identifier']}: conflicting users={amb['conflicting_users']}")
            print(f"      reason: {amb['reason']}")
    else:
        print("\n[3] AMBIGUOUS LINKS: None detected.")

    print("=" * 80)


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve identity graph for a case or identifier.")
    parser.add_argument("case_id", help="Case ID (e.g. case_01) or identifier value")
    parser.add_argument("--dataset-dir", type=Path, default=Path("dataset"), help="Path to dataset dir")
    args = parser.parse_args()

    target = args.case_id.strip()

    try:
        if target.startswith("case_"):
            res = resolve_case(target, args.dataset_dir)
            print_resolution_report(res, case_id=target)
        else:
            # Fallback direct resolution
            if "@" in target:
                itype = "email"
            elif target.startswith("user_"):
                itype = "user_id"
            else:
                itype = "phone"
            res = resolve(itype, target, "2026-10-01T00:00:00Z", args.dataset_dir)
            print_resolution_report(res, case_id="")
    except Exception as e:
        print(f"Error resolving {target}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
