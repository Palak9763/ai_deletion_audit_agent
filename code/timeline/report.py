"""
timeline/report.py — CLI report for event timeline, copy states, recreate paths,
and resurrection audit.

Usage:
  python -m code.timeline.report <case_id> [--dataset-dir PATH]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from code.loaders.report import run_pipeline
from code.identity.resolver import resolve_case
from code.timeline.reconstructor import TimelineReconstructor
from code.timeline.models import TimelineResult


_CACHED_PIPELINE = None


def get_pipeline_data(dataset_dir: Path):
    global _CACHED_PIPELINE
    if _CACHED_PIPELINE is None:
        _CACHED_PIPELINE = run_pipeline(dataset_dir)
    return _CACHED_PIPELINE


def print_timeline_report(res: TimelineResult) -> None:
    print("=" * 85)
    print("                 PHASE 3: TIMELINE & STATE AUDIT REPORT")
    print("=" * 85)
    print(f"Case ID           : {res.case_id}")
    print(f"Requester         : {res.requester}")
    print(f"Audit Cutoff Time : {res.audit_at.isoformat()}")
    print(f"Timeline Events   : {len(res.timeline)} (active <= audit_at) | {len(res.after_audit)} after audit")
    print(f"Data Copies Found : {len(res.copy_states)} distinct copies")
    print(f"Recreate Paths    : {len(res.recreate_paths)} evaluated")
    print(f"Resurrections     : {len(res.resurrections)} detected")
    print("-" * 85)

    # 1. Timeline Events
    print("\n[1] CHRONOLOGICAL EVENT TIMELINE (at or before audit_at):")
    if not res.timeline:
        print("  (No events recorded at or before audit_at)")
    else:
        for i, entry in enumerate(res.timeline, start=1):
            ts_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%SZ")
            state_tag = f"[{entry.state}]" if entry.state != "UNKNOWN" else ""
            print(f"  {i:>2}. {ts_str} | {entry.source:<12} | {entry.system:<20} | {entry.record_id:<16} | {entry.event_type:<28} {state_tag}")

    # 2. Copy States AT audit_at
    print("\n[2] STATE OF EVERY COPY AT AUDIT_AT:")
    if not res.copy_states:
        print("  (No copies identified)")
    else:
        for (sys_name, rid), cs in sorted(res.copy_states.items(), key=lambda x: (x[0][0], x[0][1])):
            flags = []
            if cs.resurrected:
                flags.append("RESURRECTED")
            if cs.is_unconfirmed:
                flags.append("UNCONFIRMED_OCR")
            flag_str = f" ({', '.join(flags)})" if flags else ""
            print(f"  - {sys_name:<22} : {rid:<18} [{cs.data_category:<18}] -> {cs.state:<12} (ev: {cs.last_evidence_id}){flag_str}")

    # 3. Recreate Paths
    print("\n[3] RECREATE PATH AUDIT (Sync / Restore / Connectors):")
    if not res.recreate_paths:
        print("  No recreate paths discovered.")
    else:
        for p in res.recreate_paths:
            verdict = "CAN RECREATE" if p.can_recreate else "SAFE (cannot recreate)"
            active_s = "ACTIVE" if p.is_active else "INACTIVE/PAUSED"
            scope_s = "IN SCOPE" if p.in_scope else "OUT OF SCOPE"
            print(f"  * {p.path_id:<16} [{p.job_type}]: {p.source_system} -> {p.target_system}")
            print(f"    Status : {active_s} | Scope: {scope_s} => Verdict: {verdict}")
            print(f"    Evidence: {p.evidence_source} (record: {p.record_id})")

    # 4. Resurrections
    if res.resurrections:
        print("\n[4] RESURRECTIONS DETECTED (Exposing Copies):")
        for r in res.resurrections:
            print(f"  [!] Copy {r['system']}:{r['resource_id']} was deleted at {r['deleted_at']} and written again at {r['resurrected_at']}")
            print(f"      Attributed to job/evidence: {r['job_evidence']} ({r['event_type']})")
    else:
        print("\n[4] RESURRECTIONS: None detected.")

    # 5. After Audit Events
    if res.after_audit:
        print(f"\n[5] AFTER-AUDIT EVENTS ({len(res.after_audit)} events - diagnostic only, ignored for decisions):")
        for entry in res.after_audit[:5]:
            ts_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%SZ")
            print(f"    * {ts_str} | {entry.source} | {entry.system} | {entry.record_id} | {entry.event_type}")
        if len(res.after_audit) > 5:
            print(f"    ... and {len(res.after_audit) - 5} more")

    # 6. Unconfirmed OCR Signals
    if res.unconfirmed_signals:
        print("\n[6] UNCONFIRMED OCR SIGNALS (Supporting only, not firm state):")
        for s in res.unconfirmed_signals:
            print(f"    * {s['file_id']} ({s['file_path']}): signals={s['signals']}, conf={s['confidence']}")

    print("=" * 85)


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconstruct timeline and copy states for a case.")
    parser.add_argument("case_id", help="Case ID (e.g. case_01, case_11)")
    parser.add_argument("--dataset-dir", type=Path, default=Path("dataset"), help="Path to dataset directory")
    args = parser.parse_args()

    # Load records & media
    data = get_pipeline_data(args.dataset_dir)
    all_records = []
    for r in data["results"].values():
        all_records.extend(r.records)
    media_links = data["media_links"]

    # Resolve identity
    resolved_id = resolve_case(args.case_id, args.dataset_dir)

    # Reconstruct timeline
    reconstructor = TimelineReconstructor(all_records, media_links)
    result = reconstructor.reconstruct(args.case_id, resolved_id)

    print_timeline_report(result)


if __name__ == "__main__":
    main()
