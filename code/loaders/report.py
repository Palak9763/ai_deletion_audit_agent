"""
loaders/report.py — CLI report for deletion-audit data loaders.

Runs end-to-end loading across all datasets and evidence files.
Prints:
  1. Record count per source and per system
  2. Identifier counts by type
  3. Rejects per source with top reasons
  4. Media files linked vs. unlinked
  5. Gate verification status (zero silent drops, timezone awareness)

Usage:
  python -m code.loaders.report [--dataset-dir PATH]
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter, defaultdict
from datetime import timezone
from pathlib import Path

from code.models import MediaLink, ParseReject, ParseResult, ParseWarning, Record
from code.loaders.csv_loader import (
    parse_deletion_requests,
    parse_system_activity,
    parse_user_audit_log,
    parse_user_identities,
)
from code.loaders.json_loader import parse_json_evidence
from code.loaders.sql_loader import parse_sql_evidence
from code.loaders.log_loader import parse_log_evidence
from code.loaders.txt_loader import parse_txt_evidence
from code.loaders.media_loader import (
    build_activity_links_from_records,
    build_media_link,
)
from code.loaders.archive_loader import parse_archive_evidence


def run_pipeline(dataset_dir: Path) -> dict:
    """Run loaders on all sources and return aggregated statistics."""
    results: dict[str, ParseResult] = {}
    media_links: list[MediaLink] = []
    source_row_counts: dict[str, int] = {}

    # 1. Structured CSVs
    csv_configs = [
        ("user_identities", dataset_dir / "user_identities.csv", parse_user_identities),
        ("user_audit_log", dataset_dir / "user_audit_log.csv", parse_user_audit_log),
        ("system_activity", dataset_dir / "system_activity.csv", parse_system_activity),
        ("deletion_requests", dataset_dir / "deletion_requests.csv", parse_deletion_requests),
    ]

    for name, path, parser_fn in csv_configs:
        if path.exists():
            # Count physical data rows (excluding header)
            lines = [l for l in path.read_text(encoding="utf-8-sig").splitlines() if l.strip()]
            source_row_counts[name] = max(0, len(lines) - 1)
            res = parser_fn(path, name)
            results[name] = res

    # 2. Activity links for media
    activity_records = results.get("system_activity", ParseResult()).records
    activity_links = build_activity_links_from_records(activity_records)

    # 3. Evidence manifest (evidence_files.csv)
    evidence_csv = dataset_dir / "evidence_files.csv"
    if evidence_csv.exists():
        reader = csv.DictReader(evidence_csv.open("r", encoding="utf-8-sig"))
        for row in reader:
            file_id = row["file_id"].strip()
            rel_path = row["file_path"].strip()
            abs_path = dataset_dir / rel_path

            if not abs_path.exists():
                res = ParseResult()
                res.rejects.append(
                    ParseReject(file_id, "manifest", str(abs_path), "Evidence file missing on disk")
                )
                results[file_id] = res
                source_row_counts[file_id] = 1
                continue

            suffix = abs_path.suffix.lower()

            if suffix == ".json":
                res = parse_json_evidence(abs_path, file_id)
                results[file_id] = res
                source_row_counts[file_id] = res.total_rows()
            elif suffix == ".sql":
                res = parse_sql_evidence(abs_path, file_id)
                results[file_id] = res
                source_row_counts[file_id] = res.total_rows()
            elif suffix == ".log":
                lines = [l for l in abs_path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
                source_row_counts[file_id] = len(lines)
                res = parse_log_evidence(abs_path, file_id)
                results[file_id] = res
            elif suffix == ".txt":
                lines = [l for l in abs_path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
                source_row_counts[file_id] = len(lines)
                res = parse_txt_evidence(abs_path, file_id)
                results[file_id] = res
            elif suffix in (".pdf", ".png", ".jpg", ".jpeg"):
                mlink, w = build_media_link(file_id, rel_path, abs_path, activity_links)
                media_links.append(mlink)
                res = ParseResult()
                res.warnings.extend(w)
                results[file_id] = res
            elif suffix in (".zip", ".tar", ".tgz", ".tar.gz", ".bz2"):
                res = parse_archive_evidence(abs_path, file_id)
                results[file_id] = res
                source_row_counts[file_id] = res.total_rows()
            else:
                res = ParseResult()
                res.rejects.append(
                    ParseReject(file_id, "file", str(abs_path), f"Unhandled evidence suffix {suffix!r}")
                )
                results[file_id] = res
                source_row_counts[file_id] = 1

    return {
        "results": results,
        "media_links": media_links,
        "source_row_counts": source_row_counts,
    }


def print_report(data: dict) -> int:
    results: dict[str, ParseResult] = data["results"]
    media_links: list[MediaLink] = data["media_links"]
    source_row_counts: dict[str, int] = data["source_row_counts"]

    total_records = sum(len(r.records) for r in results.values())
    total_rejects = sum(len(r.rejects) for r in results.values())
    total_warnings = sum(len(r.warnings) for r in results.values())

    # 1. Records per source & system
    records_per_source = Counter({src: len(r.records) for src, r in results.items()})
    records_per_system = Counter()
    for r in results.values():
        for rec in r.records:
            records_per_system[rec.system] += 1

    # 2. Identifiers by type
    ident_counts = Counter()
    tz_aware_count = 0
    tz_naive_count = 0

    for r in results.values():
        for rec in r.records:
            if rec.timestamp.tzinfo is not None:
                tz_aware_count += 1
            else:
                tz_naive_count += 1
            for ident in rec.identifiers:
                ident_counts[ident.id_type] += 1

    # 3. Rejects per source & top reasons
    rejects_per_source = Counter({src: len(r.rejects) for src, r in results.items() if r.rejects})
    reject_reasons = Counter()
    reject_reasons_by_source: dict[str, Counter] = defaultdict(Counter)
    for src, r in results.items():
        for rej in r.rejects:
            reject_reasons[rej.reason] += 1
            reject_reasons_by_source[src][rej.reason] += 1

    # 4. Media links
    linked_media = [m for m in media_links if m.is_linked]
    unlinked_media = [m for m in media_links if not m.is_linked]

    # Print formatted output
    print("=" * 80)
    print("                PHASE 1: LOADER & NORMALIZATION AUDIT REPORT")
    print("=" * 80)
    print(f"Total Sources Loaded    : {len(results)}")
    print(f"Total Records Produced  : {total_records:,}")
    print(f"Total Rejects Logged    : {total_rejects:,}")
    print(f"Total Warnings Logged   : {total_warnings:,}")
    print(f"Total Media Files       : {len(media_links)} ({len(linked_media)} linked, {len(unlinked_media)} unlinked)")
    print("-" * 80)

    print("\n[1] RECORD COUNTS PER SYSTEM:")
    for sys_name, cnt in records_per_system.most_common():
        print(f"  - {sys_name:<30}: {cnt:>6,}")

    print("\n[2] RECORD COUNTS PER SOURCE (Top 20 sources):")
    for src, cnt in records_per_source.most_common(20):
        print(f"  - {src:<30}: {cnt:>6,} records")

    print("\n[3] IDENTIFIER COUNTS BY TYPE:")
    for id_type, cnt in ident_counts.most_common():
        print(f"  - {id_type:<20}: {cnt:>6,}")

    print("\n[4] REJECTS SUMMARY BY SOURCE (Sources with rejects):")
    for src, cnt in rejects_per_source.most_common(15):
        top_reason, top_rcnt = reject_reasons_by_source[src].most_common(1)[0]
        print(f"  - {src:<20}: {cnt:>5,} rejects | Top reason: {top_reason} ({top_rcnt})")

    print("\n[5] MEDIA FILES AUDIT:")
    print(f"  - Total media evidence files: {len(media_links)}")
    print(f"  - Linked media files        : {len(linked_media)}")
    print(f"  - Unlinked media files      : {len(unlinked_media)}")
    if unlinked_media:
        print("  - Unlinked sample (first 5):")
        for m in unlinked_media[:5]:
            ocr_info = f"OCR: {m.ocr_text_length} chars" if hasattr(m, "ocr_text_length") else ""
            signals = f"signals: {m.candidate_signals}" if m.candidate_signals else "no signals"
            print(f"    * {m.file_id} ({m.file_path}) -> {signals}")

    print("\n[6] GATE VERIFICATION:")
    tz_gate = (tz_naive_count == 0 and tz_aware_count == total_records)
    print(f"  [*] Timezone Awareness Check: {'PASS' if tz_gate else 'FAIL'}")
    print(f"      (TZ-aware: {tz_aware_count:,}, TZ-naive: {tz_naive_count:,})")

    silent_drops = 0
    for src, r in results.items():
        expected = source_row_counts.get(src)
        actual = len(r.records) + len(r.rejects)
        # For non-media sources where expected rows were counted
        if expected is not None and expected > 0 and actual < expected:
            silent_drops += (expected - actual)

    zero_drop_gate = (silent_drops == 0)
    print(f"  [*] Zero Silent Drops Check  : {'PASS' if zero_drop_gate else 'FAIL'}")
    print(f"      (Silent drops detected: {silent_drops})")

    print("=" * 80)
    return 0 if (tz_gate and zero_drop_gate) else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Run evidence loader and print audit report.")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("dataset"),
        help="Path to dataset directory containing CSVs and evidence/ folder",
    )
    args = parser.parse_args()

    data = run_pipeline(args.dataset_dir)
    sys.exit(print_report(data))


if __name__ == "__main__":
    main()
