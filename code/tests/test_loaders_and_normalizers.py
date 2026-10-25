"""
tests/test_loaders_and_normalizers.py — Comprehensive unit tests for Phase 1.

Covers:
  1. Timestamp format variants (UTC, offsets, fractions, naive rejection)
  2. Email normalization (lowercasing, whitespace trimming, preserving dots and plus-tags)
  3. Phone, hash, and user_id normalization
  4. One malformed row/entry per parser:
     - CSV parser
     - JSON parser
     - SQL parser
     - Log parser
     - TXT parser
     - Media parser
     - Archive parser
  5. Zero silent drops and deterministic reject logging
"""
from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from code.models import Identifier, ParseReject, ParseResult, ParseWarning, Record
from code.normalizers import (
    classify_and_normalize,
    is_email,
    normalize_email,
    normalize_hash,
    normalize_phone,
    normalize_user_id,
    parse_timestamp,
)
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
from code.loaders.media_loader import build_media_link
from code.loaders.archive_loader import parse_archive_evidence


class TestNormalizers(unittest.TestCase):
    """Test timestamp, email, phone, and hash normalization."""

    def test_timestamp_variants(self):
        # 1. Standard ISO Z
        dt = parse_timestamp("2026-09-15T08:51:43Z")
        self.assertIsNotNone(dt.tzinfo)
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 9)
        self.assertEqual(dt.hour, 8)
        self.assertEqual(dt.minute, 51)
        self.assertEqual(dt.second, 43)

        # 2. Fractional seconds with Z
        dt = parse_timestamp("2026-09-15T08:51:43.123456Z")
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(dt.microsecond, 123456)

        # 3. Positive timezone offset (+05:30) converted to UTC
        dt = parse_timestamp("2026-09-15T08:51:43+05:30")
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(dt.hour, 3)
        self.assertEqual(dt.minute, 21)

        # 4. Negative timezone offset (-04:00) converted to UTC
        dt = parse_timestamp("2026-09-15T08:51:43-04:00")
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(dt.hour, 12)
        self.assertEqual(dt.minute, 51)

        # 5. Space separated
        dt = parse_timestamp("2026-09-15 08:51:43Z")
        self.assertEqual(dt.tzinfo, timezone.utc)

        # 6. Date only (assumed start of day UTC)
        dt = parse_timestamp("2026-09-15")
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(dt.day, 15)

        # 7. Invalid timestamp raises ValueError
        with self.assertRaises(ValueError):
            parse_timestamp("not-a-timestamp")
        with self.assertRaises(ValueError):
            parse_timestamp("")

    def test_email_normalization(self):
        # Lowercasing and whitespace trim
        self.assertEqual(normalize_email("  ALICE@EXAMPLE.COM  "), "alice@example.com")
        # Preserves plus tags
        self.assertEqual(normalize_email("bob+work@gmail.com"), "bob+work@gmail.com")
        # Preserves dots
        self.assertEqual(normalize_email("charlie.d.brown@sub.domain.org"), "charlie.d.brown@sub.domain.org")
        # Empty or null
        self.assertEqual(normalize_email(""), "")
        self.assertEqual(normalize_email(None), "")

    def test_phone_normalization(self):
        self.assertEqual(normalize_phone("+1 (555) 123-4567"), "+15551234567")
        self.assertEqual(normalize_phone("020 7946 0912"), "02079460912")
        self.assertEqual(normalize_phone("  +44 20-7946-0912 "), "+442079460912")

    def test_hash_and_user_id(self):
        h = "A" * 64
        self.assertEqual(normalize_hash(h), "a" * 64)
        self.assertEqual(normalize_user_id("  user_99  "), "user_99")

    def test_record_rejects_naive_timestamp(self):
        naive_dt = datetime(2026, 9, 15, 8, 0, 0)
        with self.assertRaises(ValueError):
            Record(
                source="test",
                record_id="rec_01",
                timestamp=naive_dt,
                system="test_sys",
                data_category="USER_PROFILE",
            )


class TestParsersMalformedRows(unittest.TestCase):
    """Test each parser handles malformed rows deterministically via rejects."""

    def test_csv_parser_malformed_rows(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "bad_identities.csv"
            # Row 2: valid, Row 3: missing columns, Row 4: bad timestamp
            p.write_text(
                "user_id,name,email,phone,email_hash,updated_at\n"
                "user_01,Alice,alice@test.com,+1234567890,abc123hash,2026-09-15T08:00:00Z\n"
                "user_02,Bob\n"
                "user_03,Charlie,charlie@test.com,+1234567890,def456hash,INVALID_TIME\n",
                encoding="utf-8",
            )
            res = parse_user_identities(p, "test_csv")
            self.assertEqual(len(res.records), 1)
            self.assertEqual(len(res.rejects), 2)
            self.assertEqual(res.total_rows(), 3)
            self.assertEqual(res.records[0].record_id, "user_01")
            self.assertIn("Missing columns", res.rejects[0].reason)
            self.assertIn("Unparseable updated_at", res.rejects[1].reason)

    def test_json_parser_malformed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "bad_bundle.json"
            # One valid record, one non-dict record, one missing resource_id
            content = {
                "exported_at": "2026-09-15T08:00:00Z",
                "snapshots": [
                    {
                        "data_store": "account_service",
                        "collection": "customer_profiles",
                        "captured_at": "2026-09-15T08:00:00Z",
                        "records": [
                            {"resource_id": "account_101", "email": "good@test.com"},
                            "MALFORMED_NON_DICT_ROW",
                            {"email": "missing_rid@test.com"},
                        ],
                    }
                ],
            }
            p.write_text(json.dumps(content), encoding="utf-8")
            res = parse_json_evidence(p, "test_json")
            self.assertEqual(len(res.records), 1)
            self.assertEqual(len(res.rejects), 2)
            self.assertEqual(res.records[0].record_id, "account_101")
            self.assertIn("Not a dict", res.rejects[0].reason)
            self.assertIn("Missing resource_id", res.rejects[1].reason)

    def test_sql_parser_malformed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "corrupt.sql"
            # SQL with valid table and one malformed JSON row
            sql = (
                "CREATE TABLE customer_data_primary ("
                "  resource_id TEXT, origin_system TEXT, collection_name TEXT, record_json TEXT, updated_at TEXT"
                ");\n"
                "INSERT INTO customer_data_primary VALUES ('acc_01', 'account_service', 'customer_profiles', '{\"email\":\"ok@test.com\"}', '2026-09-15T08:00:00Z');\n"
                "INSERT INTO customer_data_primary VALUES ('acc_02', 'account_service', 'customer_profiles', '{BROKEN_JSON', '2026-09-15T08:00:00Z');\n"
            )
            p.write_text(sql, encoding="utf-8")
            res = parse_sql_evidence(p, "test_sql")
            self.assertEqual(len(res.records), 1)
            self.assertEqual(len(res.rejects), 1)
            self.assertEqual(res.records[0].record_id, "acc_01")
            self.assertIn("record_json parse error", res.rejects[0].reason)

    def test_log_parser_malformed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "bad.log"
            lines = [
                # 1. Valid line with resource_id
                '2026-09-15T08:51:57Z level=INFO service=search_service resource_id=search_101 event=index_query_completed result=hit',
                # 2. Line missing timestamp
                'INVALID_NO_TIMESTAMP level=INFO resource_id=search_102 event=index_query_completed',
                # 3. Operational line without resource_id
                '2026-09-15T08:51:58Z level=DEBUG service=log_router event=export_started sources=platform_services',
            ]
            p.write_text("\n".join(lines), encoding="utf-8")
            res = parse_log_evidence(p, "test_log")
            self.assertEqual(len(res.records), 1)
            self.assertEqual(len(res.rejects), 2)
            self.assertEqual(res.records[0].record_id, "search_101")
            self.assertIn("missing ISO timestamp", res.rejects[0].reason)
            self.assertIn("without resource_id", res.rejects[1].reason)

    def test_txt_parser_malformed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "bad_handover.txt"
            lines = [
                "SHIFT HANDOVER HEADER",
                "- 2026-10-01T12:00:00Z | account_service | account_01 | USER_PROFILE | FOUND | user@test.com",
                "- MALFORMED_DATA_ROW_MISSING_PIPES",
            ]
            p.write_text("\n".join(lines), encoding="utf-8")
            res = parse_txt_evidence(p, "test_txt")
            self.assertEqual(len(res.records), 1)
            self.assertEqual(len(res.rejects), 2)
            self.assertEqual(res.records[0].record_id, "account_01")
            self.assertIn("Header / narrative", res.rejects[0].reason)
            self.assertIn("not full data pattern", res.rejects[1].reason)

    def test_media_parser_graceful(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_png = Path(tmpdir) / "screen.png"
            fake_png.write_bytes(b"FAKE_PNG_HEADER")
            link, warnings = build_media_link("evidence_test", "screen.png", fake_png, {})
            self.assertFalse(link.is_linked)
            self.assertEqual(link.file_id, "evidence_test")

    def test_archive_parser(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "test_archive.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr(
                    "customers.txt",
                    "- 2026-10-01T12:00:00Z | account_service | account_88 | USER_PROFILE | FOUND | zip_user@test.com\n",
                )
                zf.writestr("unknown_format.xyz", "some random binary data")

            res = parse_archive_evidence(zip_path, "evidence_zip")
            self.assertEqual(len(res.records), 1)
            self.assertEqual(res.records[0].record_id, "account_88")
            self.assertEqual(len(res.rejects), 1)
            self.assertIn("Unsupported file format '.xyz'", res.rejects[0].reason)


if __name__ == "__main__":
    unittest.main()
