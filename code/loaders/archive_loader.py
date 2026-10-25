"""
loaders/archive_loader.py — Parser for archive evidence files (ZIP, TAR, TGZ).

Deterministic archive reader:
- Opens zip or tar files in-memory / temp directory
- Inspects member files and dispatches to appropriate format loaders
- Any unparseable or corrupted member goes to rejects (never silently dropped)
- Returns ParseResult (records + warnings + rejects)
"""
from __future__ import annotations

import io
import os
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

from code.models import ParseReject, ParseResult, ParseWarning
from code.loaders.json_loader import parse_json_evidence
from code.loaders.sql_loader import parse_sql_evidence
from code.loaders.log_loader import parse_log_evidence
from code.loaders.txt_loader import parse_txt_evidence
from code.loaders.csv_loader import (
    parse_user_identities,
    parse_user_audit_log,
    parse_system_activity,
    parse_deletion_requests,
)


def _dispatch_member(path: Path, member_name: str, file_id: str) -> ParseResult:
    """Dispatch an extracted archive file to the right parser based on extension / name."""
    suffix = path.suffix.lower()
    sub_id = f"{file_id}:{member_name}"

    if suffix == ".json":
        return parse_json_evidence(path, sub_id)
    elif suffix == ".sql":
        return parse_sql_evidence(path, sub_id)
    elif suffix == ".log":
        return parse_log_evidence(path, sub_id)
    elif suffix == ".txt":
        return parse_txt_evidence(path, sub_id)
    elif suffix == ".csv":
        fname = path.name.lower()
        if "identity" in fname or "identities" in fname:
            return parse_user_identities(path, sub_id)
        elif "audit" in fname:
            return parse_user_audit_log(path, sub_id)
        elif "activity" in fname:
            return parse_system_activity(path, sub_id)
        elif "request" in fname:
            return parse_deletion_requests(path, sub_id)
        else:
            # Fallback activity parser for generic CSVs
            return parse_system_activity(path, sub_id)
    else:
        res = ParseResult()
        res.rejects.append(
            ParseReject(
                source=sub_id,
                row_or_offset=member_name,
                raw_content=str(path),
                reason=f"Unsupported file format '{suffix}' inside archive",
            )
        )
        return res


def parse_archive_evidence(path: Path, file_id: str) -> ParseResult:
    """
    Parse an archive (.zip, .tar, .tar.gz, .tgz, .tar.bz2).
    Extracts entries to a temporary sandbox, parses them deterministically,
    and returns a combined ParseResult.
    """
    result = ParseResult()

    if not path.exists():
        result.rejects.append(
            ParseReject(file_id, "file", str(path), f"File does not exist: {path}")
        )
        return result

    is_zip = zipfile.is_zipfile(str(path))
    is_tar = tarfile.is_tarfile(str(path))

    if not is_zip and not is_tar:
        result.rejects.append(
            ParseReject(
                file_id,
                "file",
                str(path),
                "File is neither a valid zip nor tar archive",
            )
        )
        return result

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        try:
            if is_zip:
                with zipfile.ZipFile(str(path), "r") as zf:
                    for zip_info in sorted(zf.infolist(), key=lambda x: x.filename):
                        if zip_info.is_dir():
                            continue
                        # Security / path sanitization check
                        if ".." in zip_info.filename or zip_info.filename.startswith("/"):
                            result.rejects.append(
                                ParseReject(
                                    file_id,
                                    zip_info.filename,
                                    zip_info.filename,
                                    "Insecure member path with traversal",
                                )
                            )
                            continue
                        try:
                            extracted_file = zf.extract(zip_info, path=tmpdir)
                            sub_res = _dispatch_member(
                                Path(extracted_file), zip_info.filename, file_id
                            )
                            result.merge(sub_res)
                        except Exception as e:
                            result.rejects.append(
                                ParseReject(
                                    file_id,
                                    zip_info.filename,
                                    zip_info.filename,
                                    f"Failed to extract/parse zip entry: {e}",
                                )
                            )
            elif is_tar:
                with tarfile.open(str(path), "r:*") as tf:
                    members = tf.getmembers()
                    for tar_info in sorted(members, key=lambda x: x.name):
                        if tar_info.isdir():
                            continue
                        if ".." in tar_info.name or tar_info.name.startswith("/"):
                            result.rejects.append(
                                ParseReject(
                                    file_id,
                                    tar_info.name,
                                    tar_info.name,
                                    "Insecure member path with traversal",
                                )
                            )
                            continue
                        try:
                            tf.extract(tar_info, path=tmpdir)
                            extracted_file = tmp_path / tar_info.name
                            sub_res = _dispatch_member(
                                extracted_file, tar_info.name, file_id
                            )
                            result.merge(sub_res)
                        except Exception as e:
                            result.rejects.append(
                                ParseReject(
                                    file_id,
                                    tar_info.name,
                                    tar_info.name,
                                    f"Failed to extract/parse tar entry: {e}",
                                )
                            )
        except Exception as e:
            result.rejects.append(
                ParseReject(file_id, "file", str(path), f"Corrupted archive: {e}")
            )

    return result
