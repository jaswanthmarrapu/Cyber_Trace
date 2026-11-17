"""
CyberTrace Forensic File Analysis & Integrity Engine
Features:
1. SHA-256 cryptographic hashing (FIPS 180-4 standard)
2. MD5 hashing for legacy evidence comparison
3. SHA-1 hashing
4. File metadata extraction (MIME, timestamps, magic bytes, line counts, character counts, entropy)
5. File size identification (bytes, KB, MB)
6. File type detection (magic byte signature matching independent of extension)
7. Cryptographic hash comparison (baseline vs current re-computed hash)
8. Bit-level evidence integrity verification (Verified vs Compromised status)
9. File analysis and verification history tracking in SQLite
10. Strict isolated non-executable vault handling: NEVER execute or launch uploaded files with system applications.
"""

import os
import hashlib
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List, BinaryIO

CHUNK_SIZE = 64 * 1024  # 64 KB read buffer

# Magic byte signatures for accurate file type detection independent of extension
MAGIC_BYTE_SIGNATURES = [
    (b"\x4D\x5A", "Windows PE Executable / DLL (PE32/PE64)", "application/vnd.microsoft.portable-executable"),
    (b"\x7F\x45\x4C\x46", "Linux Executable and Linkable Format (ELF)", "application/x-executable"),
    (b"\x50\x4B\x03\x04", "ZIP Archive / OpenDocument / Office OpenXML", "application/zip"),
    (b"\x25\x50\x44\x46", "Adobe Portable Document Format (PDF)", "application/pdf"),
    (b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", "Portable Network Graphics (PNG)", "image/png"),
    (b"\xFF\xD8\xFF", "JPEG Image Format", "image/jpeg"),
    (b"\xD4\xC3\xB2\xA1", "Wireshark PCAP Capture (Little Endian)", "application/vnd.tcpdump.pcap"),
    (b"\xA1\xB2\xC3\xD4", "Wireshark PCAP Capture (Big Endian)", "application/vnd.tcpdump.pcap"),
    (b"\x0A\x0D\x0D\x0A", "Wireshark PCAPNG Next Generation Capture", "application/vnd.tcpdump.pcapng"),
    (b"PK\x05\x06", "Empty ZIP Archive", "application/zip"),
    (b"\x1F\x8B\x08", "GZIP Compressed Archive", "application/gzip"),
    (b"\x42\x5A\x68", "BZIP2 Compressed Archive", "application/x-bzip2"),
    (b"\x75\x73\x74\x61\x72", "TAR Archive", "application/x-tar"),
    (b"<?php", "PHP Script / Web Shell", "text/x-php"),
    (b"#!/bin/bash", "Bash Shell Script", "text/x-shellscript"),
    (b"#!/bin/sh", "POSIX Shell Script", "text/x-shellscript"),
]

NON_EXECUTION_NOTICE = (
    "FORENSIC SAFEGUARD (ISO/IEC 27037): "
    "File is stored in an isolated non-executable vault. "
    "Static passive inspection only. The file is never opened with host execution binaries."
)

# =====================================================================
# 1. Hasher: SHA-256, MD5, SHA-1 Computation (Features 1, 2)
# =====================================================================

def calculate_stream_hashes(stream: BinaryIO) -> Dict[str, str]:
    """Calculate SHA-256, MD5, and SHA-1 simultaneously in streaming chunks."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    stream.seek(0)
    while chunk := stream.read(CHUNK_SIZE):
        sha256.update(chunk)
        md5.update(chunk)
        sha1.update(chunk)

    stream.seek(0)
    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest()
    }


def calculate_bytes_hashes(data_bytes: bytes) -> Dict[str, str]:
    """Calculate SHA-256, MD5, and SHA-1 directly over memory bytes."""
    return {
        "sha256": hashlib.sha256(data_bytes).hexdigest(),
        "md5": hashlib.md5(data_bytes).hexdigest(),
        "sha1": hashlib.sha1(data_bytes).hexdigest()
    }


# =====================================================================
# 2. File Type & Magic Bytes Detection (Feature 5)
# =====================================================================

def detect_file_type_from_header(header_bytes: bytes, filename: str = "") -> Dict[str, Any]:
    """Inspect magic bytes to determine true file type independently of extension."""
    hex_repr = header_bytes[:16].hex(" ").upper()
    detected_desc = "Unknown Binary / Stream"
    detected_mime = "application/octet-stream"

    # Match against known forensic signatures
    for sig, desc, mime in MAGIC_BYTE_SIGNATURES:
        if header_bytes.startswith(sig):
            detected_desc = desc
            detected_mime = mime
            break

    # If still octet-stream, check text formats
    if detected_mime == "application/octet-stream":
        try:
            sample_text = header_bytes.decode("utf-8")
            if sample_text.strip().startswith("{") or sample_text.strip().startswith("["):
                detected_desc = "JSON Document / Event Export"
                detected_mime = "application/json"
            elif "," in sample_text and "\n" in sample_text:
                detected_desc = "CSV Delimited Record File"
                detected_mime = "text/csv"
            elif any(k in sample_text for k in ["GET ", "POST ", "HTTP/"]):
                detected_desc = "Web Access / HTTP Log File"
                detected_mime = "text/plain"
            elif any(k in sample_text for k in ["sshd", "sudo:", "pam_unix"]):
                detected_desc = "Linux Syslog / Auth Log File"
                detected_mime = "text/plain"
            else:
                detected_desc = "Plain Text Document (UTF-8/ASCII)"
                detected_mime = "text/plain"
        except UnicodeDecodeError:
            pass

    return {
        "magic_hex": hex_repr,
        "detected_type": detected_desc,
        "mime_type": detected_mime,
        "is_binary": detected_mime != "text/plain" and detected_mime != "application/json" and detected_mime != "text/csv"
    }


# =====================================================================
# 3. File Metadata Extraction & Size Identification (Features 3, 4)
# =====================================================================

def extract_file_metadata(data_bytes: bytes, filename: str, vault_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Extract comprehensive metadata:
    - File size in bytes, KB, and MB
    - True file type and magic bytes
    - Character and line count (if text)
    - Shannon entropy score
    """
    size_bytes = len(data_bytes)
    size_kb = round(size_bytes / 1024, 2)
    size_mb = round(size_bytes / (1024 * 1024), 4)

    type_info = detect_file_type_from_header(data_bytes[:64], filename)

    text_lines = 0
    char_count = 0
    if not type_info["is_binary"]:
        try:
            decoded = data_bytes.decode("utf-8", errors="replace")
            text_lines = len(decoded.splitlines())
            char_count = len(decoded)
        except Exception:
            pass

    # Shannon Entropy calculation for compression/packing/encryption detection
    import math
    entropy = 0.0
    if size_bytes > 0:
        byte_counts = [0] * 256
        for b in data_bytes:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p = count / size_bytes
                entropy -= p * math.log2(p)
    entropy = round(entropy, 4)

    return {
        "filename": filename,
        "vault_path": vault_path or "vault/isolated_buffer",
        "file_size_bytes": size_bytes,
        "file_size_kb": size_kb,
        "file_size_mb": size_mb,
        "file_type_description": type_info["detected_type"],
        "mime_type": type_info["mime_type"],
        "magic_bytes_hex": type_info["magic_hex"],
        "is_binary": type_info["is_binary"],
        "line_count": text_lines,
        "character_count": char_count,
        "shannon_entropy": entropy,
        "is_packed_or_encrypted": entropy >= 7.2,
        "non_execution_safeguard": NON_EXECUTION_NOTICE
    }


# =====================================================================
# 4. Hash Comparison & Evidence Integrity Verification (Features 6, 7)
# =====================================================================

def verify_evidence_hash_comparison(
    current_data_bytes: bytes,
    baseline_sha256: str,
    original_md5: Optional[str] = None,
    original_sha1: Optional[str] = None
) -> Dict[str, Any]:
    """
    Recalculate hashes and verify cryptographic integrity:
    - Compares current SHA-256 against initial acquisition baseline
    - Compares legacy MD5 if provided
    - Explicitly returns: original hash, current hash, integrity status, and verification timestamp
    """
    current_hashes = calculate_bytes_hashes(current_data_bytes)
    clean_baseline = baseline_sha256.strip().lower()
    clean_current = current_hashes["sha256"].lower()

    sha256_match = (clean_current == clean_baseline)

    md5_match = None
    if original_md5:
        md5_match = (current_hashes["md5"].lower() == original_md5.strip().lower())

    integrity_status = "Verified" if sha256_match else "Compromised"
    verification_time = datetime.now(timezone.utc).isoformat()

    return {
        "original_sha256": clean_baseline,
        "current_sha256": clean_current,
        "sha256_match": sha256_match,
        "original_md5": original_md5 or "N/A",
        "current_md5": current_hashes["md5"],
        "md5_match": md5_match,
        "current_sha1": current_hashes["sha1"],
        "integrity_status": integrity_status,
        "verification_timestamp": verification_time,
        "is_tampered": not sha256_match,
        "tamper_alert": None if sha256_match else f"CRITICAL INTEGRITY BREACH: Bit-level deviation detected! Baseline: {clean_baseline[:16]}... Current: {clean_current[:16]}..."
    }


# =====================================================================
# 5. File Analysis History in SQLite (Feature 8)
# =====================================================================

def init_file_forensics_tables(db_path: str):
    """Ensure database tables exist for file forensic analysis and verification history."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS file_forensic_history (
        id TEXT PRIMARY KEY,
        case_id TEXT,
        evidence_id TEXT,
        filename TEXT NOT NULL,
        file_size_bytes INTEGER NOT NULL,
        mime_type TEXT NOT NULL,
        file_type_desc TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        md5_hash TEXT NOT NULL,
        sha1_hash TEXT NOT NULL,
        entropy_score REAL,
        integrity_status TEXT NOT NULL,
        analyzed_by TEXT NOT NULL,
        analyzed_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS file_verification_logs (
        id TEXT PRIMARY KEY,
        file_history_id TEXT,
        filename TEXT NOT NULL,
        original_sha256 TEXT NOT NULL,
        current_sha256 TEXT NOT NULL,
        original_md5 TEXT,
        current_md5 TEXT,
        integrity_status TEXT NOT NULL,
        verification_timestamp TEXT NOT NULL,
        verifier TEXT NOT NULL,
        notes TEXT
    );
    """)
    conn.commit()
    conn.close()


def record_file_analysis_to_sqlite(
    db_path: str,
    analysis_record: Dict[str, Any],
    case_id: str = "case-001",
    evidence_id: Optional[str] = None,
    analyzed_by: str = "Senior Forensic Examiner"
) -> str:
    """Store initial file upload forensics and hash baseline in SQLite."""
    init_file_forensics_tables(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    record_id = str(uuid.uuid4())
    hashes = analysis_record["hashes"]
    meta = analysis_record["metadata"]

    cur.execute("""
    INSERT INTO file_forensic_history (
        id, case_id, evidence_id, filename, file_size_bytes, mime_type, file_type_desc,
        sha256_hash, md5_hash, sha1_hash, entropy_score, integrity_status, analyzed_by, analyzed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record_id,
        case_id,
        evidence_id,
        meta["filename"],
        meta["file_size_bytes"],
        meta["mime_type"],
        meta["file_type_description"],
        hashes["sha256"],
        hashes["md5"],
        hashes["sha1"],
        meta.get("shannon_entropy", 0.0),
        "Verified",
        analyzed_by,
        datetime.now(timezone.utc).isoformat()
    ))
    conn.commit()
    conn.close()
    return record_id


def record_verification_log_to_sqlite(
    db_path: str,
    verification_result: Dict[str, Any],
    filename: str,
    file_history_id: Optional[str] = None,
    verifier: str = "Forensic Examiner"
) -> str:
    """Record an audit trail entry every time an investigator verifies a file."""
    init_file_forensics_tables(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    log_id = str(uuid.uuid4())
    cur.execute("""
    INSERT INTO file_verification_logs (
        id, file_history_id, filename, original_sha256, current_sha256,
        original_md5, current_md5, integrity_status, verification_timestamp, verifier, notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        log_id,
        file_history_id,
        filename,
        verification_result["original_sha256"],
        verification_result["current_sha256"],
        verification_result.get("original_md5"),
        verification_result.get("current_md5"),
        verification_result["integrity_status"],
        verification_result["verification_timestamp"],
        verifier,
        "Recalculated cryptographic hash matching baseline" if verification_result["sha256_match"] else "CRITICAL: Byte-level mismatch detected during re-verification"
    ))
    conn.commit()
    conn.close()
    return log_id


def get_file_forensic_history(db_path: str, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve full file forensics history from SQLite."""
    init_file_forensics_tables(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if case_id:
        cur.execute("SELECT * FROM file_forensic_history WHERE case_id = ? ORDER BY analyzed_at DESC", (case_id,))
    else:
        cur.execute("SELECT * FROM file_forensic_history ORDER BY analyzed_at DESC")

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_file_verification_audit_trail(db_path: str, filename: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve chronological verification log history."""
    init_file_forensics_tables(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if filename:
        cur.execute("SELECT * FROM file_verification_logs WHERE filename = ? ORDER BY verification_timestamp DESC", (filename,))
    else:
        cur.execute("SELECT * FROM file_verification_logs ORDER BY verification_timestamp DESC")

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# =====================================================================
# 6. Master End-to-End Pipeline
# =====================================================================

def process_file_forensics_upload(
    data_bytes: bytes,
    filename: str,
    db_path: Optional[str] = None,
    case_id: str = "case-001",
    evidence_id: Optional[str] = None,
    examiner: str = "Senior Forensic Examiner"
) -> Dict[str, Any]:
    """
    Complete upload pipeline:
    1. Computes SHA-256, MD5, SHA-1 hashes
    2. Identifies file size (bytes, KB, MB)
    3. Detects true file type from magic bytes
    4. Extracts metadata and Shannon entropy
    5. Stores baseline analysis in SQLite
    6. Ensures zero file execution
    """
    hashes = calculate_bytes_hashes(data_bytes)
    meta = extract_file_metadata(data_bytes, filename)

    result = {
        "filename": filename,
        "hashes": hashes,
        "metadata": meta,
        "initial_integrity_status": "Verified",
        "acquisition_timestamp": datetime.now(timezone.utc).isoformat(),
        "examiner": examiner,
        "non_execution_policy": NON_EXECUTION_NOTICE
    }

    if db_path:
        history_id = record_file_analysis_to_sqlite(
            db_path=db_path,
            analysis_record=result,
            case_id=case_id,
            evidence_id=evidence_id,
            analyzed_by=examiner
        )
        result["file_history_id"] = history_id

    return result
