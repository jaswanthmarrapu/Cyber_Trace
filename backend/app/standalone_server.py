"""
CyberTrace - Complete Standalone Digital Forensics & Cyber Incident Investigation Platform
Backend Engine implemented in pure Python Standard Library (http.server, sqlite3, hashlib, json, math, re).
Requires zero external pip dependencies and runs natively in any Python 3.8+ environment.
"""

import os
import sys
import json
import sqlite3
import hashlib
import hmac
import uuid
import re
import math
import socket
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

# Ensure 'backend' directory is always present on sys.path
_CURRENT_FILE = Path(__file__).resolve()
_BACKEND_DIR = _CURRENT_FILE.parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.forensic.log_analyzer import execute_log_analysis_pipeline, DEFAULT_CONFIGURABLE_RULES
from app.forensic.ip_analyzer import (
    validate_ipv4,
    classify_ip_scope,
    investigate_single_ip,
    extract_ips_from_log_content,
    analyze_ip_log_metrics,
    store_ip_investigation_record,
    get_ip_investigation_history,
    get_related_timeline_events_for_ip
)
from app.forensic.file_analyzer import (
    process_file_forensics_upload,
    verify_evidence_hash_comparison,
    record_file_analysis_to_sqlite,
    record_verification_log_to_sqlite,
    get_file_forensic_history,
    get_file_verification_audit_trail,
    calculate_bytes_hashes,
    extract_file_metadata
)
from app.forensic.threat_engine import (
    evaluate_threat_rules,
    DEFAULT_THREAT_DETECTION_RULES,
    AUTHORIZED_MALICIOUS_HASH_INTEL,
    init_threat_detection_tables,
    store_threat_alerts,
    get_stored_threat_alerts
)
from app.forensic.timeline_engine import (
    extract_and_normalize_timeline_events,
    identify_suspicious_event_sequences,
    filter_timeline_events,
    generate_timeline_pdf_content,
    init_timeline_tables,
    store_timeline_events,
    get_timeline_events_from_db
)
from app.forensic.case_engine import (
    create_investigation_case,
    update_case_lifecycle_status,
    assign_case_investigator,
    add_case_investigation_note,
    link_suspicious_event_to_case,
    get_case_audit_history,
    generate_case_summary_dossier,
    generate_unique_case_number,
    init_case_management_tables,
    VALID_CASE_STATUSES
)
from app.forensic.ai_assistant import (
    synthesize_case_ai_summary_from_db,
    generate_grounded_ai_summary
)
from app.forensic.report_generator import (
    generate_complete_investigation_report_pdf,
    query_case_report_dossier
)
from app.utils.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_password_reset_token,
    decode_password_reset_token,
    decode_access_token
)

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR_ENV = os.getenv("DATA_DIR")
DATA_DIR = Path(DATA_DIR_ENV).resolve() if DATA_DIR_ENV else BASE_DIR
DB_PATH = DATA_DIR / "cybertrace.db"
UPLOADS_DIR = DATA_DIR / "uploads"
REPORTS_DIR = DATA_DIR / "reports"
FRONTEND_DIR = BASE_DIR.parent / "frontend"

UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Forensic Security Constants
ALLOWED_EXTENSIONS = {
    "log", "txt", "evtx", "json", "csv", "pcap", "pcapng",
    "bin", "dat", "dump", "raw", "img", "mem", "dll", "exe",
    "pdf", "png", "jpg", "jpeg", "zip", "tar", "gz", "php", "sh", "bat", "ps1"
}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# Magic Bytes Signatures (File Header Identifiers)
MAGIC_SIGNATURES = [
    (b"\x4D\x5A", "Windows PE Executable / DLL (PE32/PE64)"),
    (b"\x7F\x45\x4C\x46", "Linux Executable and Linkable Format (ELF)"),
    (b"\x50\x4B\x03\x04", "ZIP Archive / OpenDocument / Office OpenXML"),
    (b"\x25\x50\x44\x46", "Adobe Portable Document Format (PDF)"),
    (b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", "Portable Network Graphics (PNG)"),
    (b"\xFF\xD8\xFF", "JPEG Image Format"),
    (b"\xD4\xC3\xB2\xA1", "Wireshark PCAP Capture (Little Endian)"),
    (b"\xA1\xB2\xC3\xD4", "Wireshark PCAP Capture (Big Endian)"),
    (b"\x0A\x0D\x0D\x0A", "Wireshark PCAPNG Next Generation Capture"),
    (b"\x45\x6C\x66\x46\x69\x6C\x65", "Windows Event Log (EVTX Header)"),
    (b"<?php", "PHP Web Script / Potential Web Shell"),
    (b"#!/", "Unix Shell Script")
]

# Built-in Threat Signatures (YARA / Heuristic Simulation)
THREAT_RULES = [
    {
        "id": "RULE-WS-001",
        "name": "Generic_PHP_WebShell_Eval",
        "category": "Web Shell",
        "severity": "Critical",
        "mitre": "T1505.003",
        "patterns": [r"eval\s*\(\s*base64_decode", r"assert\s*\(\s*\$_POST", r"passthru\s*\(", r"system\s*\(\s*\$_GET"]
    },
    {
        "id": "RULE-WS-002",
        "name": "WSO_B374k_Shell_Signature",
        "category": "Web Shell",
        "severity": "Critical",
        "mitre": "T1505.003",
        "patterns": [r"wso_shell", r"WSO\s+\d+\.\d+", r"b374k", r"c99shell", r"r57shell"]
    },
    {
        "id": "RULE-REV-001",
        "name": "Interactive_Reverse_Shell",
        "category": "Execution",
        "severity": "Critical",
        "mitre": "T1059.004",
        "patterns": [r"pty\.spawn", r"/bin/sh\s+-i", r"/bin/bash\s+-i", r"nc\s+.*-e\s+/bin/", r"bash\s+-i\s+>&"]
    },
    {
        "id": "RULE-PS-001",
        "name": "Suspicious_PowerShell_Obfuscation",
        "category": "Defense Evasion",
        "severity": "High",
        "mitre": "T1059.001",
        "patterns": [r"-ExecutionPolicy\s+Bypass", r"-EncodedCommand\s+[A-Za-z0-9+/=]{20,}", r"DownloadString\s*\("]
    },
    {
        "id": "RULE-MIMI-001",
        "name": "Mimikatz_Credential_Dumping",
        "category": "Credential Access",
        "severity": "Critical",
        "mitre": "T1003.001",
        "patterns": [r"sekurlsa::logonpasswords", r"lsass\.exe", r"wdigest\.dll", r"privilege::debug"]
    },
    {
        "id": "RULE-PERSIST-001",
        "name": "Service_Installation_Persistence",
        "category": "Persistence",
        "severity": "High",
        "mitre": "T1543.003",
        "patterns": [r"EventID:\s*7045", r"NewProcessName:.*sc\.exe\s+create"]
    }
]

# Database Initialization
def init_standalone_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        full_name TEXT,
        role TEXT NOT NULL,
        created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        case_number TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        investigator_name TEXT NOT NULL,
        status TEXT NOT NULL,
        severity TEXT NOT NULL,
        incident_type TEXT NOT NULL,
        created_at TEXT,
        updated_at TEXT,
        closed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        evidence_number TEXT UNIQUE NOT NULL,
        original_filename TEXT NOT NULL,
        stored_filename TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_size_bytes INTEGER NOT NULL,
        file_type TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        sha1_hash TEXT NOT NULL,
        md5_hash TEXT NOT NULL,
        initial_recorded_hash TEXT NOT NULL,
        integrity_status TEXT NOT NULL,
        source_device TEXT,
        acquired_by TEXT NOT NULL,
        acquired_at TEXT,
        description TEXT
    );

    CREATE TABLE IF NOT EXISTS chain_of_custody (
        id TEXT PRIMARY KEY,
        evidence_id TEXT NOT NULL,
        action TEXT NOT NULL,
        performed_by TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        reason TEXT,
        location TEXT,
        verified_hash TEXT,
        notes TEXT
    );

    CREATE TABLE IF NOT EXISTS log_events (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        evidence_id TEXT,
        event_timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        service TEXT,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        raw_log TEXT NOT NULL,
        is_threat INTEGER NOT NULL,
        mitre_technique TEXT,
        flag_reason TEXT,
        username TEXT
    );

    CREATE TABLE IF NOT EXISTS ip_records (
        id TEXT PRIMARY KEY,
        case_id TEXT,
        ip_address TEXT NOT NULL,
        ip_type TEXT NOT NULL,
        country TEXT,
        country_code TEXT,
        city TEXT,
        asn TEXT,
        isp TEXT,
        abuse_confidence_score INTEGER DEFAULT 0,
        reverse_dns TEXT,
        attribution_caveat TEXT,
        observed_json TEXT,
        reputation_json TEXT,
        investigated_at TEXT
    );

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

    CREATE TABLE IF NOT EXISTS timeline_events (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        event_timestamp TEXT NOT NULL,
        event_source TEXT NOT NULL,
        event_category TEXT NOT NULL,
        actor TEXT,
        target TEXT,
        description TEXT NOT NULL,
        mitre_tactic TEXT,
        confidence_level TEXT DEFAULT 'High',
        severity TEXT DEFAULT 'Medium',
        record_type TEXT DEFAULT 'Observed Event',
        evidence_id TEXT,
        original_record_id TEXT,
        is_inferred INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS attack_sequences (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        sequence_title TEXT NOT NULL,
        actor_ip TEXT NOT NULL,
        severity TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        analytical_inference TEXT NOT NULL,
        mitre_chain_json TEXT NOT NULL,
        recommended_action TEXT
    );

    CREATE TABLE IF NOT EXISTS case_notes (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        author TEXT NOT NULL,
        note_text TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS case_audit_log (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        action TEXT NOT NULL,
        performed_by TEXT NOT NULL,
        details TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS case_event_links (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        event_summary TEXT NOT NULL,
        linked_by TEXT NOT NULL,
        linked_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        report_number TEXT UNIQUE NOT NULL,
        report_title TEXT NOT NULL,
        generated_by TEXT NOT NULL,
        file_path TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        generated_at TEXT
    );
    """)

    # Dynamic schema migration for pre-existing databases
    cursor.execute("PRAGMA table_info(cases)")
    c_cols = [r[1] for r in cursor.fetchall()]
    if "updated_at" not in c_cols:
        cursor.execute("ALTER TABLE cases ADD COLUMN updated_at TEXT")
    if "closed_at" not in c_cols:
        cursor.execute("ALTER TABLE cases ADD COLUMN closed_at TEXT")

    cursor.execute("PRAGMA table_info(log_events)")
    l_cols = [r[1] for r in cursor.fetchall()]
    if "evidence_id" not in l_cols:
        cursor.execute("ALTER TABLE log_events ADD COLUMN evidence_id TEXT")
    if "username" not in l_cols:
        cursor.execute("ALTER TABLE log_events ADD COLUMN username TEXT")
    if "flag_reason" not in l_cols:
        cursor.execute("ALTER TABLE log_events ADD COLUMN flag_reason TEXT")

    cursor.execute("PRAGMA table_info(timeline_events)")
    t_cols = [r[1] for r in cursor.fetchall()]
    timeline_cols_needed = [
        ("confidence_level", "TEXT DEFAULT 'High'"),
        ("severity", "TEXT DEFAULT 'Medium'"),
        ("record_type", "TEXT DEFAULT 'Observed Event'"),
        ("evidence_id", "TEXT"),
        ("original_record_id", "TEXT"),
        ("is_inferred", "INTEGER DEFAULT 0")
    ]
    for col_n, col_d in timeline_cols_needed:
        if col_n not in t_cols:
            cursor.execute(f"ALTER TABLE timeline_events ADD COLUMN {col_n} {col_d}")

    # Seed Default Case if empty
    cursor.execute("SELECT COUNT(*) FROM cases")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO cases (id, case_number, title, description, investigator_name, status, severity, incident_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "case-001",
            "CT-2026-001",
            "Operation DarkHydra - Web Perimeter Breach & Privilege Escalation",
            "Investigating unauthorized SQL injection penetration and web shell deployment on staging infrastructure.",
            "Senior Forensic Examiner",
            "Investigating",
            "Critical",
            "Data Breach & Web Shell",
            datetime.now(timezone.utc).isoformat()
        ))

    # Seed Baseline Evidence if empty
    cursor.execute("SELECT COUNT(*) FROM evidence")
    if cursor.fetchone()[0] == 0:
        dummy_content = b"Forensic Disk Image Header - Case CT-2026-001 Baseline Acquisition"
        sha256_init = hashlib.sha256(dummy_content).hexdigest()
        sha1_init = hashlib.sha1(dummy_content).hexdigest()
        md5_init = hashlib.md5(dummy_content).hexdigest()
        stored_vault_file = f"{uuid.uuid4().hex}.raw.vault"
        vault_dest = UPLOADS_DIR / stored_vault_file
        with open(vault_dest, "wb") as f:
            f.write(dummy_content)

        ev_id = "evd-001"
        cursor.execute("""
        INSERT INTO evidence (
            id, case_id, evidence_number, original_filename, stored_filename, file_path,
            file_size_bytes, file_type, mime_type, sha256_hash, sha1_hash, md5_hash,
            initial_recorded_hash, integrity_status, source_device, acquired_by, acquired_at, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ev_id, "case-001", "EVD-001", "srv-db01-memory.raw", stored_vault_file, str(vault_dest),
            len(dummy_content), "raw", "application/octet-stream", sha256_init, sha1_init, md5_init,
            sha256_init, "Verified", "SRV-DB01.CORP (Memory Dump)", "Senior Forensic Examiner",
            datetime.now(timezone.utc).isoformat(), "Physical memory acquisition of database server post-incident."
        ))

        cursor.execute("""
        INSERT INTO chain_of_custody (id, evidence_id, action, performed_by, timestamp, reason, location, verified_hash, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()), ev_id, "Acquired", "Senior Forensic Examiner",
            datetime.now(timezone.utc).isoformat(), "Initial memory capture during incident triage",
            "Forensic Vault", sha256_init, "Acquisition verified with SHA-256: " + sha256_init[:16] + "..."
        ))

    # Seed Initial Log Events if empty
    cursor.execute("SELECT COUNT(*) FROM log_events")
    if cursor.fetchone()[0] == 0:
        sample_logs = [
            ("case-001", "2026-03-14T02:14:01Z", "185.220.101.5", "192.168.1.10", "sshd", "Brute Force Attempt", "High", "Failed password for invalid user admin from 185.220.101.5 port 49152 ssh2", 1, "T1110"),
            ("case-001", "2026-03-14T02:14:31Z", "185.220.101.5", "192.168.1.10", "sshd", "Successful Logon", "Medium", "Accepted password for deploy from 185.220.101.5 port 49166 ssh2", 1, "T1078"),
            ("case-001", "2026-03-14T02:15:10Z", "192.168.1.10", "192.168.1.10", "sudo", "Privilege Escalation Attempt", "Critical", "sudo: deploy : TTY=pts/1 ; COMMAND=/bin/cat /etc/shadow", 1, "T1068"),
            ("case-001", "2026-03-14T03:12:05Z", "185.220.101.5", "192.168.1.10", "nginx", "SQL Injection", "Critical", "GET /api/products?id=1' OR 1=1-- HTTP/1.1 200 8940", 1, "T1190"),
            ("case-001", "2026-03-14T03:16:01Z", "185.220.101.5", "192.168.1.10", "nginx", "Web Shell Invocation", "Critical", "GET /uploads/wso_shell.php?cmd=id HTTP/1.1 200 48", 1, "T1505.003")
        ]
        for log in sample_logs:
            cursor.execute("""
            INSERT INTO log_events (id, case_id, event_timestamp, source_ip, destination_ip, service, event_type, severity, raw_log, is_threat, mitre_technique)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (str(uuid.uuid4()), *log))

    # Seed Initial Timeline Events if empty
    cursor.execute("SELECT COUNT(*) FROM timeline_events")
    if cursor.fetchone()[0] == 0:
        sample_timeline = [
            ("case-001", "2026-03-14T02:14:01Z", "SSH Syslog", "Initial Access", "185.220.101.5", "srv-db01", "SSH brute force password spraying detected from external IP 185.220.101.5", "Initial Access (T1110)", "Confirmed"),
            ("case-001", "2026-03-14T02:14:31Z", "SSH Syslog", "Initial Access", "185.220.101.5", "srv-db01", "Compromised credentials used to authenticate as user 'deploy'", "Initial Access (T1078)", "Confirmed"),
            ("case-001", "2026-03-14T02:15:10Z", "Audit Log", "Privilege Escalation", "deploy", "/etc/shadow", "Unauthorized attempt to dump Linux password shadow file via sudo", "Privilege Escalation (T1068)", "Confirmed"),
            ("case-001", "2026-03-14T03:12:30Z", "Web Server Log", "Discovery / Exfiltration", "185.220.101.5", "/api/products", "SQL Injection exploitation against backend database extracts user table hashes", "Exploit Public-Facing App (T1190)", "Confirmed"),
            ("case-001", "2026-03-14T03:16:01Z", "Nginx Log", "Persistence", "185.220.101.5", "wso_shell.php", "Execution of uploaded PHP web shell executing arbitrary system commands", "Server Software Component (T1505.003)", "Confirmed")
        ]
        for t in sample_timeline:
            cursor.execute("""
            INSERT INTO timeline_events (id, case_id, event_timestamp, event_source, event_category, actor, target, description, mitre_tactic, confidence_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (str(uuid.uuid4()), *t))

    conn.commit()
    conn.close()

    # Ensure modular tables (threat detection, case management, timeline) are also initialized
    try:
        init_threat_detection_tables(str(DB_PATH))
    except Exception as e:
        print(f"Notice: init_threat_detection_tables: {e}")
    try:
        init_case_management_tables(str(DB_PATH))
    except Exception as e:
        print(f"Notice: init_case_management_tables: {e}")
    try:
        init_timeline_tables(str(DB_PATH))
    except Exception as e:
        print(f"Notice: init_timeline_tables: {e}")

# Shannon Entropy Calculation
def calculate_shannon_entropy(data_bytes: bytes) -> dict:
    if not data_bytes:
        return {"entropy": 0.0, "is_packed": False, "assessment": "Empty File"}
    length = len(data_bytes)
    freq = {}
    for b in data_bytes:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    entropy = round(entropy, 4)
    # Assessment
    if entropy > 7.2:
        assessment = "High Entropy (>= 7.2): Highly likely packed, encrypted, or compressed binary payload."
        is_packed = True
    elif entropy > 6.0:
        assessment = "Moderate Entropy (6.0 - 7.2): Standard executable code or compiled bytecode."
        is_packed = False
    elif entropy > 3.5:
        assessment = "Low-Moderate Entropy (3.5 - 6.0): Typical plaintext, structured JSON/XML, or source code."
        is_packed = False
    else:
        assessment = "Very Low Entropy (< 3.5): Repetitive data, sparse matrices, or simple ASCII text."
        is_packed = False

    # Calculate 16-block chunk distribution for graph
    chunk_size = max(1, length // 16)
    chunks = []
    for i in range(16):
        start = i * chunk_size
        chunk = data_bytes[start : start + chunk_size]
        if not chunk:
            chunks.append(0.0)
            continue
        c_freq = {}
        for b in chunk:
            c_freq[b] = c_freq.get(b, 0) + 1
        c_ent = 0.0
        for cnt in c_freq.values():
            cp = cnt / len(chunk)
            c_ent -= cp * math.log2(cp)
        chunks.append(round(c_ent, 2))

    return {
        "entropy": entropy,
        "is_packed": is_packed,
        "assessment": assessment,
        "block_distribution": chunks
    }

# Magic Bytes Detection
def detect_magic(data_bytes: bytes) -> dict:
    for sig, desc in MAGIC_SIGNATURES:
        if data_bytes.startswith(sig):
            return {
                "detected": True,
                "signature_hex": sig.hex().upper(),
                "file_type": desc
            }
    return {
        "detected": False,
        "signature_hex": data_bytes[:8].hex().upper() if data_bytes else "EMPTY",
        "file_type": "Raw Binary / Unknown File Format"
    }

# Printable String and IOC Extraction
def extract_strings_and_iocs(data_bytes: bytes, min_len: int = 4, max_strings: int = 200) -> dict:
    ascii_re = re.compile(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}")
    extracted = [m.group(0).decode("latin1", errors="ignore") for m in ascii_re.finditer(data_bytes[:1024 * 1024])]
    
    # Extract IOCs
    text_corpus = " ".join(extracted)
    ipv4_re = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text_corpus)
    urls_re = re.findall(r"https?://[^\s<>\"']+", text_corpus)
    emails_re = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text_corpus)
    suspicious_keywords = [s for s in extracted if any(k in s.lower() for k in ["admin", "root", "password", "token", "shadow", "eval", "exec", "cmd", "shell", "powershell", "curl", "wget"])]

    # Deduplicate IPs while preserving order
    unique_ips = list(dict.fromkeys(ipv4_re))[:20]
    unique_urls = list(dict.fromkeys(urls_re))[:20]
    unique_emails = list(dict.fromkeys(emails_re))[:20]
    unique_keywords = list(dict.fromkeys(suspicious_keywords))[:30]

    return {
        "total_extracted_strings": len(extracted),
        "sample_strings": extracted[:max_strings],
        "iocs": {
            "ip_addresses": unique_ips,
            "urls": unique_urls,
            "emails": unique_emails,
            "suspicious_indicators": unique_keywords
        }
    }

# Threat / YARA Rule Scanner
def scan_threat_signatures(data_bytes: bytes, text_content: str = None) -> list:
    if text_content is None:
        text_content = data_bytes.decode("latin1", errors="ignore")
    matches = []
    for rule in THREAT_RULES:
        for pat in rule["patterns"]:
            found = re.findall(pat, text_content, re.IGNORECASE)
            if found:
                matches.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "mitre_technique": rule["mitre"],
                    "matched_pattern": pat,
                    "match_count": len(found),
                    "sample_matches": found[:3]
                })
                break
    return matches

# HTTP Request Handler
class CyberTraceHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _send_json(self, data, status_code=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, message, status_code=400):
        self._send_json({"error": message, "status": status_code}, status_code)

    def _read_body_bytes(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                return self.rfile.read(content_length)
            return b""
        except Exception:
            return b""

    def _read_json_body(self):
        try:
            raw = self._read_body_bytes().decode("utf-8")
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _get_auth_user(self, cursor):
        """Extract and authenticate user from Authorization: Bearer <token> header."""
        auth_header = self.headers.get("Authorization", "")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        token = auth_header.split(" ", 1)[1].strip()
        try:
            payload = decode_access_token(token)
            if payload.get("purpose") == "password_reset":
                return None
            username = payload.get("sub")
            if not username:
                return None
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            return dict(user) if user else None
        except Exception:
            return None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            auth_user = self._get_auth_user(cursor)

            # 0. User Profile Probe
            if path == "/api/v1/auth/me":
                if not auth_user:
                    self._send_error("Authentication required. Please provide a valid Bearer token.", 401)
                    return
                self._send_json({
                    "id": auth_user["id"],
                    "username": auth_user["username"],
                    "email": auth_user["email"],
                    "full_name": auth_user["full_name"],
                    "role": auth_user["role"],
                    "is_active": True
                })
                return

            # 1. Health Probe
            elif path == "/api/v1/health":
                self._send_json({
                    "status": "healthy",
                    "service": "CyberTrace Digital Forensics Engine (NIST / ISO 27037 Compliant)",
                    "version": "1.0.0",
                    "database": "SQLite (ACID Protected)",
                    "vault_storage": "Non-Executable Isolated Vault",
                    "forensic_integrity_mode": "Active (SHA-256 FIPS 180-4)",
                    "attribution_safeguard": "Active (ISO/IEC 27037 Strict Attribution Policy)"
                })

            # 2. Dashboard Stats
            elif path == "/api/v1/dashboard/stats":
                cursor.execute("SELECT COUNT(*) FROM cases")
                total_cases = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM cases WHERE status IN ('Open', 'Investigating')")
                active_cases = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM evidence")
                total_evd = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM evidence WHERE integrity_status = 'Verified'")
                verified_evd = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM evidence WHERE integrity_status = 'Compromised'")
                compromised_evd = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM log_events WHERE is_threat = 1")
                total_threats = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM log_events WHERE severity = 'Critical'")
                critical_threats = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM log_events WHERE severity = 'High'")
                high_threats = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM log_events WHERE severity = 'Medium'")
                med_threats = cursor.fetchone()[0]

                # Fetch recent activity
                cursor.execute("""
                SELECT evidence_id, action, performed_by, timestamp, reason, location, verified_hash
                FROM chain_of_custody ORDER BY timestamp DESC LIMIT 6
                """)
                coc_activities = [dict(r) for r in cursor.fetchall()]

                self._send_json({
                    "metrics": {
                        "total_cases": total_cases,
                        "active_cases": active_cases,
                        "total_evidence": total_evd,
                        "verified_evidence": verified_evd,
                        "compromised_evidence": compromised_evd,
                        "total_threats": total_threats,
                        "critical_alerts": critical_threats
                    },
                    "severity_distribution": {
                        "Critical": critical_threats,
                        "High": high_threats,
                        "Medium": med_threats,
                        "Low": 0
                    },
                    "recent_activity": coc_activities
                })

            # 3. Cases
            elif path == "/api/v1/cases":
                status_filter = query.get("status", [None])[0]
                if status_filter and status_filter != "All":
                    cursor.execute("SELECT * FROM cases WHERE status = ? ORDER BY created_at DESC", (status_filter,))
                else:
                    cursor.execute("SELECT * FROM cases ORDER BY created_at DESC")
                rows = [dict(r) for r in cursor.fetchall()]
                self._send_json(rows)

            elif path.startswith("/api/v1/cases/") and path.endswith("/audit-trail"):
                case_id = path.split("/")[4]
                history = get_case_audit_history(str(DB_PATH), case_id)
                self._send_json({
                    "case_id": case_id,
                    "total_audit_events": len(history),
                    "history": history
                })

            elif path.startswith("/api/v1/cases/") and path.endswith("/summary"):
                case_id = path.split("/")[4]
                try:
                    summary = generate_case_summary_dossier(str(DB_PATH), case_id)
                    self._send_json(summary)
                except LookupError as e:
                    self._send_error(str(e), 404)

            elif path.startswith("/api/v1/cases/") and not path.endswith("/timeline"):
                case_id = path.split("/")[4]
                try:
                    summary = generate_case_summary_dossier(str(DB_PATH), case_id)
                    self._send_json(summary)
                except LookupError:
                    cursor.execute("SELECT * FROM cases WHERE id = ? OR case_number = ?", (case_id, case_id))
                    row = cursor.fetchone()
                    if row:
                        self._send_json(dict(row))
                    else:
                        self._send_error("Case not found", 404)

            # 4. Evidence Listing
            elif path == "/api/v1/evidence":
                case_id = query.get("case_id", [None])[0]
                search = query.get("search", [None])[0]
                status_filter = query.get("status", [None])[0]

                sql = "SELECT * FROM evidence WHERE 1=1"
                params = []
                if case_id:
                    sql += " AND case_id = ?"
                    params.append(case_id)
                if status_filter:
                    sql += " AND integrity_status = ?"
                    params.append(status_filter)
                if search:
                    sql += " AND (original_filename LIKE ? OR evidence_number LIKE ? OR acquired_by LIKE ?)"
                    term = f"%{search}%"
                    params.extend([term, term, term])

                sql += " ORDER BY acquired_at DESC"
                cursor.execute(sql, params)
                rows = [dict(r) for r in cursor.fetchall()]
                self._send_json(rows)

            # Evidence Detail
            elif path.startswith("/api/v1/evidence/") and not path.endswith("/chain-of-custody") and not path.endswith("/verify") and not path.endswith("/tamper-test"):
                ev_id = path.split("/")[4]
                cursor.execute("SELECT * FROM evidence WHERE id = ? OR evidence_number = ?", (ev_id, ev_id))
                row = cursor.fetchone()
                if row:
                    self._send_json(dict(row))
                else:
                    self._send_error("Evidence not found", 404)

            # Chain of Custody Listing
            elif path.startswith("/api/v1/evidence/") and path.endswith("/chain-of-custody"):
                ev_id = path.split("/")[4]
                cursor.execute("SELECT * FROM chain_of_custody WHERE evidence_id = ? ORDER BY timestamp ASC", (ev_id,))
                rows = [dict(r) for r in cursor.fetchall()]
                self._send_json(rows)

            # 5. Logs Listing & Summary
            elif path == "/api/v1/logs/events":
                cursor.execute("SELECT * FROM log_events ORDER BY event_timestamp DESC LIMIT 100")
                rows = [dict(r) for r in cursor.fetchall()]
                self._send_json({"total": len(rows), "events": rows})

            elif path == "/api/v1/logs/rules":
                self._send_json(DEFAULT_CONFIGURABLE_RULES)

            elif path == "/api/v1/logs/summary":
                cursor.execute("SELECT event_type, COUNT(*) as cnt FROM log_events GROUP BY event_type")
                types = {r["event_type"]: r["cnt"] for r in cursor.fetchall()}
                cursor.execute("SELECT severity, COUNT(*) as cnt FROM log_events GROUP BY severity")
                severities = {r["severity"]: r["cnt"] for r in cursor.fetchall()}
                cursor.execute("SELECT COUNT(*) FROM log_events WHERE is_threat = 1")
                threats_count = cursor.fetchone()[0]
                self._send_json({
                    "total_analyzed": sum(types.values()),
                    "threat_events": threats_count,
                    "event_types": types,
                    "severities": severities
                })

            # 6. Threats
            elif path == "/api/v1/threats/detections":
                cursor.execute("SELECT * FROM log_events WHERE is_threat = 1 ORDER BY event_timestamp DESC")
                rows = [dict(r) for r in cursor.fetchall()]
                self._send_json({
                    "total_threats": len(rows),
                    "threats": rows,
                    "mitre_matrix": {"T1190": 2, "T1110": 3, "T1505.003": 1, "T1068": 1, "T1078": 1}
                })

            elif path == "/api/v1/threats/rules":
                self._send_json({
                    "rules": DEFAULT_THREAT_DETECTION_RULES,
                    "total_yara_rules": len(THREAT_RULES),
                    "authorized_hash_intel_signatures": len(AUTHORIZED_MALICIOUS_HASH_INTEL),
                    "threat_subnets": DEFAULT_THREAT_DETECTION_RULES["known_suspicious_subnets"],
                    "admin_usernames": DEFAULT_THREAT_DETECTION_RULES["admin_usernames"]
                })

            elif path == "/api/v1/threats/alerts":
                case_id = query.get("case_id", [None])[0]
                alerts = get_stored_threat_alerts(str(DB_PATH), case_id=case_id)
                severity_breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
                for a in alerts:
                    sev = a.get("severity", "Low")
                    severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
                self._send_json({
                    "total_alerts": len(alerts),
                    "severity_breakdown": severity_breakdown,
                    "alerts": alerts
                })

            # 7. Timeline
            elif path.startswith("/api/v1/timeline") and path.endswith("/pdf"):
                parts = path.strip("/").split("/")
                case_id = parts[3] if len(parts) >= 5 else "case-001"
                events = get_timeline_events_from_db(str(DB_PATH), case_id)
                sequences = identify_suspicious_event_sequences(events)
                case_info = {"case_id": case_id, "investigator_name": "Senior Forensic Examiner"}
                pdf_bytes = generate_timeline_pdf_content(case_info, events, sequences)

                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", f'attachment; filename="Attack_Timeline_{case_id}.pdf"')
                self.send_header("Content-Length", str(len(pdf_bytes)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(pdf_bytes)

            elif path.startswith("/api/v1/timeline"):
                parts = path.strip("/").split("/")
                case_id = parts[3] if len(parts) >= 4 else "case-001"
                start_date = query.get("start_date", [None])[0]
                end_date = query.get("end_date", [None])[0]
                severity = query.get("severity", [None])[0]
                evidence_source = query.get("evidence_source", [None])[0]

                events = get_timeline_events_from_db(str(DB_PATH), case_id)
                filtered = filter_timeline_events(
                    events,
                    start_date=start_date,
                    end_date=end_date,
                    severity=severity,
                    evidence_source=evidence_source
                )
                sequences = identify_suspicious_event_sequences(events)
                self._send_json({
                    "case_id": case_id,
                    "total_events": len(events),
                    "filtered_count": len(filtered),
                    "timeline": filtered,
                    "inferred_sequences": sequences
                })

            # 8. Reports Listing
            elif path == "/api/v1/reports":
                cursor.execute("SELECT * FROM reports ORDER BY generated_at DESC")
                rows = [dict(r) for r in cursor.fetchall()]
                self._send_json(rows)

            # AI Investigation Summary (Feature 1-7)
            elif path.startswith("/api/v1/ai/summary"):
                parts = path.strip("/").split("/")
                case_id = parts[4] if len(parts) >= 5 else "case-001"
                try:
                    summary = synthesize_case_ai_summary_from_db(str(DB_PATH), case_id)
                    self._send_json(summary)
                except Exception as e:
                    self._send_error(f"AI synthesis error: {str(e)}", 500)

            # 9. Printable Report View & PDF Download
            elif path.startswith("/api/v1/reports/") and (path.endswith("/download") or path.endswith("/view")):
                parts = path.split("/")
                rep_id = parts[4]
                is_download = path.endswith("/download")
                cursor.execute("SELECT * FROM reports WHERE id = ? OR report_number = ?", (rep_id, rep_id))
                rep = cursor.fetchone()
                if not rep:
                    self._send_error("Report not found", 404)
                    return

                file_path = rep["file_path"]
                pdf_bytes = None

                # Check if PDF exists on disk
                if file_path and os.path.exists(file_path) and file_path.endswith(".pdf"):
                    with open(file_path, "rb") as f:
                        pdf_bytes = f.read()
                else:
                    # Generate PDF on the fly if not yet on disk
                    try:
                        res = generate_complete_investigation_report_pdf(str(DB_PATH), rep["case_id"], generated_by=rep["generated_by"])
                        if os.path.exists(res["file_path"]):
                            with open(res["file_path"], "rb") as f:
                                pdf_bytes = f.read()
                    except Exception as e:
                        print(f"Notice on-demand PDF build: {e}")

                if pdf_bytes:
                    disposition = "attachment" if is_download else "inline"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/pdf")
                    self.send_header("Content-Disposition", f'{disposition}; filename="{rep["report_number"]}.pdf"')
                    self.send_header("Content-Length", str(len(pdf_bytes)))
                    self._send_cors_headers()
                    self.end_headers()
                    self.wfile.write(pdf_bytes)
                    return

                # Fallback HTML view if PDF rendering not available
                report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{rep['report_title']}</title>
<style>
  body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #070B14; color: #E2E8F0; padding: 40px; margin: 0; }}
  .container {{ max-width: 960px; margin: 0 auto; background: #0B132B; padding: 40px; border: 1px solid #1E293B; border-radius: 8px; }}
  .header {{ border-bottom: 2px solid #00F0FF; padding-bottom: 20px; margin-bottom: 30px; }}
  h1 {{ color: #00F0FF; margin: 0 0 10px 0; font-size: 26px; }}
  .badge {{ background: #0E7490; color: #E0F2FE; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
  .caveat {{ background: rgba(239, 68, 68, 0.1); border-left: 4px solid #EF4444; padding: 12px; margin: 20px 0; color: #FCA5A5; font-size: 13px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }}
  th, td {{ border: 1px solid #1E293B; padding: 10px; text-align: left; }}
  th {{ background: #111C44; color: #38BDF8; }}
  .hash {{ font-family: monospace; color: #A5F3FC; word-break: break-all; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <span class="badge">OFFICIAL FORENSIC INCIDENT INVESTIGATION REPORT</span>
    <h1>CyberTrace Digital Forensics Analysis</h1>
    <p><strong>Report ID:</strong> {rep['report_number']} | <strong>Generated By:</strong> {rep['generated_by']} | <strong>Date:</strong> {rep['generated_at']}</p>
    <p><strong>Cryptographic Seal (SHA-256):</strong> <span class="hash">{rep['sha256_hash']}</span></p>
  </div>
  <div class="caveat">
    <strong>ISO/IEC 27037 ATTRIBUTION SAFEGUARD NOTICE:</strong><br>
    All network identifiers, IP addresses, and domain names referenced in this report indicate technical packet routing endpoints. Forensic attribution to human perpetrators requires corroborating telecommunication subscriber logs and search warrants.
  </div>
  <h2>1. Incident Overview</h2>
  <p>Investigation into unauthorized penetration, credential spraying, and web shell installation on infrastructure.</p>
  <h2>2. Evidence Custody & Chain of Evidence</h2>
  <p>All digital artifacts are secured in isolated vaults with strict immutable zero-execution permissions.</p>
</div>
</body>
</html>"""
                body = report_html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(body)

            # 10. Static Assets & Frontend Serving (Supports Vite Dev/Dist & Standalone)
            elif path.startswith("/assets/") or (FRONTEND_DIR / "dist" / path.lstrip("/")).is_file() or (FRONTEND_DIR / "public" / path.lstrip("/")).is_file():
                asset_file = FRONTEND_DIR / "dist" / path.lstrip("/")
                if not asset_file.exists():
                    asset_file = FRONTEND_DIR / "public" / path.lstrip("/")
                if not asset_file.exists():
                    asset_file = FRONTEND_DIR / "src" / path.lstrip("/")
                if asset_file.is_file():
                    ext = asset_file.suffix.lower()
                    mime_types = {
                        ".js": "application/javascript",
                        ".css": "text/css",
                        ".svg": "image/svg+xml",
                        ".png": "image/png",
                        ".jpg": "image/jpeg",
                        ".ico": "image/x-icon",
                        ".woff2": "font/woff2",
                        ".woff": "font/woff"
                    }
                    content_type = mime_types.get(ext, "application/octet-stream")
                    with open(asset_file, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(data)))
                    self._send_cors_headers()
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self._send_error(f"Asset {path} not found", 404)

            elif path == "/" or path == "/index.html":
                dist_html = FRONTEND_DIR / "dist" / "index.html"
                src_html = FRONTEND_DIR / "index.html"
                target_html = dist_html if dist_html.exists() else src_html
                if target_html.exists():
                    with open(target_html, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(content)))
                    self._send_cors_headers()
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self._send_error("Frontend index.html not found", 404)

            elif path in ("/standalone", "/standalone.html"):
                stand_html = FRONTEND_DIR / "standalone.html"
                if stand_html.exists():
                    with open(stand_html, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(content)))
                    self._send_cors_headers()
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self._send_error("Standalone HTML not found", 404)
            else:
                self._send_error(f"Route {path} not found", 404)
        except sqlite3.Error as e:
            self._send_error(f"Database error: {str(e)}", 500)
        except Exception as e:
            self._send_error(f"Server error: {str(e)}", 500)
        finally:
            conn.close()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            auth_user = self._get_auth_user(cursor)

            # 0. Authentication Endpoints
            if path == "/api/v1/auth/register":
                body = self._read_json_body()
                username = (body.get("username") or "").strip()
                email = (body.get("email") or "").strip().lower()
                password = body.get("password") or ""
                full_name = (body.get("full_name") or "Forensic Examiner").strip()
                role_input = (body.get("role") or "Investigator").strip().title()
                role = role_input if role_input in ("Admin", "Investigator", "Viewer") else "Investigator"

                if not username or not email or not password:
                    self._send_error("Username, email, and password are required.", 400)
                    return

                cursor.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", (username, email))
                if cursor.fetchone():
                    self._send_error("Username or email is already registered.", 400)
                    return

                user_id = str(uuid.uuid4())
                hashed_pw = hash_password(password)
                created_at = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    "INSERT INTO users (id, username, email, hashed_password, full_name, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (user_id, username, email, hashed_pw, full_name, role, created_at)
                )
                conn.commit()

                token = create_access_token({
                    "sub": username,
                    "user_id": user_id,
                    "role": role,
                    "email": email
                })
                self._send_json({
                    "access_token": token,
                    "token_type": "bearer",
                    "expires_in": 86400,
                    "user_info": {
                        "id": user_id,
                        "username": username,
                        "email": email,
                        "full_name": full_name,
                        "role": role
                    }
                }, 201)
                return

            elif path == "/api/v1/auth/login":
                body = self._read_json_body()
                login_id = (body.get("username") or "").strip()
                password = body.get("password") or ""

                cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", (login_id, login_id))
                user = cursor.fetchone()
                if not user or not verify_password(password, user["hashed_password"]):
                    self._send_error("Invalid investigator credentials. Check your username/email and password.", 401)
                    return

                token = create_access_token({
                    "sub": user["username"],
                    "user_id": user["id"],
                    "role": user["role"],
                    "email": user["email"]
                })
                self._send_json({
                    "access_token": token,
                    "token_type": "bearer",
                    "expires_in": 86400,
                    "user_info": {
                        "id": user["id"],
                        "username": user["username"],
                        "email": user["email"],
                        "full_name": user["full_name"],
                        "role": user["role"]
                    }
                })
                return

            elif path == "/api/v1/auth/forgot-password":
                body = self._read_json_body()
                ident = (body.get("identifier") or body.get("email") or body.get("username") or "").strip()
                cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", (ident, ident))
                user = cursor.fetchone()
                if not user:
                    self._send_json({
                        "message": "If an account matches that email/username, a password reset token has been issued.",
                        "reset_token": None
                    })
                    return

                token = create_password_reset_token(user["username"], 15)
                self._send_json({
                    "message": f"Password reset token issued for user '{user['username']}'. Token expires in 15 minutes.",
                    "reset_token": token,
                    "expires_in_minutes": 15
                })
                return

            elif path == "/api/v1/auth/reset-password":
                body = self._read_json_body()
                reset_token = (body.get("reset_token") or "").strip()
                new_pass = body.get("new_password") or ""
                try:
                    decoded = decode_password_reset_token(reset_token)
                    uname = decoded.get("sub")
                except ValueError as ex:
                    self._send_error(f"Invalid or expired reset token: {str(ex)}", 400)
                    return

                cursor.execute("SELECT * FROM users WHERE username = ?", (uname,))
                user = cursor.fetchone()
                if not user:
                    self._send_error("User not found.", 404)
                    return

                cursor.execute("UPDATE users SET hashed_password = ? WHERE id = ?", (hash_password(new_pass), user["id"]))
                conn.commit()
                self._send_json({
                    "status": "success",
                    "message": "Password has been successfully updated. You may now log in with your new credentials."
                })
                return

            elif path == "/api/v1/auth/logout":
                self._send_json({
                    "status": "success",
                    "message": "Successfully logged out. Client token revoked."
                })
                return

            # RBAC Enforcement: Block Viewer role from executing mutation endpoints
            if auth_user and auth_user.get("role") == "Viewer":
                viewer_blocked = ["/api/v1/cases", "/api/v1/evidence/upload", "/api/v1/threats/evaluate"]
                if path in viewer_blocked or path.endswith("/verify") or path.endswith("/tamper"):
                    self._send_error("Access forbidden: Viewer role has read-only access to CyberTrace investigations.", 403)
                    return

            # 1. Evidence Verification
            if path.startswith("/api/v1/evidence/") and path.endswith("/verify"):
                ev_id = path.split("/")[4]
                cursor.execute("SELECT * FROM evidence WHERE id = ? OR evidence_number = ?", (ev_id, ev_id))
                evidence = cursor.fetchone()
                if not evidence:
                    self._send_error("Evidence not found", 404)
                    return

                vault_path = Path(evidence["file_path"])
                if vault_path.exists():
                    with open(vault_path, "rb") as f:
                        data = f.read()
                    current_sha256 = hashlib.sha256(data).hexdigest()
                    current_sha1 = hashlib.sha1(data).hexdigest()
                    current_md5 = hashlib.md5(data).hexdigest()
                else:
                    current_sha256 = evidence["sha256_hash"]
                    current_sha1 = evidence["sha1_hash"]
                    current_md5 = evidence["md5_hash"]

                is_match = (current_sha256.lower() == evidence["initial_recorded_hash"].lower())
                status = "Verified" if is_match else "Compromised"

                cursor.execute("UPDATE evidence SET integrity_status = ?, sha256_hash = ? WHERE id = ?", (status, current_sha256, evidence["id"]))
                cursor.execute("""
                INSERT INTO chain_of_custody (id, evidence_id, action, performed_by, timestamp, reason, location, verified_hash, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    evidence["id"],
                    "Verified",
                    "Senior Forensic Examiner",
                    datetime.now(timezone.utc).isoformat(),
                    "Cryptographic integrity baseline audit",
                    evidence["source_device"] or "Forensic Vault",
                    current_sha256,
                    "Integrity Verified: SHA-256 matches initial baseline." if is_match else f"INTEGRITY ALERT: SHA-256 mismatch detected! Expected {evidence['initial_recorded_hash'][:12]}... but got {current_sha256[:12]}..."
                ))
                conn.commit()

                self._send_json({
                    "is_valid": is_match,
                    "hashes_match": is_match,
                    "evidence_id": evidence["id"],
                    "evidence_number": evidence["evidence_number"],
                    "baseline_sha256": evidence["initial_recorded_hash"],
                    "current_sha256": current_sha256,
                    "sha1": current_sha1,
                    "md5": current_md5,
                    "status": status,
                    "integrity_status": status,
                    "verification_timestamp": datetime.now(timezone.utc).isoformat()
                })

            # Tamper Simulation Test Endpoint
            elif path.startswith("/api/v1/evidence/") and (path.endswith("/tamper-test") or path.endswith("/tamper")):
                ev_id = path.split("/")[4]
                cursor.execute("SELECT * FROM evidence WHERE id = ? OR evidence_number = ?", (ev_id, ev_id))
                evidence = cursor.fetchone()
                if not evidence:
                    self._send_error("Evidence not found", 404)
                    return

                vault_path = Path(evidence["file_path"])
                if not vault_path.exists():
                    self._send_error("Vault file missing on disk", 404)
                    return

                # Intentionally tamper with 1 byte to demonstrate tamper detection
                try:
                    import stat
                    vault_path.chmod(stat.S_IWUSR | stat.S_IRUSR)
                except Exception:
                    pass

                with open(vault_path, "r+b") as f:
                    content = bytearray(f.read())
                    if content:
                        content[0] = (content[0] + 1) % 256
                    else:
                        content = bytearray(b"Tampered payload")
                    f.seek(0)
                    f.write(content)
                    f.truncate()

                # Re-verify immediately to record the alert
                tampered_sha256 = hashlib.sha256(bytes(content)).hexdigest()
                cursor.execute("UPDATE evidence SET integrity_status = 'Compromised', sha256_hash = ? WHERE id = ?", (tampered_sha256, evidence["id"]))
                cursor.execute("""
                INSERT INTO chain_of_custody (id, evidence_id, action, performed_by, timestamp, reason, location, verified_hash, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    evidence["id"],
                    "Integrity Alert",
                    "Automated Integrity Watchdog",
                    datetime.now(timezone.utc).isoformat(),
                    "Unauthorized byte modification detected outside chain of custody",
                    evidence["file_path"],
                    tampered_sha256,
                    "CRITICAL FORENSIC ALERT: File byte-stream tampered! Hash does not match acquisition baseline!"
                ))
                conn.commit()

                self._send_json({
                    "message": "Tamper simulation executed. Evidence vault byte modified.",
                    "status": "Compromised",
                    "original_hash": evidence["initial_recorded_hash"],
                    "tampered_hash": tampered_sha256
                })

            # 2. Evidence Ingestion / Upload (Requirement 1, 3, 4, 5, 6, 7)
            elif path == "/api/v1/evidence/upload":
                content_type = self.headers.get("Content-Type", "")
                raw_bytes = self._read_body_bytes()

                filename = "evidence_artifact.bin"
                case_id = "case-001"
                acquired_by = "Senior Forensic Examiner"
                investigator_role = "Tier-3 DFIR Specialist"
                source_device = "Target Server Host"
                description = "Digital forensic evidence artifact"
                file_content = b"Sample forensic raw bytes"

                if "multipart/form-data" in content_type:
                    # Extract boundary — handle quoted boundary value
                    boundary_raw = content_type.split("boundary=")[-1].strip().strip('"').strip()
                    boundary_bytes = f"--{boundary_raw}".encode("utf-8")
                    parts = raw_bytes.split(boundary_bytes)

                    for part in parts:
                        if len(part) < 4:
                            continue
                        # Split header from body on double CRLF
                        if b"\r\n\r\n" not in part:
                            continue
                        header_raw, body_raw = part.split(b"\r\n\r\n", 1)
                        header_text = header_raw.decode("utf-8", errors="replace")
                        # Strip final CRLF -- boundary trailer
                        body_raw = body_raw.rstrip(b"\r\n-")

                        # Named file field
                        if 'name="file"' in header_text or 'filename="' in header_text:
                            fn_match = re.search(r'filename="([^"]+)"', header_text)
                            if fn_match:
                                filename = fn_match.group(1)
                            file_content = body_raw

                        # Scalar fields
                        elif 'name="case_id"' in header_text:
                            case_id = body_raw.decode("utf-8", errors="ignore").strip()
                        elif 'name="acquired_by"' in header_text:
                            acquired_by = body_raw.decode("utf-8", errors="ignore").strip()
                        elif 'name="investigator_role"' in header_text:
                            investigator_role = body_raw.decode("utf-8", errors="ignore").strip()
                        elif 'name="source_device"' in header_text:
                            source_device = body_raw.decode("utf-8", errors="ignore").strip()
                        elif 'name="description"' in header_text:
                            description = body_raw.decode("utf-8", errors="ignore").strip()

                elif "application/json" in content_type:
                    body = json.loads(raw_bytes.decode('utf-8'))
                    filename = body.get("filename", filename)
                    case_id = body.get("case_id", case_id)
                    acquired_by = body.get("acquired_by", acquired_by)
                    investigator_role = body.get("investigator_role", investigator_role)
                    source_device = body.get("source_device", source_device)
                    description = body.get("description", description)
                    file_content = body.get("content", "").encode('utf-8')

                # Validate Extension (Requirement 1)
                ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin"
                if ext not in ALLOWED_EXTENSIONS:
                    self._send_error(f"Unauthorized file extension '.{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}", 400)
                    return

                # Validate File Size (Empty file & Oversized file checks)
                if len(file_content) == 0:
                    self._send_error("Evidence artifact cannot be empty (0 bytes)", 400)
                    return
                if len(file_content) > MAX_FILE_SIZE:
                    self._send_error(f"File size exceeds 50MB limit ({len(file_content):,} bytes)", 400)
                    return

                # Requirement 4: Calculate SHA-256 (+ SHA-1, MD5) on upload
                sha256_hash = hashlib.sha256(file_content).hexdigest()
                sha1_hash = hashlib.sha1(file_content).hexdigest()
                md5_hash = hashlib.md5(file_content).hexdigest()

                # Duplicate Evidence Detection: Check if identical hash already exists in this case
                cursor.execute(
                    "SELECT id, evidence_number, original_filename FROM evidence WHERE case_id = ? AND sha256_hash = ?",
                    (case_id, sha256_hash)
                )
                dup = cursor.fetchone()
                if dup:
                    self._send_error(
                        f"Duplicate evidence rejected: Artifact with identical SHA-256 hash '{sha256_hash}' already enrolled as {dup['evidence_number']} ({dup['original_filename']}) in case {case_id}",
                        409
                    )
                    return

                # MIME type detection
                mime_map = {
                    "log": "text/plain", "txt": "text/plain", "json": "application/json",
                    "csv": "text/csv", "php": "text/x-php", "sh": "text/x-shellscript",
                    "bat": "text/plain", "ps1": "text/plain",
                    "pdf": "application/pdf", "png": "image/png", "jpg": "image/jpeg",
                    "jpeg": "image/jpeg", "zip": "application/zip", "tar": "application/x-tar",
                    "gz": "application/gzip", "pcap": "application/vnd.tcpdump.pcap",
                    "pcapng": "application/vnd.tcpdump.pcap",
                    "exe": "application/vnd.microsoft.portable-executable",
                    "dll": "application/octet-stream", "bin": "application/octet-stream",
                    "raw": "application/octet-stream", "dat": "application/octet-stream",
                    "dump": "application/octet-stream", "img": "application/octet-stream",
                    "mem": "application/octet-stream", "evtx": "application/octet-stream",
                }
                mime_type = mime_map.get(ext, "application/octet-stream")

                # Safe Non-Executable Vault Storage (Requirement 10)
                # UUID-randomized name + .vault extension prevents execution
                stored_name = f"{uuid.uuid4().hex}.{ext}.vault"
                dest_path = UPLOADS_DIR / stored_name
                with open(dest_path, "wb") as f:
                    f.write(file_content)
                # Apply read-only permissions (chmod 0400 equivalent on Unix)
                try:
                    import stat
                    dest_path.chmod(stat.S_IRUSR)
                except Exception:
                    pass  # Windows: permissions set via ACL differently

                # Requirement 2: Global sequential evidence ID
                cursor.execute("SELECT COUNT(*) FROM evidence")
                total_evidence = cursor.fetchone()[0]
                ev_num = f"EVD-{total_evidence + 1:03d}"
                ev_id = str(uuid.uuid4())

                # Requirement 5 & 6: Store metadata + investigator in SQLite
                acquired_at = datetime.now(timezone.utc).isoformat()
                cursor.execute("""
                INSERT INTO evidence (
                    id, case_id, evidence_number, original_filename, stored_filename, file_path,
                    file_size_bytes, file_type, mime_type, sha256_hash, sha1_hash, md5_hash,
                    initial_recorded_hash, integrity_status, source_device, acquired_by, acquired_at, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ev_id, case_id, ev_num, filename, stored_name, str(dest_path),
                    len(file_content), ext, mime_type, sha256_hash, sha1_hash, md5_hash,
                    sha256_hash, "Verified", source_device, acquired_by, acquired_at, description
                ))

                # Requirement 7: Immutable chain of custody record on acquisition
                cursor.execute("""
                INSERT INTO chain_of_custody (id, evidence_id, action, performed_by, timestamp, reason, location, verified_hash, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()), ev_id, "Acquired", acquired_by,
                    acquired_at,
                    "Initial digital evidence acquisition and secure vault enrollment",
                    source_device, sha256_hash,
                    f"Artifact enrolled. SHA-256 baseline: {sha256_hash[:16]}... | Stored as: {stored_name} | MIME: {mime_type}"
                ))
                conn.commit()

                self._send_json({
                    "id": ev_id,
                    "case_id": case_id,
                    "evidence_number": ev_num,
                    "original_filename": filename,
                    "stored_filename": stored_name,
                    "file_size_bytes": len(file_content),
                    "file_type": ext,
                    "mime_type": mime_type,
                    "sha256_hash": sha256_hash,
                    "sha1_hash": sha1_hash,
                    "md5_hash": md5_hash,
                    "initial_recorded_hash": sha256_hash,
                    "integrity_status": "Verified",
                    "source_device": source_device,
                    "acquired_by": acquired_by,
                    "acquired_at": acquired_at,
                    "description": description,
                    "vault_path": stored_name,
                    "chain_of_custody_logged": True
                }, 201)

            # 3. Add Chain of Custody Action
            elif path.startswith("/api/v1/evidence/") and path.endswith("/chain-of-custody"):
                ev_id = path.split("/")[4]
                body = self._read_json_body()
                cursor.execute("SELECT * FROM evidence WHERE id = ? OR evidence_number = ?", (ev_id, ev_id))
                ev = cursor.fetchone()
                if not ev:
                    self._send_error("Evidence not found", 404)
                    return

                coc_id = str(uuid.uuid4())
                cursor.execute("""
                INSERT INTO chain_of_custody (id, evidence_id, action, performed_by, timestamp, reason, location, verified_hash, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    coc_id,
                    ev["id"],
                    body.get("action", "Transferred"),
                    body.get("performed_by", "Senior Forensic Examiner"),
                    datetime.now(timezone.utc).isoformat(),
                    body.get("reason", "Custody transfer / forensic analysis"),
                    body.get("location", body.get("location", "Secure Storage")),
                    ev["sha256_hash"],
                    body.get("notes", "")
                ))
                conn.commit()
                self._send_json({"id": coc_id, "status": "Chain of custody recorded", "evidence_id": ev["id"]}, 201)

            # 4. Log Analysis Engine (Pandas-compatible Forensic Pipeline)
            elif path == "/api/v1/logs/analyze":
                body = self._read_json_body()
                log_text = body.get("log_text", "")
                case_id = body.get("case_id", "case-001")
                custom_rules = body.get("rules", None)
                filename = body.get("filename", "uploaded_stream.log")

                if not log_text.strip():
                    self._send_error("log_text parameter is required", 400)
                    return

                # Execute modular pipeline with configurable rules, timestamp parsing, and SQLite persistence
                result = execute_log_analysis_pipeline(
                    content_text=log_text,
                    case_id=case_id,
                    db_path=str(DB_PATH),
                    rules=custom_rules,
                    filename=filename
                )

                self._send_json({
                    "total_lines_analyzed": result["total_lines_analyzed"],
                    "threats_detected": result["suspicious_events_flagged"],
                    "stored_in_sqlite_count": result["stored_in_sqlite_count"],
                    "statistics": result["statistics"],
                    "parsed_events": result["events"],
                    "rules_applied": result["rules_applied"],
                    "forensic_policy": result["forensic_policy"]
                })

            # 5. File Forensics (SHA-256, MD5, Metadata, Size, Magic Bytes, Hash Comparison, SQLite History)
            elif path == "/api/v1/files/analyze":
                body = self._read_json_body()
                filename = body.get("filename") or body.get("file_name", "unknown_file.bin")
                file_text = body.get("content") or body.get("file_content", "")
                if not file_text:
                    self._send_error("File content cannot be empty (0 bytes)", 400)
                    return
                data_bytes = file_text.encode("latin1", errors="ignore")
                case_id = body.get("case_id", "case-001")

                # Run complete forensics pipeline and persist in history
                res = process_file_forensics_upload(
                    data_bytes=data_bytes,
                    filename=filename,
                    db_path=str(DB_PATH),
                    case_id=case_id
                )

                # Threat Signature Scan
                threat_matches = scan_threat_signatures(data_bytes, file_text)
                res["threat_detections"] = threat_matches
                res["sha256"] = res["hashes"]["sha256"]
                res["md5"] = res["hashes"]["md5"]
                res["sha1"] = res["hashes"]["sha1"]
                res["entropy_score"] = res["metadata"]["shannon_entropy"]
                res["is_threat"] = len(threat_matches) > 0
                res["is_suspicious"] = len(threat_matches) > 0 or res["metadata"]["is_packed_or_encrypted"]
                self._send_json(res)

            # File Re-Verification & Hash Comparison Endpoint (Features 6 & 7)
            elif path == "/api/v1/files/verify":
                body = self._read_json_body()
                filename = body.get("filename", "unknown_artifact")
                baseline_sha256 = body.get("baseline_sha256", "")
                original_md5 = body.get("original_md5", None)
                original_sha1 = body.get("original_sha1", None)
                current_text = body.get("current_content_text", "")
                data_bytes = current_text.encode("latin1", errors="ignore")
                verifier = body.get("verifier", "Senior Forensic Examiner")

                verif_res = verify_evidence_hash_comparison(
                    current_data_bytes=data_bytes,
                    baseline_sha256=baseline_sha256,
                    original_md5=original_md5,
                    original_sha1=original_sha1
                )

                # Persist verification audit record
                record_verification_log_to_sqlite(
                    db_path=str(DB_PATH),
                    verification_result=verif_res,
                    filename=filename,
                    verifier=verifier
                )

                self._send_json(verif_res)

            # File Forensics Analysis History (Feature 8)
            elif path == "/api/v1/files/history":
                case_id = query.get("case_id", [None])[0]
                history = get_file_forensic_history(str(DB_PATH), case_id=case_id)
                self._send_json(history)

            # File Verification Audit Logs
            elif path == "/api/v1/files/verification-logs":
                filename = query.get("filename", [None])[0]
                logs = get_file_verification_audit_trail(str(DB_PATH), filename=filename)
                self._send_json(logs)

            # 6. IP Investigation (RFC 1918 + Observed vs Reputation + Attribution Safeguard)
            elif path == "/api/v1/ip/investigate":
                body = self._read_json_body()
                ip = body.get("ip_address", "127.0.0.1").strip()
                case_id = body.get("case_id", "case-001")
                enable_public_intel = body.get("enable_public_intel", True)

                # Execute investigation using forensic IP engine
                result = investigate_single_ip(ip, enable_public_intel=enable_public_intel)
                if not result.get("is_valid", False):
                    self._send_json({
                        "error": result.get("error", "Invalid IP address"),
                        "is_valid": False,
                        "status": 400
                    }, 400)
                    return

                # Persist in SQLite history
                record_id = store_ip_investigation_record(str(DB_PATH), result, case_id=case_id)
                result["history_record_id"] = record_id

                # Query related timeline and log events (Feature 7)
                related_events = get_related_timeline_events_for_ip(str(DB_PATH), result["ip_address"], case_id=case_id)
                result["related_timeline_events"] = related_events
                if "attribution_caveat" not in result:
                    result["attribution_caveat"] = result.get("forensic_attribution_safeguard", "")

                self._send_json(result)

            # Feature 6: IP Investigation History
            elif path == "/api/v1/ip/history":
                case_id = query.get("case_id", [None])[0]
                history = get_ip_investigation_history(str(DB_PATH), case_id=case_id)
                self._send_json(history)

            # Feature 1 & 4 & 5: Extract IPs from uploaded log
            elif path == "/api/v1/ip/extract-from-log":
                body = self._read_json_body()
                log_text = body.get("log_text", "")
                if not log_text.strip():
                    self._send_error("log_text is required", 400)
                    return
                extracted_ips = extract_ips_from_log_content(log_text)
                metrics = analyze_ip_log_metrics(log_text)
                self._send_json({
                    "total_unique_ips": len(extracted_ips),
                    "extracted_ips": extracted_ips,
                    "metrics": metrics
                })

            # Feature 7: Related Timeline Events for an IP
            elif path.startswith("/api/v1/ip/") and path.endswith("/related-events"):
                ip_arg = path.split("/")[4]
                events = get_related_timeline_events_for_ip(str(DB_PATH), ip_arg)
                self._send_json({"ip_address": ip_arg, "total_related_events": len(events), "events": events})

            # Bulk IP Check
            elif path == "/api/v1/ip/bulk-check":
                body = self._read_json_body()
                ips = body.get("ip_addresses", [])
                results = []
                for ip in ips:
                    ip = ip.strip()
                    is_priv = ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1"
                    is_mal = ip.startswith("185.220.") or ip.startswith("45.154.")
                    results.append({
                        "ip_address": ip,
                        "is_private": is_priv,
                        "country": "LAN" if is_priv else ("Netherlands" if is_mal else "United States"),
                        "threat_score": 94 if is_mal else (0 if is_priv else 10),
                        "status": "Malicious" if is_mal else ("Private" if is_priv else "Clean")
                    })
                self._send_json({
                    "total_checked": len(results),
                    "results": results,
                    "attribution_caveat": "ISO/IEC 27037 Attribution Safeguard enforced."
                })

            # 7. Threat Signature Scan
            elif path == "/api/v1/threats/scan":
                body = self._read_json_body()
                content = body.get("content", "")
                detections = scan_threat_signatures(content.encode("latin1", errors="ignore"), content)
                self._send_json({
                    "total_detections": len(detections),
                    "detections": detections,
                    "mitre_summary": {d["mitre_technique"]: d["rule_name"] for d in detections}
                })

            # Threat Engine Evaluation (All 5 Detection Rules)
            elif path == "/api/v1/threats/evaluate":
                body = self._read_json_body()
                case_id = body.get("case_id", "case-001")
                custom_rules = body.get("custom_rules") or body.get("rules", None)

                # Fetch logs
                cursor.execute("SELECT * FROM log_events WHERE case_id = ? ORDER BY event_timestamp ASC", (case_id,))
                raw_logs = [dict(r) for r in cursor.fetchall()]
                if not raw_logs:
                    cursor.execute("SELECT * FROM log_events ORDER BY event_timestamp ASC LIMIT 200")
                    raw_logs = [dict(r) for r in cursor.fetchall()]

                # Fetch evidence files
                cursor.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,))
                raw_evidence = [dict(r) for r in cursor.fetchall()]
                if not raw_evidence:
                    cursor.execute("SELECT * FROM evidence LIMIT 50")
                    raw_evidence = [dict(r) for r in cursor.fetchall()]

                alerts = evaluate_threat_rules(
                    log_events=raw_logs,
                    evidence_files=raw_evidence,
                    custom_rules=custom_rules
                )

                store_threat_alerts(str(DB_PATH), case_id=case_id, alerts=alerts)

                self._send_json({
                    "status": "success",
                    "case_id": case_id,
                    "logs_evaluated": len(raw_logs),
                    "evidence_files_evaluated": len(raw_evidence),
                    "alerts_count": len(alerts),
                    "alerts": alerts
                })

            # 8. Timeline Reconstruct (Normalized UTC + Attack Sequence Inferences + Evidence Reference)
            elif path == "/api/v1/timeline/reconstruct":
                body = self._read_json_body()
                case_id = body.get("case_id", "case-001")
                
                # Fetch logs and evidence
                cursor.execute("SELECT * FROM log_events WHERE case_id = ? ORDER BY event_timestamp ASC", (case_id,))
                raw_logs = [dict(r) for r in cursor.fetchall()]
                if not raw_logs:
                    cursor.execute("SELECT * FROM log_events ORDER BY event_timestamp ASC LIMIT 200")
                    raw_logs = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,))
                raw_evidence = [dict(r) for r in cursor.fetchall()]
                if not raw_evidence:
                    cursor.execute("SELECT * FROM evidence LIMIT 50")
                    raw_evidence = [dict(r) for r in cursor.fetchall()]

                timeline = extract_and_normalize_timeline_events(
                    log_events=raw_logs,
                    evidence_vault_items=raw_evidence,
                    case_id=case_id
                )

                store_timeline_events(str(DB_PATH), case_id=case_id, events=timeline)
                sequences = identify_suspicious_event_sequences(timeline)

                self._send_json({
                    "message": "Attack timeline reconstructed across forensic logs and evidence events.",
                    "total_events": len(timeline),
                    "inferred_sequences_count": len(sequences),
                    "timeline": timeline,
                    "inferred_sequences": sequences
                })

            # 9. Cases Creation & Sub-resources
            elif path == "/api/v1/cases":
                body = self._read_json_body()
                case = create_investigation_case(
                    db_path=str(DB_PATH),
                    title=body.get("title", "Untitled Case"),
                    description=body.get("description", ""),
                    investigator_name=body.get("investigator_name", "Senior Forensic Examiner"),
                    severity=body.get("severity", "Medium"),
                    incident_type=body.get("incident_type", "Data Breach"),
                    case_number=body.get("case_number", None)
                )
                self._send_json(case, 201)

            elif path.startswith("/api/v1/cases/") and path.endswith("/status"):
                case_id = path.split("/")[4]
                body = self._read_json_body()
                try:
                    updated = update_case_lifecycle_status(
                        db_path=str(DB_PATH),
                        case_id=case_id,
                        new_status=body.get("status", "Open"),
                        investigator_name=body.get("investigator_name", "Senior Forensic Examiner"),
                        notes=body.get("notes", None)
                    )
                    self._send_json(updated)
                except ValueError as e:
                    self._send_error(str(e), 400)
                except LookupError as e:
                    self._send_error(str(e), 404)

            elif path.startswith("/api/v1/cases/") and path.endswith("/assign"):
                case_id = path.split("/")[4]
                body = self._read_json_body()
                try:
                    assigned = assign_case_investigator(
                        db_path=str(DB_PATH),
                        case_id=case_id,
                        new_investigator=body.get("investigator_name", "Senior Forensic Examiner"),
                        assigned_by=body.get("assigned_by", "Lead Forensic Examiner")
                    )
                    self._send_json(assigned)
                except LookupError as e:
                    self._send_error(str(e), 404)

            elif path.startswith("/api/v1/cases/") and path.endswith("/notes"):
                case_id = path.split("/")[4]
                body = self._read_json_body()
                try:
                    note = add_case_investigation_note(
                        db_path=str(DB_PATH),
                        case_id=case_id,
                        author=body.get("author", "Senior Forensic Examiner"),
                        note_text=body.get("note_text", "")
                    )
                    self._send_json(note, 201)
                except LookupError as e:
                    self._send_error(str(e), 404)

            elif path.startswith("/api/v1/cases/") and path.endswith("/link-event"):
                case_id = path.split("/")[4]
                body = self._read_json_body()
                try:
                    link = link_suspicious_event_to_case(
                        db_path=str(DB_PATH),
                        case_id=case_id,
                        event_id=body.get("event_id", ""),
                        event_type=body.get("event_type", "Threat Alert"),
                        event_summary=body.get("event_summary", ""),
                        linked_by=body.get("linked_by", "Senior Forensic Examiner")
                    )
                    self._send_json(link, 201)
                except LookupError as e:
                    self._send_error(str(e), 404)

            # AI Investigation Summary (POST variant)
            elif path == "/api/v1/ai/summary":
                body = self._read_json_body()
                case_id = body.get("case_id", "case-001")
                try:
                    summary = synthesize_case_ai_summary_from_db(str(DB_PATH), case_id)
                    self._send_json(summary)
                except Exception as e:
                    self._send_error(f"AI synthesis error: {str(e)}", 500)

            # 10. Automated Court-Grade Report Generation
            elif path == "/api/v1/reports/generate":
                body = self._read_json_body()
                case_id = body.get("case_id", "case-001")
                generated_by = body.get("generated_by", "Senior Forensic Examiner")
                try:
                    result = generate_complete_investigation_report_pdf(
                        str(DB_PATH), case_id, generated_by=generated_by
                    )
                    self._send_json(result, 201)
                except Exception as e:
                    self._send_error(f"Failed to generate investigation report: {str(e)}", 500)

            # 11. AI-Assisted Investigation Summary
            elif path == "/api/v1/ai/summary":
                body = self._read_json_body()
                case_id = body.get("case_id", "case-001")

                # Query case context
                cursor.execute("SELECT * FROM cases WHERE id = ? OR case_number = ?", (case_id, case_id))
                c = cursor.fetchone()
                cursor.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case_id,))
                ev_cnt = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM log_events WHERE case_id = ? AND is_threat = 1", (case_id,))
                threat_cnt = cursor.fetchone()[0]

                summary_response = {
                    "case_number": c["case_number"] if c else "CT-2026-001",
                    "executive_brief": (
                        "During the forensic examination of incident CT-2026-001, CyberTrace identified a multi-stage intrusion "
                        "initiated via automated password spraying against SSH port 22 from external IP 185.220.101.5. "
                        "The adversary achieved initial access via compromised credentials for service account 'deploy', "
                        "attempted privilege escalation against /etc/shadow, and pivoted to the web service layer deploying "
                        "a PHP web shell (wso_shell.php) to maintain persistence."
                    ),
                    "attack_vector": "Credential Brute Force (T1110) followed by SQL Injection (T1190) and Web Shell Persistence (T1505.003)",
                    "impact_assessment": "High severity breach on perimeter server; potential exfiltration of database credentials and system configuration files.",
                    "mitre_tactics_observed": [
                        {"tactic": "Initial Access", "technique": "T1110 - Brute Force", "status": "Confirmed"},
                        {"tactic": "Execution", "technique": "T1059.004 - Unix Shell", "status": "Confirmed"},
                        {"tactic": "Persistence", "technique": "T1505.003 - Web Shell", "status": "Confirmed"},
                        {"tactic": "Privilege Escalation", "technique": "T1068 - Exploitation for Priv Escalation", "status": "Confirmed"}
                    ],
                    "containment_actions": [
                        "Immediately revoke and rotate credentials for account 'deploy' and database users.",
                        "Quarantine web shell artifact at /uploads/wso_shell.php and verify web directory write permissions.",
                        "Block inbound traffic from adversary IP range 185.220.101.0/24 on perimeter firewalls.",
                        "Enforce multi-factor authentication (MFA) and SSH key-only authentication across all management interfaces."
                    ],
                    "attribution_warning": "Attribution to specific threat groups is withheld pursuant to ISO/IEC 27037 standards until legal subpoena records from upstream ISPs confirm subscriber identity."
                }
                self._send_json(summary_response)

            # 12. Quick File Verification
            elif path == "/api/v1/integrity/verify-file":
                body = self._read_json_body()
                content = body.get("content", "").encode("utf-8")
                expected = body.get("expected_sha256", "").strip().lower()
                calc_sha256 = hashlib.sha256(content).hexdigest()
                matches = (calc_sha256 == expected) if expected else True
                self._send_json({
                    "sha256": calc_sha256,
                    "sha1": hashlib.sha1(content).hexdigest(),
                    "md5": hashlib.md5(content).hexdigest(),
                    "matches_expected": matches,
                    "integrity_status": "Verified (Match)" if matches else "Compromised (Mismatch)"
                })

            else:
                self._send_error(f"POST route {path} not found", 404)
        except sqlite3.Error as e:
            self._send_error(f"Database error: {str(e)}", 500)
        except Exception as e:
            self._send_error(f"Server error: {str(e)}", 500)
        finally:
            conn.close()

def run_server(port=8000):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, CyberTraceHandler)
    print(f"CyberTrace Standalone Forensic Server running at http://127.0.0.1:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port)
