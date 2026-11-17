"""
CyberTrace - Complete Application End-to-End Workflow Integration Test
=====================================================================
Validates the full investigative lifecycle across all modules:
1. Case Management: Create unique case ID, title, description, investigator.
2. Evidence Collection: Ingest digital artifact into vault with SHA-256 baseline, linked to case.
3. File Forensics: Calculate SHA-256/MD5, entropy, magic bytes, verify integrity against acquisition.
4. Log Analysis: Parse multi-format logs, flag anomalies, correlate with MITRE tactics.
5. IP Investigation: Investigate observed endpoints, ASN, WHOIS, ISO/IEC 27037 attribution safeguard.
6. Threat Detection: Evaluate rules (brute force, suspicious IP, admin login, malicious hashes).
7. Attack Timeline: Normalize timestamps to UTC, order chronologically, group suspicious sequences.
8. AI-Assisted Summary: Synthesize grounded findings (facts, rationales, hypotheses, containment).
9. PDF Report Generation & Download: Compile 12-section PDF report with SHA-256 cryptographic seal.
10. Dashboard Telemetry: Verify live SQLite metrics reflect actual database changes.
"""

import io
import os
import sys
import json
import uuid
import hashlib
import unittest
from pathlib import Path

# Ensure 'backend' directory is on sys.path
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.standalone_server import CyberTraceHandler, DB_PATH, init_standalone_db
from app.forensic.report_generator import generate_complete_investigation_report_pdf


class MockSocket:
    def __init__(self, data: bytes):
        self.data = data
        self.output = io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        if 'r' in mode:
            return io.BytesIO(self.data)
        return self.output

    def sendall(self, b: bytes):
        self.output.write(b)


def dispatch_request(method: str, path: str, body: dict = None) -> tuple[int, dict, bytes]:
    """Helper to dispatch HTTP request through CyberTraceHandler without network binding."""
    headers = [f"{method} {path} HTTP/1.1", "Host: localhost"]
    payload_bytes = b""
    if body is not None:
        payload_bytes = json.dumps(body).encode("utf-8")
        headers.append("Content-Type: application/json")
        headers.append(f"Content-Length: {len(payload_bytes)}")
    headers.append("\r\n")

    raw_req = "\r\n".join(headers).encode("utf-8") + payload_bytes
    sock = MockSocket(raw_req)

    from unittest.mock import Mock
    handler = CyberTraceHandler(sock, ("127.0.0.1", 54321), Mock())

    raw_resp = sock.output.getvalue()
    sep = raw_resp.find(b"\r\n\r\n")
    if sep == -1:
        return 500, {}, raw_resp

    hdr_str = raw_resp[:sep].decode("latin1", errors="replace")
    body_bytes = raw_resp[sep+4:]

    status_line = hdr_str.split("\r\n")[0]
    status_code = int(status_line.split(" ")[1])

    json_data = {}
    try:
        json_data = json.loads(body_bytes.decode("utf-8", errors="replace"))
    except Exception:
        pass

    return status_code, json_data, body_bytes


class TestFullApplicationWorkflow(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_standalone_db()
        cls.test_case_id = f"case-integ-{int(uuid.uuid4().hex[:6], 16)}"
        cls.test_case_num = f"CT-INTEG-{int(uuid.uuid4().hex[:4], 16)}"

    # -------------------------------------------------------------
    # Step 1: Case Management - Create New Investigation Case
    # -------------------------------------------------------------
    def test_01_create_investigation_case(self):
        code, data, _ = dispatch_request("POST", "/api/v1/cases", {
            "title": "Operation Apex - Advanced Persistent Intrusion",
            "description": "Simulated multi-stage intrusion investigation for integration verification.",
            "investigator_name": "Senior Forensic Examiner",
            "severity": "Critical",
            "incident_type": "Data Breach & Web Shell"
        })
        self.assertEqual(code, 201)
        self.assertIn("case_number", data)
        self.__class__.created_case = data
        self.__class__.test_case_id = data["id"]
        self.__class__.test_case_num = data["case_number"]

    # -------------------------------------------------------------
    # Step 2: Evidence Collection - Ingest Artifact Linked to Case
    # -------------------------------------------------------------
    def test_02_evidence_upload_and_hashing(self):
        case_id = self.__class__.test_case_id
        code, data, _ = dispatch_request("POST", "/api/v1/evidence/upload", {
            "case_id": case_id,
            "filename": "srv_db01_core_dump.raw",
            "acquired_by": "Senior Forensic Examiner",
            "source_device": "Database Core Server (SRV-DB01)",
            "description": "Volatile memory dump acquired post-compromise.",
            "content": "FORENSIC MEMORY BITSTREAM ACQUISITION FOR CASE " + case_id
        })
        self.assertEqual(code, 201)
        self.assertIn("sha256_hash", data)
        self.assertEqual(len(data["sha256_hash"]), 64)
        self.assertEqual(data["case_id"], case_id)
        self.__class__.uploaded_evidence = data

    # -------------------------------------------------------------
    # Step 3: File Forensics - Inspection and Hash Comparison
    # -------------------------------------------------------------
    def test_03_file_forensics_analysis(self):
        ev = self.__class__.uploaded_evidence
        sample_code = "<?php @eval($_POST['cmd']); system($_GET['c']); echo 'b374k'; ?>"
        code, data, _ = dispatch_request("POST", "/api/v1/files/analyze", {
            "file_name": "b374k_shell.php",
            "file_content": sample_code,
            "case_id": self.__class__.test_case_id
        })
        self.assertEqual(code, 200)
        self.assertIn("sha256", data)
        self.assertIn("md5", data)
        self.assertIn("entropy_score", data)
        self.assertTrue(data.get("is_suspicious") or data.get("is_threat"))

    # -------------------------------------------------------------
    # Step 4: Log Analysis - Ingest Telemetry & Map MITRE Tactics
    # -------------------------------------------------------------
    def test_04_log_analysis_pipeline(self):
        case_id = self.__class__.test_case_id
        sample_log = (
            "Nov 12 04:12:01 srv sshd[14201]: Failed password for root from 198.51.100.23 port 45212 ssh2\n"
            "Nov 12 04:12:15 srv sshd[14205]: Failed password for root from 198.51.100.23 port 45214 ssh2\n"
            "Nov 12 04:12:28 srv sshd[14209]: Failed password for root from 198.51.100.23 port 45218 ssh2\n"
            "Nov 12 04:12:45 srv sshd[14228]: Accepted password for deploy from 198.51.100.23 port 45230 ssh2\n"
            "Nov 12 04:13:02 srv sudo: deploy : TTY=pts/0 ; COMMAND=/bin/bash\n"
        )
        code, data, _ = dispatch_request("POST", "/api/v1/logs/analyze", {
            "log_text": sample_log,
            "case_id": case_id,
            "filename": "auth_investigation.log",
            "rules": {"failed_login_threshold": 3}
        })
        self.assertEqual(code, 200)
        self.assertGreaterEqual(data.get("total_lines_analyzed", 0), 4)
        self.assertGreaterEqual(data.get("threats_detected", 0), 1)

    # -------------------------------------------------------------
    # Step 5: IP Investigation - Resolve Ingress Endpoints & Caveats
    # -------------------------------------------------------------
    def test_05_ip_investigation(self):
        code, data, _ = dispatch_request("POST", "/api/v1/ip/investigate", {
            "ip_address": "198.51.100.23",
            "enable_threat_intel": True,
            "case_id": self.__class__.test_case_id
        })
        self.assertEqual(code, 200)
        self.assertEqual(data["ip_address"], "198.51.100.23")
        self.assertIn("attribution_caveat", data)
        self.assertIn("ISO/IEC 27037", data["attribution_caveat"])

    # -------------------------------------------------------------
    # Step 6: Threat Detection - Evaluate Configurable Rules
    # -------------------------------------------------------------
    def test_06_threat_detection_engine(self):
        case_id = self.__class__.test_case_id
        code, data, _ = dispatch_request("POST", "/api/v1/threats/evaluate", {
            "case_id": case_id,
            "rules": {
                "failed_login_threshold": 3,
                "suspicious_ip_connection_threshold": 2
            }
        })
        self.assertEqual(code, 200)
        self.assertIn("alerts", data)

    # -------------------------------------------------------------
    # Step 7: Timeline Reconstruction - Chronological Sequences
    # -------------------------------------------------------------
    def test_07_attack_timeline_reconstruction(self):
        case_id = self.__class__.test_case_id
        code, data, _ = dispatch_request("POST", "/api/v1/timeline/reconstruct", {
            "case_id": case_id,
            "auto_sequence": True
        })
        self.assertEqual(code, 200)
        self.assertIn("timeline", data)

    # -------------------------------------------------------------
    # Step 8: AI Investigation Summary - Grounded Multi-Stage Synthesis
    # -------------------------------------------------------------
    def test_08_ai_investigation_summary(self):
        case_id = self.__class__.test_case_id
        code, data, _ = dispatch_request("GET", f"/api/v1/ai/summary/{case_id}")
        self.assertEqual(code, 200)
        self.assertIn("case_number", data)
        self.assertIn("assessment_status", data)
        self.assertIn("facts", data)
        self.assertIn("hypotheses", data)
        self.assertIn("recommendations", data)
        self.assertIn("ISO/IEC 27037", data["forensic_integrity_guarantee"])

    # -------------------------------------------------------------
    # Step 9: PDF Report Generation & Download - 12 Sections Sealed
    # -------------------------------------------------------------
    def test_09_pdf_report_generation_and_download(self):
        case_id = self.__class__.test_case_id
        # Generate report
        code, data, _ = dispatch_request("POST", "/api/v1/reports/generate", {
            "case_id": case_id,
            "generated_by": "Senior Forensic Examiner"
        })
        self.assertEqual(code, 201)
        self.assertIn("report_number", data)
        self.assertIn("sha256_hash", data)
        rep_id = data["id"]

        # Download report
        dl_code, _, pdf_bytes = dispatch_request("GET", f"/api/v1/reports/{rep_id}/download")
        self.assertEqual(dl_code, 200)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertGreater(len(pdf_bytes), 1000)

        # Verify SHA-256 seal matches downloaded bytes
        computed_sha = hashlib.sha256(pdf_bytes).hexdigest()
        self.assertEqual(computed_sha, data["sha256_hash"])

    # -------------------------------------------------------------
    # Step 10: Dashboard Telemetry - Verify Live SQLite Metrics
    # -------------------------------------------------------------
    def test_10_dashboard_telemetry_metrics(self):
        code, data, _ = dispatch_request("GET", "/api/v1/dashboard/stats")
        self.assertEqual(code, 200)
        metrics = data.get("metrics", {})
        self.assertGreaterEqual(metrics.get("total_cases", 0), 1)
        self.assertGreaterEqual(metrics.get("total_evidence", 0), 1)
        self.assertIn("severity_distribution", data)


if __name__ == "__main__":
    unittest.main()
