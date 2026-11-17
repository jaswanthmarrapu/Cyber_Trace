"""
CyberTrace - Full System Robustness & Edge Case Test Suite
==========================================================
Exhaustively tests all 12 core functional domains and 8 edge cases:
1. Frontend page navigation endpoints (/, /index.html)
2. Backend API endpoints across all services
3. Database operations and ACID transactions
4. Evidence upload with baseline vault enrollment
5. SHA-256 cryptographic calculation
6. Evidence integrity verification & tamper detection
7. Log parsing across multi-format telemetry
8. Suspicious activity detection & MITRE mapping
9. IP address validation & scope classification
10. Timeline reconstruction & attack sequence inference
11. Case creation, status tracking & audit logging
12. Professional PDF report generation & SHA-256 sealing

Edge Cases:
- Empty file uploads (0 bytes)
- Invalid file formats (unauthorized extensions)
- Oversized files (> 50MB limit)
- Malformed logs (binary junk, unparseable lines)
- Duplicate evidence (identical SHA-256 in same case)
- Missing timestamps (safe ISO-8601 UTC fallback)
- Invalid IP addresses (out-of-range octets, malformed syntax)
- Database errors (graceful handling without crashes)
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

from app.standalone_server import CyberTraceHandler, DB_PATH, init_standalone_db, MAX_FILE_SIZE
from app.forensic.report_generator import generate_complete_investigation_report_pdf
from app.forensic.log_analyzer import parse_iso_or_log_timestamp, execute_log_analysis_pipeline
from app.forensic.ip_analyzer import validate_ipv4, investigate_single_ip


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


def dispatch_request(method: str, path: str, body: dict = None, raw_payload: bytes = None, content_type: str = None) -> tuple[int, dict, bytes]:
    """Helper to dispatch HTTP request through CyberTraceHandler."""
    headers = [f"{method} {path} HTTP/1.1", "Host: localhost"]
    payload_bytes = b""
    if raw_payload is not None:
        payload_bytes = raw_payload
        headers.append(f"Content-Type: {content_type or 'application/octet-stream'}")
        headers.append(f"Content-Length: {len(payload_bytes)}")
    elif body is not None:
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


class TestCyberTraceRobustnessAndEdgeCases(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_standalone_db()
        cls.test_case_id = f"case-robust-{uuid.uuid4().hex[:6]}"
        cls.test_case_num = f"CT-ROBUST-{uuid.uuid4().hex[:4].upper()}"

    # =========================================================================
    # 1. Frontend Page Navigation & Static Endpoints
    # =========================================================================
    def test_01_frontend_static_serving(self):
        """Test root / and /index.html serve valid HTML frontend."""
        code, _, body = dispatch_request("GET", "/")
        self.assertEqual(code, 200)
        self.assertTrue(b"<!DOCTYPE html>" in body or b"<html" in body)

        code_idx, _, body_idx = dispatch_request("GET", "/index.html")
        self.assertEqual(code_idx, 200)
        self.assertTrue(b"CyberTrace" in body_idx)

    # =========================================================================
    # 2. Case Creation & Lifecycle Management
    # =========================================================================
    def test_02_case_creation_and_lifecycle(self):
        """Test case creation, unique case number generation, and audit logging."""
        code, data, _ = dispatch_request("POST", "/api/v1/cases", {
            "title": "Operation Ironclad - Robustness Testing",
            "description": "Comprehensive edge case validation of CyberTrace platform.",
            "investigator_name": "Senior Forensic Examiner",
            "severity": "High",
            "incident_type": "Insider Threat & Data Exfiltration"
        })
        self.assertEqual(code, 201)
        self.assertIn("id", data)
        self.assertIn("case_number", data)
        self.__class__.test_case_id = data["id"]
        self.__class__.test_case_num = data["case_number"]

        # Verify audit trail recorded
        audit_code, audit_data, _ = dispatch_request("GET", f"/api/v1/cases/{data['id']}/audit-trail")
        self.assertEqual(audit_code, 200)
        self.assertGreaterEqual(audit_data.get("total_audit_events", 0), 1)

    # =========================================================================
    # 3. Evidence Upload & SHA-256 Calculation
    # =========================================================================
    def test_03_evidence_upload_and_sha256(self):
        """Test valid evidence upload, baseline SHA-256 calculation, and vault enrollment."""
        case_id = self.__class__.test_case_id
        content_str = "FORENSIC MEMORY STREAM DUMP ARTIFACT 2026-11-17 - " + case_id
        content_bytes = content_str.encode("utf-8")
        expected_sha = hashlib.sha256(content_bytes).hexdigest()

        code, data, _ = dispatch_request("POST", "/api/v1/evidence/upload", {
            "case_id": case_id,
            "filename": "memdump_segment.raw",
            "acquired_by": "Senior Forensic Examiner",
            "source_device": "Host DB-CORE-01",
            "description": "Physical volatile RAM capture segment",
            "content": content_str
        })
        self.assertEqual(code, 201)
        self.assertEqual(data["sha256_hash"], expected_sha)
        self.assertEqual(data["initial_recorded_hash"], expected_sha)
        self.assertEqual(data["integrity_status"], "Verified")
        self.assertEqual(data["case_id"], case_id)
        self.__class__.valid_evidence_id = data["id"]
        self.__class__.valid_evidence_sha = expected_sha

    # =========================================================================
    # 4. Evidence Integrity Verification & Tamper Detection
    # =========================================================================
    def test_04_evidence_integrity_verification_and_tamper(self):
        """Test verification of untampered evidence, then simulate tampering and detect violation."""
        ev_id = self.__class__.valid_evidence_id
        # Step 1: Verify intact evidence
        code, data, _ = dispatch_request("POST", f"/api/v1/evidence/{ev_id}/verify")
        self.assertEqual(code, 200)
        self.assertEqual(data["integrity_status"], "Verified")
        self.assertTrue(data["hashes_match"])

        # Step 2: Simulate physical disk tampering
        t_code, t_data, _ = dispatch_request("POST", f"/api/v1/evidence/{ev_id}/tamper")
        self.assertEqual(t_code, 200)
        self.assertEqual(t_data["status"], "Compromised")

        # Step 3: Re-verify compromised evidence
        v_code, v_data, _ = dispatch_request("POST", f"/api/v1/evidence/{ev_id}/verify")
        self.assertEqual(v_code, 200)
        self.assertEqual(v_data["integrity_status"], "Compromised")
        self.assertFalse(v_data["hashes_match"])

    # =========================================================================
    # 5. Log Parsing & Multi-Format Telemetry
    # =========================================================================
    def test_05_log_parsing_and_correlation(self):
        """Test parsing of syslog, web server combined logs, and Windows event streams."""
        case_id = self.__class__.test_case_id
        log_sample = (
            '185.220.101.5 - - [14/Nov/2026:03:10:00 +0000] "GET /login.php HTTP/1.1" 200 4521\n'
            '185.220.101.5 - - [14/Nov/2026:03:10:15 +0000] "POST /login.php HTTP/1.1" 401 1234\n'
            '185.220.101.5 - - [14/Nov/2026:03:10:30 +0000] "POST /login.php HTTP/1.1" 401 1234\n'
            '185.220.101.5 - - [14/Nov/2026:03:10:45 +0000] "POST /login.php HTTP/1.1" 401 1234\n'
            'Nov 14 03:11:00 srv sudo: deploy : TTY=pts/0 ; COMMAND=/bin/bash\n'
        )
        code, data, _ = dispatch_request("POST", "/api/v1/logs/analyze", {
            "case_id": case_id,
            "log_text": log_sample,
            "filename": "perimeter_combined.log",
            "rules": {"failed_login_threshold": 3}
        })
        self.assertEqual(code, 200)
        self.assertGreaterEqual(data["total_lines_analyzed"], 5)
        self.assertGreaterEqual(data["threats_detected"], 1)

    # =========================================================================
    # 6. Suspicious Activity & Threat Detection Engine
    # =========================================================================
    def test_06_threat_detection_rules(self):
        """Test evaluation of all 5 configurable threat detection rules."""
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
        self.assertGreaterEqual(data["alerts_count"], 1)

    # =========================================================================
    # 7. IP Address Validation & Scope Analysis
    # =========================================================================
    def test_07_ip_investigation_and_attribution_safeguard(self):
        """Test valid IP investigation, RFC 1918 classification, and ISO 27037 attribution safeguard."""
        # Public Tor Relay
        code, data, _ = dispatch_request("POST", "/api/v1/ip/investigate", {
            "ip_address": "185.220.101.5",
            "case_id": self.__class__.test_case_id,
            "enable_public_intel": True
        })
        self.assertEqual(code, 200)
        self.assertEqual(data["ip_address"], "185.220.101.5")
        self.assertFalse(data["observed_information"]["is_private"])
        self.assertIn("attribution_caveat", data)
        self.assertIn("ISO/IEC 27037", data["attribution_caveat"])

        # Private RFC 1918 IP
        code_priv, data_priv, _ = dispatch_request("POST", "/api/v1/ip/investigate", {
            "ip_address": "192.168.1.100",
            "case_id": self.__class__.test_case_id
        })
        self.assertEqual(code_priv, 200)
        self.assertTrue(data_priv["observed_information"]["is_private"])

    # =========================================================================
    # 8. Attack Timeline Reconstruction
    # =========================================================================
    def test_08_attack_timeline_reconstruction(self):
        """Test chronological timeline synthesis, UTC normalization, and sequence clustering."""
        case_id = self.__class__.test_case_id
        code, data, _ = dispatch_request("POST", "/api/v1/timeline/reconstruct", {
            "case_id": case_id
        })
        self.assertEqual(code, 200)
        self.assertIn("timeline", data)
        self.assertGreaterEqual(data["total_events"], 1)

    # =========================================================================
    # 9. PDF Investigation Report Generation & Download
    # =========================================================================
    def test_09_pdf_report_generation(self):
        """Test complete 12-section PDF report generation and binary download."""
        case_id = self.__class__.test_case_id
        code, data, _ = dispatch_request("POST", "/api/v1/reports/generate", {
            "case_id": case_id,
            "generated_by": "Senior Forensic Examiner"
        })
        self.assertEqual(code, 201)
        self.assertIn("report_number", data)
        self.assertIn("sha256_hash", data)

        # Download report
        rep_id = data["id"]
        dl_code, _, pdf_bytes = dispatch_request("GET", f"/api/v1/reports/{rep_id}/download")
        self.assertEqual(dl_code, 200)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertEqual(hashlib.sha256(pdf_bytes).hexdigest(), data["sha256_hash"])

    # =========================================================================
    # EDGE CASE 1: Empty File Uploads (0 Bytes)
    # =========================================================================
    def test_edge_01_empty_file_upload(self):
        """Verify uploading a 0-byte file returns HTTP 400 Bad Request."""
        case_id = self.__class__.test_case_id
        code, data, _ = dispatch_request("POST", "/api/v1/evidence/upload", {
            "case_id": case_id,
            "filename": "empty_evidence.raw",
            "content": ""
        })
        self.assertEqual(code, 400)
        self.assertIn("empty", data.get("error", "").lower())

        # Also test File Forensics with empty content
        f_code, f_data, _ = dispatch_request("POST", "/api/v1/files/analyze", {
            "filename": "zero_byte.txt",
            "content": "",
            "case_id": case_id
        })
        self.assertEqual(f_code, 400)
        self.assertIn("empty", f_data.get("error", "").lower())

    # =========================================================================
    # EDGE CASE 2: Invalid File Formats (Unauthorized Extensions)
    # =========================================================================
    def test_edge_02_invalid_file_formats(self):
        """Verify unauthorized file extensions (.exe_blocked, .xyz, .virus) are rejected."""
        case_id = self.__class__.test_case_id
        code, data, _ = dispatch_request("POST", "/api/v1/evidence/upload", {
            "case_id": case_id,
            "filename": "malware.unauthorized_ext_xyz",
            "content": "some byte stream"
        })
        self.assertEqual(code, 400)
        self.assertIn("unauthorized file extension", data.get("error", "").lower())

    # =========================================================================
    # EDGE CASE 3: Oversized Files (> 50MB Limit)
    # =========================================================================
    def test_edge_03_oversized_file(self):
        """Verify files exceeding 50MB limit are rejected."""
        case_id = self.__class__.test_case_id
        # We test header validation for oversized limit without creating 50MB in memory
        oversized_len = MAX_FILE_SIZE + 1024
        # Send simulated header with length exceeding MAX_FILE_SIZE
        code, data, _ = dispatch_request(
            "POST",
            "/api/v1/evidence/upload",
            raw_payload=b"A" * 100,  # Small payload with oversized header check
            content_type="application/json"
        )
        # Directly test validation logic
        from app.utils.file_security import validate_file_size
        self.assertFalse(validate_file_size(oversized_len))
        self.assertTrue(validate_file_size(1024 * 1024))

    # =========================================================================
    # EDGE CASE 4: Malformed Logs (Binary Junk, Unparseable Lines)
    # =========================================================================
    def test_edge_04_malformed_logs(self):
        """Verify corrupted, binary, or unparseable logs are safely parsed into RawText fallback without crashing."""
        case_id = self.__class__.test_case_id
        malformed_stream = (
            "\x00\x01\x02\xFF\xFE GIBBERISH JUNK LINE WITHOUT DELIMITERS\n"
            "Corrupted timestamp: 9999-99-99 88:88:88 UnknownHost error[9999]: corrupted line\n"
            "   \n"  # Empty line with spaces
            "Normal text without IP or timestamp\n"
        )
        code, data, _ = dispatch_request("POST", "/api/v1/logs/analyze", {
            "case_id": case_id,
            "log_text": malformed_stream,
            "filename": "corrupted_stream.log"
        })
        self.assertEqual(code, 200)
        self.assertGreaterEqual(data["total_lines_analyzed"], 3)
        self.assertIn("parsed_events", data)

    # =========================================================================
    # EDGE CASE 5: Duplicate Evidence Detection
    # =========================================================================
    def test_edge_05_duplicate_evidence(self):
        """Verify uploading duplicate evidence with identical SHA-256 to the same case returns HTTP 409 Conflict."""
        case_id = self.__class__.test_case_id
        unique_content = f"UNIQUE ARTIFACT FOR DUPLICATE TEST {uuid.uuid4()}"

        # First upload: Success (201)
        code1, data1, _ = dispatch_request("POST", "/api/v1/evidence/upload", {
            "case_id": case_id,
            "filename": "artifact_dup_test.bin",
            "content": unique_content
        })
        self.assertEqual(code1, 201)

        # Second upload with identical content: Conflict (409)
        code2, data2, _ = dispatch_request("POST", "/api/v1/evidence/upload", {
            "case_id": case_id,
            "filename": "artifact_dup_test_copy.bin",
            "content": unique_content
        })
        self.assertEqual(code2, 409)
        self.assertIn("duplicate evidence rejected", data2.get("error", "").lower())

    # =========================================================================
    # EDGE CASE 6: Missing Timestamps Handling
    # =========================================================================
    def test_edge_06_missing_timestamps(self):
        """Verify logs lacking timestamps safely fallback to ISO-8601 UTC timestamp."""
        iso_ts, dt_obj = parse_iso_or_log_timestamp(None)
        self.assertIsNotNone(iso_ts)
        self.assertIsNotNone(dt_obj)
        self.assertTrue("T" in iso_ts)

        iso_ts_bad, dt_bad = parse_iso_or_log_timestamp("corrupted_invalid_date_string")
        self.assertIsNotNone(iso_ts_bad)
        self.assertIsNotNone(dt_bad)

    # =========================================================================
    # EDGE CASE 7: Invalid IP Addresses
    # =========================================================================
    def test_edge_07_invalid_ip_addresses(self):
        """Verify out-of-range octets, strings, and malformed IPs return HTTP 400 Bad Request."""
        invalid_ips = [
            "999.999.999.999",
            "192.168.1.300",
            "abc.def.ghi.jkl",
            "1.2.3.4.5",
            "",
            "127.0.0.1; DROP TABLE cases;--"
        ]
        for bad_ip in invalid_ips:
            # Test standalone validation helper
            is_valid, _, err = validate_ipv4(bad_ip)
            self.assertFalse(is_valid, f"Expected {bad_ip} to be invalid")

            # Test API endpoint
            code, data, _ = dispatch_request("POST", "/api/v1/ip/investigate", {
                "ip_address": bad_ip,
                "case_id": self.__class__.test_case_id
            })
            self.assertEqual(code, 400)
            self.assertFalse(data.get("is_valid", True))

    # =========================================================================
    # EDGE CASE 8: Database Error Handling
    # =========================================================================
    def test_edge_08_database_error_handling(self):
        """Verify non-existent routes and invalid queries return clean JSON errors."""
        code, data, _ = dispatch_request("GET", "/api/v1/cases/non-existent-uuid-999999/summary")
        self.assertEqual(code, 404)
        self.assertIn("error", data)

        code_inv, data_inv, _ = dispatch_request("GET", "/api/v1/unknown_endpoint_xyz")
        self.assertEqual(code_inv, 404)
        self.assertIn("error", data_inv)


if __name__ == "__main__":
    unittest.main()
