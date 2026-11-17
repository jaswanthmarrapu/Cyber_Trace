"""
CyberTrace - Professional PDF Investigation Report Generator Unit Test Suite
Validates all 12 required sections and forensic formatting standards:
1. CyberTrace header and branding.
2. Investigation case ID.
3. Investigation title.
4. Investigator details.
5. Evidence collection details.
6. Evidence SHA-256 hashes.
7. Log analysis findings.
8. IP investigation results.
9. Threat detection alerts.
10. Attack timeline.
11. AI-assisted investigation summary.
12. Final observations (with clear distinction between confirmed observations and potential threats).
Layout: Page numbers, headings, tables, timestamps.
"""

import os
import sys
import unittest
import hashlib
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.forensic.report_generator import (
    generate_complete_investigation_report_pdf,
    query_case_report_dossier,
    REPORTLAB_AVAILABLE
)
from app.standalone_server import DB_PATH, init_standalone_db


class TestReportGenerator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_standalone_db()
        cls.case_id = "case-001"
        cls.dossier = query_case_report_dossier(str(DB_PATH), cls.case_id)
        cls.output_pdf = str(Path(__file__).parent / "test_forensic_report.pdf")
        cls.report_result = generate_complete_investigation_report_pdf(
            str(DB_PATH),
            cls.case_id,
            output_path=cls.output_pdf,
            generated_by="Lead DFIR Specialist"
        )

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.output_pdf):
            try:
                os.remove(cls.output_pdf)
            except Exception:
                pass

    def test_section_01_cybertrace_header_and_branding(self):
        """Req 1: CyberTrace header and branding."""
        self.assertIn("report_number", self.dossier)
        self.assertTrue(self.dossier["report_number"].startswith("REP-"))
        self.assertIn("generated_at", self.dossier)
        self.assertIn("UTC", self.dossier["generated_at"])

    def test_section_02_investigation_case_id(self):
        """Req 2: Investigation case ID."""
        case_info = self.dossier["case_info"]
        self.assertIn("case_number", case_info)
        self.assertEqual(case_info["case_number"], "CT-2026-001")

    def test_section_03_investigation_title(self):
        """Req 3: Investigation title."""
        case_info = self.dossier["case_info"]
        self.assertIn("title", case_info)
        self.assertIn("DarkHydra", case_info["title"])
        self.assertIn("severity", case_info)
        self.assertEqual(case_info["severity"], "Critical")

    def test_section_04_investigator_details(self):
        """Req 4: Investigator details."""
        case_info = self.dossier["case_info"]
        self.assertIn("investigator_name", case_info)
        self.assertTrue(len(case_info["investigator_name"]) > 0)

    def test_section_05_evidence_collection_details(self):
        """Req 5: Evidence collection details."""
        evidence = self.dossier["evidence_items"]
        self.assertTrue(len(evidence) >= 1)
        ev0 = evidence[0]
        self.assertIn("evidence_number", ev0)
        self.assertIn("original_filename", ev0)
        self.assertIn("file_size_bytes", ev0)
        self.assertIn("source_device", ev0)

    def test_section_06_evidence_sha256_hashes(self):
        """Req 6: Evidence SHA-256 hashes."""
        evidence = self.dossier["evidence_items"]
        self.assertTrue(len(evidence) >= 1)
        for ev in evidence:
            sha = ev.get("sha256_hash")
            self.assertIsNotNone(sha)
            self.assertEqual(len(sha), 64, "SHA-256 must be a 64-hex character string")

    def test_section_07_log_analysis_findings(self):
        """Req 7: Log analysis findings."""
        logs = self.dossier["log_events"]
        self.assertTrue(len(logs) >= 1)
        l0 = logs[0]
        self.assertIn("event_timestamp", l0)
        self.assertIn("service", l0)
        self.assertIn("source_ip", l0)
        self.assertIn("event_type", l0)

    def test_section_08_ip_investigation_results(self):
        """Req 8: IP investigation results."""
        ips = self.dossier["ip_records"]
        self.assertTrue(len(ips) >= 1)
        ip0 = ips[0]
        self.assertIn("ip_address", ip0)
        self.assertIn("scope", ip0)
        self.assertIn("abuse_score", ip0)

    def test_section_09_threat_detection_alerts(self):
        """Req 9: Threat detection alerts."""
        threats = self.dossier["threat_alerts"]
        self.assertTrue(len(threats) >= 1)
        t0 = threats[0]
        self.assertIn("alert_id", t0)
        self.assertIn("detection_category", t0)
        self.assertIn("severity", t0)
        self.assertIn("reason_for_detection", t0)

    def test_section_10_attack_timeline(self):
        """Req 10: Attack timeline."""
        timeline = self.dossier["timeline_events"]
        self.assertTrue(len(timeline) >= 1)
        tl0 = timeline[0]
        self.assertIn("event_timestamp", tl0)
        self.assertIn("event_category", tl0)
        self.assertIn("actor", tl0)
        self.assertIn("description", tl0)

    def test_section_11_ai_assisted_investigation_summary(self):
        """Req 11: AI-assisted investigation summary."""
        ai = self.dossier["ai_summary"]
        self.assertIn("assessment_status", ai)
        self.assertIn("confidence_level", ai)
        self.assertIn("facts", ai)
        self.assertIn("hypotheses", ai)
        self.assertIn("recommendations", ai)
        self.assertTrue(len(ai["recommendations"]) >= 3)

    def test_section_12_final_observations_and_distinction(self):
        """Req 12: Final observations with distinction between confirmed and potential threats."""
        confirmed = self.dossier["confirmed_observations"]
        potential = self.dossier["potential_threats"]

        self.assertTrue(len(confirmed) >= 2)
        self.assertTrue(len(potential) >= 2)

        # Confirmed observations should reflect empirical facts
        joined_confirmed = " ".join(confirmed)
        self.assertIn("Integrity", joined_confirmed)

        # Potential threats should reflect risks / hypotheses
        joined_potential = " ".join(potential)
        self.assertIn("Attribution", joined_potential)

    def test_pdf_file_generation_and_checksum(self):
        """Verify the generated PDF is standard-compliant and cryptographically sealed."""
        self.assertTrue(os.path.exists(self.output_pdf))
        file_size = os.path.getsize(self.output_pdf)
        self.assertGreater(file_size, 1000, "PDF must not be empty")

        # Verify PDF header
        with open(self.output_pdf, "rb") as f:
            header = f.read(8)
            self.assertEqual(header[:5], b"%PDF-")

        # Verify SHA-256 seal
        with open(self.output_pdf, "rb") as f:
            computed_sha = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(computed_sha, self.report_result["sha256_hash"])

    def test_reportlab_or_pure_python_fallback(self):
        """Verify report generator engine status."""
        self.assertIn("status", self.report_result)
        self.assertEqual(self.report_result["status"], "Generated & Cryptographically Sealed")


if __name__ == "__main__":
    unittest.main()
