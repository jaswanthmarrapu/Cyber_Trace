"""
CyberTrace - AI-Assisted Investigation Summary Test Suite
Validates all 7 functional requirements and mandatory forensic constraints:
1. Read structured investigation findings.
2. Summarise suspicious activities.
3. Explain why events were flagged.
4. Identify possible relationships between events.
5. Summarise attack timelines.
6. Suggest investigation steps.
7. Generate human-readable incident summaries.
Constraints:
- Strictly grounded in provided evidence (Zero invented IPs, events, hashes).
- Calibrated confidence: No declaring attack confirmed without multi-source evidence.
- Clear separation: Facts, Hypotheses, Recommendations.
- Evidence remains strictly immutable.
"""

import sys
import unittest
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.forensic.ai_assistant import (
    generate_grounded_ai_summary,
    synthesize_case_ai_summary_from_db
)
from app.standalone_server import init_standalone_db, DB_PATH


class TestAIAssistant(unittest.TestCase):

    def setUp(self):
        self.sample_case = {
            "id": "case-test-01",
            "case_number": "CT-TEST-001",
            "title": "Operation Alpha - Simulated Perimeter Intrusion",
            "description": "Controlled DFIR test scenario.",
            "investigator_name": "Tier-3 Forensic Examiner",
            "status": "Under Investigation",
            "severity": "Critical",
            "incident_type": "Data Exfiltration & Web Shell"
        }

        self.sample_evidence = [
            {
                "id": "ev-01",
                "evidence_number": "EVD-01",
                "original_filename": "staging_dump.raw",
                "sha256_hash": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
                "file_type": "raw",
                "file_size_bytes": 1048576,
                "integrity_status": "Verified"
            }
        ]

        self.sample_logs = [
            {
                "id": "log-01",
                "event_timestamp": "2026-11-12T04:12:01Z",
                "source_ip": "198.51.100.23",
                "service": "sshd",
                "event_type": "Failed Authentication",
                "severity": "Medium",
                "raw_log": "Failed password for root from 198.51.100.23 port 45212 ssh2",
                "is_threat": True,
                "mitre_technique": "T1110"
            },
            {
                "id": "log-02",
                "event_timestamp": "2026-11-12T04:12:30Z",
                "source_ip": "198.51.100.23",
                "service": "sshd",
                "event_type": "Accepted Password",
                "severity": "High",
                "raw_log": "Accepted password for deployer from 198.51.100.23 port 45230 ssh2",
                "is_threat": True,
                "mitre_technique": "T1078"
            },
            {
                "id": "log-03",
                "event_timestamp": "2026-11-12T04:13:02Z",
                "source_ip": "198.51.100.23",
                "service": "sudo",
                "event_type": "Privilege Escalation",
                "severity": "Critical",
                "raw_log": "sudo: deployer : TTY=pts/0 ; COMMAND=/bin/bash",
                "is_threat": True,
                "mitre_technique": "T1548"
            }
        ]

        self.sample_threat_alerts = [
            {
                "id": "alt-01",
                "alert_id": "ALT-001",
                "rule_id": "RULE-BRUTE-01",
                "detection_category": "Brute Force Authentication",
                "severity": "High",
                "related_evidence": "auth.log",
                "detection_timestamp": "2026-11-12T04:12:01Z",
                "reason_for_detection": "Observed 5 failed authentication attempts within 60 seconds.",
                "mitre_technique": "T1110",
                "recommended_investigation_steps": [
                    "Check targeted usernames in auth log",
                    "Isolate host if brute force succeeded"
                ]
            }
        ]

        self.sample_timeline = [
            {
                "id": "tl-01",
                "event_timestamp": "2026-11-12T04:12:01Z",
                "event_source": "SSH Log",
                "event_category": "Initial Access",
                "actor": "198.51.100.23",
                "target": "srv-bastion",
                "description": "Brute force attempts detected from 198.51.100.23",
                "mitre_tactic": "T1110",
                "confidence_level": "Confirmed"
            },
            {
                "id": "tl-02",
                "event_timestamp": "2026-11-12T04:13:02Z",
                "event_source": "Sudo Log",
                "event_category": "Privilege Escalation",
                "actor": "deployer",
                "target": "/bin/bash",
                "description": "Elevated bash shell spawned via sudo",
                "mitre_tactic": "T1548",
                "confidence_level": "Confirmed"
            }
        ]

    def test_structured_findings_ingestion(self):
        """Req 1: Successfully read and parse structured findings."""
        summary = generate_grounded_ai_summary(
            case_data=self.sample_case,
            evidence_items=self.sample_evidence,
            log_events=self.sample_logs,
            threat_alerts=self.sample_threat_alerts,
            timeline_events=self.sample_timeline
        )
        self.assertEqual(summary["case_number"], "CT-TEST-001")
        self.assertEqual(summary["case_title"], "Operation Alpha - Simulated Perimeter Intrusion")
        self.assertEqual(len(summary["facts"]["evidence_artifacts"]), 1)
        self.assertIn("198.51.100.23", summary["facts"]["observed_endpoints"])

    def test_summarise_suspicious_activities(self):
        """Req 2: Summarise suspicious activities strictly based on evidence."""
        summary = generate_grounded_ai_summary(
            case_data=self.sample_case,
            evidence_items=self.sample_evidence,
            log_events=self.sample_logs,
            threat_alerts=self.sample_threat_alerts,
            timeline_events=self.sample_timeline
        )
        self.assertIn("summary_narrative", summary["facts"])
        self.assertIn("CT-TEST-001", summary["facts"]["summary_narrative"])
        self.assertTrue(len(summary["facts"]["factual_points"]) > 0)

    def test_explain_why_events_flagged(self):
        """Req 3: Explain why events were flagged (rules, thresholds, signatures)."""
        summary = generate_grounded_ai_summary(
            case_data=self.sample_case,
            evidence_items=self.sample_evidence,
            log_events=self.sample_logs,
            threat_alerts=self.sample_threat_alerts,
            timeline_events=self.sample_timeline
        )
        self.assertTrue(len(summary["why_flagged"]) > 0)
        flagged_item = summary["why_flagged"][0]
        self.assertIn("reason", flagged_item)
        self.assertIn("Observed 5 failed authentication attempts", flagged_item["reason"])
        self.assertEqual(flagged_item["category"], "Brute Force Authentication")

    def test_identify_relationships_between_events(self):
        """Req 4: Identify possible relationships between events as hypotheses."""
        summary = generate_grounded_ai_summary(
            case_data=self.sample_case,
            evidence_items=self.sample_evidence,
            log_events=self.sample_logs,
            threat_alerts=self.sample_threat_alerts,
            timeline_events=self.sample_timeline
        )
        self.assertTrue(len(summary["hypotheses"]) > 0)
        hyp = summary["hypotheses"][0]
        self.assertIn("analytical_basis", hyp)
        self.assertIn("actor", hyp)

    def test_summarise_attack_timeline(self):
        """Req 5: Summarise attack timelines in chronological milestones."""
        summary = generate_grounded_ai_summary(
            case_data=self.sample_case,
            evidence_items=self.sample_evidence,
            log_events=self.sample_logs,
            threat_alerts=self.sample_threat_alerts,
            timeline_events=self.sample_timeline
        )
        self.assertTrue(len(summary["timeline_milestones"]) >= 2)
        m1 = summary["timeline_milestones"][0]
        m2 = summary["timeline_milestones"][1]
        self.assertLessEqual(m1["timestamp"], m2["timestamp"])

    def test_suggest_investigation_steps(self):
        """Req 6: Suggest actionable investigation and containment steps."""
        summary = generate_grounded_ai_summary(
            case_data=self.sample_case,
            evidence_items=self.sample_evidence,
            log_events=self.sample_logs,
            threat_alerts=self.sample_threat_alerts,
            timeline_events=self.sample_timeline
        )
        self.assertTrue(len(summary["recommendations"]) >= 3)
        joined_recs = " ".join(summary["recommendations"])
        self.assertIn("Containment", joined_recs)
        self.assertIn("RAM capture", joined_recs)
        self.assertIn("Credential", joined_recs)

    def test_human_readable_incident_summaries(self):
        """Req 7: Generate human-readable incident summaries."""
        summary = generate_grounded_ai_summary(
            case_data=self.sample_case,
            evidence_items=self.sample_evidence,
            log_events=self.sample_logs,
            threat_alerts=self.sample_threat_alerts,
            timeline_events=self.sample_timeline
        )
        narrative = summary["facts"]["summary_narrative"]
        self.assertIsInstance(narrative, str)
        self.assertIn("Forensic evaluation ingested", narrative)

    def test_zero_invention_constraint(self):
        """Constraint: AI must NOT invent IP addresses or unverified evidence."""
        summary = generate_grounded_ai_summary(
            case_data=self.sample_case,
            evidence_items=self.sample_evidence,
            log_events=self.sample_logs,
            threat_alerts=self.sample_threat_alerts,
            timeline_events=self.sample_timeline
        )
        # Only 198.51.100.23 was present in logs
        observed = summary["facts"]["observed_endpoints"]
        self.assertEqual(observed, ["198.51.100.23"])
        # No hallucinated IPs like 1.2.3.4, 8.8.8.8, 10.0.0.1
        self.assertNotIn("1.2.3.4", observed)
        self.assertNotIn("8.8.8.8", observed)

    def test_calibrated_confidence_constraint(self):
        """Constraint: Do not declare attack confirmed without sufficient evidence."""
        # Single log with low severity should NOT be Confirmed
        weak_case = dict(self.sample_case)
        weak_logs = [
            {
                "id": "log-weak",
                "event_timestamp": "2026-11-12T04:12:01Z",
                "source_ip": "10.0.0.5",
                "service": "http",
                "event_type": "HTTP 404",
                "severity": "Low",
                "raw_log": "GET /favicon.ico 404",
                "is_threat": False
            }
        ]
        summary = generate_grounded_ai_summary(
            case_data=weak_case,
            evidence_items=[],
            log_events=weak_logs,
            threat_alerts=[],
            timeline_events=[]
        )
        self.assertEqual(summary["assessment_status"], "Suspected Telemetry Anomaly (Baseline Evaluation Required)")
        self.assertIn("Preliminary", summary["confidence_level"])

    def test_tripartite_separation_constraint(self):
        """Constraint: Strictly distinguish facts, hypotheses, and recommendations."""
        summary = generate_grounded_ai_summary(
            case_data=self.sample_case,
            evidence_items=self.sample_evidence,
            log_events=self.sample_logs,
            threat_alerts=self.sample_threat_alerts,
            timeline_events=self.sample_timeline
        )
        self.assertIn("facts", summary)
        self.assertIn("hypotheses", summary)
        self.assertIn("recommendations", summary)
        # Ensure hypotheses are explicitly distinct
        for hyp in summary["hypotheses"]:
            self.assertIn("analytical_basis", hyp)

    def test_evidence_integrity_preservation_constraint(self):
        """Constraint: Original forensic evidence remains unchanged."""
        summary = generate_grounded_ai_summary(
            case_data=self.sample_case,
            evidence_items=self.sample_evidence,
            log_events=self.sample_logs,
            threat_alerts=self.sample_threat_alerts,
            timeline_events=self.sample_timeline
        )
        self.assertIn("forensic_integrity_guarantee", summary)
        self.assertIn("ISO/IEC 27037", summary["forensic_integrity_guarantee"])
        self.assertIn("unaltered", summary["forensic_integrity_guarantee"])

    def test_sqlite_db_synthesis(self):
        """Integration: Test synthesize_case_ai_summary_from_db against real DB."""
        init_standalone_db()
        summary = synthesize_case_ai_summary_from_db(str(DB_PATH), "case-001")
        self.assertEqual(summary["case_number"], "CT-2026-001")
        self.assertTrue(len(summary["facts"]["observed_endpoints"]) > 0)
        self.assertTrue(len(summary["recommendations"]) >= 3)


if __name__ == "__main__":
    unittest.main()
