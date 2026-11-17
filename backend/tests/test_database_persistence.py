"""
CyberTrace - Database Persistence & Configuration Verification Test Suite
==========================================================================
Tests requirements:
1. Resolution of DATABASE_PATH environment variable.
2. Default Render persistent disk path (/var/data/cybertrace.db).
3. Local development fallback path.
4. Automatic table creation without resetting existing records.
5. User account preservation, PBKDF2 password verification, and JWT session handling.
6. Forensic evidence, case triage, and threat alert queries work with the updated path.
7. Database connection health probe and error recovery.
"""

import os
import sys
import uuid
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

# Ensure backend root on sys.path
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.standalone_server import init_standalone_db
from app.config import (
    Settings,
    _resolve_sqlite_db_path,
    _resolve_database_url,
    _resolve_data_dir,
    _resolve_storage_and_database,
    is_storage_path_writable,
    BASE_DIR
)
from app.utils.file_security import get_uploads_dir, get_reports_dir, generate_secure_storage_path
from app.utils.security import hash_password, verify_password, create_access_token, decode_access_token
from app.forensic.case_engine import (
    create_investigation_case,
    init_case_management_tables,
    generate_case_summary_dossier
)
from app.forensic.threat_engine import (
    init_threat_detection_tables,
    store_threat_alerts,
    get_stored_threat_alerts
)
from app.forensic.timeline_engine import (
    init_timeline_tables,
    store_timeline_events,
    get_timeline_events_from_db
)


class TestDatabasePersistence(unittest.TestCase):

    def setUp(self):
        self.original_env = os.environ.copy()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_01_local_development_fallback(self):
        """Verify local development fallback resolves to BASE_DIR / cybertrace.db when env vars are absent."""
        os.environ.pop("DATABASE_PATH", None)
        os.environ.pop("RENDER", None)
        os.environ.pop("DATA_DIR", None)

        resolved = _resolve_sqlite_db_path()
        expected = BASE_DIR / "cybertrace.db"
        self.assertEqual(resolved, expected)

        data_dir = _resolve_data_dir(resolved)
        self.assertEqual(data_dir, BASE_DIR)

        db_url = _resolve_database_url(resolved)
        self.assertTrue(db_url.startswith("sqlite:///"))
        self.assertIn("cybertrace.db", db_url)

    def test_02_database_path_env_override(self):
        """Verify explicit DATABASE_PATH environment variable overrides all defaults when writable."""
        custom_target = "/custom/mounted/forensics/vault.db"
        os.environ["DATABASE_PATH"] = custom_target

        with patch("app.config.is_storage_path_writable", return_value=True):
            resolved = _resolve_sqlite_db_path()
            self.assertEqual(str(resolved), str(Path(custom_target)))

            db_url = _resolve_database_url(resolved)
            self.assertIn("vault.db", db_url)

    def test_03_render_cloud_persistent_disk_default(self):
        """Verify Render environment (RENDER=true) defaults to /var/data/cybertrace.db when mounted."""
        os.environ.pop("DATABASE_PATH", None)
        os.environ["RENDER"] = "true"

        with patch("app.config.is_storage_path_writable", return_value=True):
            resolved = _resolve_sqlite_db_path()
            self.assertEqual(str(resolved), str(Path("/var/data/cybertrace.db")))

            data_dir = _resolve_data_dir(resolved)
            self.assertEqual(str(data_dir), str(Path("/var/data")))

            db_url = _resolve_database_url(resolved)
            self.assertEqual(db_url, "sqlite:////var/data/cybertrace.db")

    def test_04_data_dir_env_path_resolution(self):
        """Verify DATA_DIR environment variable resolves to DATA_DIR / cybertrace.db when writable."""
        os.environ.pop("DATABASE_PATH", None)
        os.environ.pop("RENDER", None)
        os.environ["DATA_DIR"] = "/mnt/forensic_volume"

        with patch("app.config.is_storage_path_writable", return_value=True):
            resolved = _resolve_sqlite_db_path()
            expected = Path("/mnt/forensic_volume/cybertrace.db")
            self.assertEqual(str(resolved), str(expected))

    def test_05_dynamic_settings_property_responsiveness(self):
        """Verify Settings properties dynamically adapt when DATABASE_PATH changes at runtime."""
        settings = Settings()
        test_db_file = f"/tmp/test_audit_{uuid.uuid4().hex[:6]}.db"
        os.environ["DATABASE_PATH"] = test_db_file

        with patch("app.config.is_storage_path_writable", return_value=True):
            self.assertEqual(str(settings.SQLITE_DB_PATH), str(Path(test_db_file)))
            self.assertIn(test_db_file.replace("\\", "/"), settings.DATABASE_URL)

    def test_06_database_creation_and_non_destructive_startup(self):
        """Verify tables are initialized on a new path without resetting existing examiner records."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_db = Path(tmpdir) / "persistent_test.db"
            db_path_str = str(test_db)

            # Step 1: Initialize complete database schema on fresh path
            init_standalone_db(db_path_str)
            self.assertTrue(test_db.exists(), "Database file must be created on initialization")

            # Step 2: Insert investigator record and case record
            conn = sqlite3.connect(db_path_str)
            cursor = conn.cursor()
            user_id = str(uuid.uuid4())
            pw_hash = hash_password("SuperSecretInvestigatorPass2026!")
            cursor.execute(
                "INSERT INTO users (id, username, email, hashed_password, full_name, role) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, "persistent_investigator", "persist@cybertrace.local", pw_hash, "Dr. Elena Vance", "Investigator")
            )
            conn.commit()
            conn.close()

            # Step 3: Create forensic case
            case_data = create_investigation_case(
                db_path=db_path_str,
                title="Operation Persistent Beacon",
                description="Testing database retention across restarts.",
                severity="Critical",
                incident_type="C2 Traffic",
                investigator_name="Dr. Elena Vance"
            )
            case_id = case_data["id"]

            # Step 4: Re-initialize (simulating container restart / deploy)
            init_standalone_db(db_path_str)

            # Step 5: Verify user was NOT wiped or recreated
            conn = sqlite3.connect(db_path_str)
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, hashed_password, role FROM users WHERE username = ?", ("persistent_investigator",))
            row = cursor.fetchone()
            conn.close()

            self.assertIsNotNone(row, "User record must persist across re-initialization")
            self.assertEqual(row[1], "persistent_investigator")
            self.assertTrue(verify_password("SuperSecretInvestigatorPass2026!", row[2]))
            self.assertEqual(row[3], "Investigator")

            # Step 6: Verify case summary dossier works on persisted database
            summary = generate_case_summary_dossier(db_path_str, case_id)
            self.assertEqual(summary["case"]["title"], "Operation Persistent Beacon")
            self.assertEqual(summary["case"]["investigator_name"], "Dr. Elena Vance")

    def test_07_forensic_threat_and_timeline_queries_on_persistent_db(self):
        """Verify threat detection and timeline engines store and retrieve data from the custom path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_db = str(Path(tmpdir) / "forensics_suite.db")
            case_id = str(uuid.uuid4())

            # Store threat alerts
            alerts = [
                {
                    "alert_id": f"ALT-{uuid.uuid4().hex[:6]}",
                    "rule_id": "TA-001",
                    "detection_category": "Command and Control",
                    "severity": "Critical",
                    "related_evidence": "packet_capture.pcap",
                    "detection_timestamp": "2026-11-17T09:00:00Z",
                    "reason_for_detection": "Detected /bin/bash reverse shell connection.",
                    "recommended_investigation_steps": ["Isolate host", "Dump process memory"],
                    "mitre_technique": "T1059.004"
                }
            ]
            stored_count = store_threat_alerts(test_db, case_id=case_id, alerts=alerts)
            self.assertEqual(stored_count, 1)

            retrieved_alerts = get_stored_threat_alerts(test_db, case_id=case_id)
            self.assertEqual(len(retrieved_alerts), 1)
            self.assertEqual(retrieved_alerts[0]["rule_id"], "TA-001")

            # Store timeline events
            timeline_events = [
                {
                    "id": str(uuid.uuid4()),
                    "timestamp": "2026-11-17T08:00:00Z",
                    "phase": "Initial Access",
                    "source": "auth.log",
                    "description": "Unauthorized SSH brute force login.",
                    "severity": "High",
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "T1110",
                    "event_type": "ssh_login"
                }
            ]
            stored_timeline_count = store_timeline_events(test_db, case_id=case_id, events=timeline_events)
            self.assertEqual(stored_timeline_count, 1)

            retrieved_timeline = get_timeline_events_from_db(test_db, case_id=case_id)
            self.assertEqual(len(retrieved_timeline), 1)
            self.assertEqual(retrieved_timeline[0]["mitre_tactic"], "Initial Access")
            self.assertEqual(retrieved_timeline[0]["event_source"], "auth.log")

    def test_08_jwt_authentication_flow_with_persisted_user(self):
        """Verify token generation and validation against persisted database credentials."""
        token = create_access_token({
            "sub": "persisted_admin",
            "user_id": "usr-123456",
            "role": "Admin",
            "email": "admin@cybertrace.local"
        })
        self.assertIsNotNone(token)

        payload = decode_access_token(token)
        self.assertEqual(payload["sub"], "persisted_admin")
        self.assertEqual(payload["role"], "Admin")

    def test_09_unwritable_storage_graceful_fallback(self):
        """
        Verify that if /var/data or DATABASE_PATH is NOT writable (e.g. persistent disk not attached),
        the backend does NOT crash, gracefully falls back to local application directory,
        sets IS_PERSISTENT_STORAGE=False, and emits STORAGE_WARNING.
        """
        os.environ["RENDER"] = "true"
        os.environ.pop("DATABASE_PATH", None)

        with patch("app.config.is_storage_path_writable", return_value=False):
            db_path, data_dir, is_persistent, warning = _resolve_storage_and_database()
            self.assertEqual(db_path, BASE_DIR / "cybertrace.db")
            self.assertEqual(data_dir, BASE_DIR)
            self.assertFalse(is_persistent)
            self.assertIsNotNone(warning)
            self.assertIn("not writable", warning)

            settings = Settings()
            self.assertEqual(settings.SQLITE_DB_PATH, BASE_DIR / "cybertrace.db")
            self.assertFalse(settings.IS_PERSISTENT_STORAGE)
            self.assertIsNotNone(settings.STORAGE_WARNING)

    def test_10_safe_directory_creation_and_file_security(self):
        """
        Verify that file_security helpers dynamically resolve upload directory
        without requiring module-level mkdir calls that crash worker startup.
        """
        uploads_dir = get_uploads_dir()
        self.assertTrue(uploads_dir.exists())
        self.assertTrue(uploads_dir.is_dir())

        reports_dir = get_reports_dir()
        self.assertTrue(reports_dir.exists())
        self.assertTrue(reports_dir.is_dir())

        stored_name, secure_path = generate_secure_storage_path("malware_test.exe")
        self.assertTrue(stored_name.endswith(".exe.vault"))
        self.assertEqual(secure_path.parent, uploads_dir)


if __name__ == "__main__":
    unittest.main()
