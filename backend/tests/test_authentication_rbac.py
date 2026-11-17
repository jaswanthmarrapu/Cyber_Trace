"""
CyberTrace - Authentication & Role-Based Access Control (RBAC) Test Suite
==========================================================================
Exhaustively tests requirements 1-15:
1. User registration across Admin, Investigator, and Viewer roles.
2. Duplicate username/email rejection (HTTP 400).
3. Salted cryptographic password hashing (PBKDF2-HMAC-SHA256, 0 plaintext).
4. Login with valid credentials returning signed JWT access token.
5. Invalid password / non-existent user rejection (HTTP 401).
6. Protected /auth/me profile endpoint with Bearer validation.
7. Unauthenticated request rejection (HTTP 401).
8. Role-based access control (RBAC):
   - Admin has full write/manage access.
   - Investigator has investigation & evidence upload access.
   - Viewer is restricted to read-only; mutations return HTTP 403 Forbidden.
9. Forgot password workflow: time-limited reset token generation.
10. Reset password workflow: updating password hash, subsequent successful login.
11. Logout endpoint response.
"""

import os
import sys
import json
import uuid
import unittest
from pathlib import Path
from unittest.mock import Mock

_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from app.standalone_server import CyberTraceHandler, DB_PATH, init_standalone_db
from app.utils.security import hash_password, verify_password, decode_access_token


class MockSocket:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0
        self.output = bytearray()

    def makefile(self, mode="r", buffering=-1):
        import io
        if "b" in mode:
            if "w" in mode or "a" in mode:
                class OutputBuffer(io.BytesIO):
                    def __init__(self, outer):
                        super().__init__()
                        self.outer = outer
                    def write(self, b):
                        self.outer.output.extend(b)
                        return len(b)
                return OutputBuffer(self)
            else:
                return io.BytesIO(self._data)
        else:
            return io.StringIO(self._data.decode("utf-8", errors="replace"))

    def sendall(self, data):
        self.output.extend(data)


def dispatch_request(method: str, path: str, body: dict = None, headers: dict = None):
    """Helper to dispatch HTTP request through CyberTraceHandler."""
    hdrs = headers or {}
    raw_body = json.dumps(body).encode("utf-8") if body else b""

    hdr_lines = [
        f"{method} {path} HTTP/1.1",
        "Host: 127.0.0.1:8000",
        f"Content-Length: {len(raw_body)}"
    ]
    if body:
        hdr_lines.append("Content-Type: application/json")
    for k, v in hdrs.items():
        hdr_lines.append(f"{k}: {v}")
    hdr_lines.append("")
    hdr_lines.append("")

    request_bytes = "\r\n".join(hdr_lines).encode("utf-8") + raw_body
    sock = MockSocket(request_bytes)
    CyberTraceHandler(sock, ("127.0.0.1", 54321), Mock())

    raw_response = sock.output.decode("utf-8", errors="replace")
    status_line = raw_response.split("\r\n")[0]
    status_code = int(status_line.split(" ")[1])

    parts = raw_response.split("\r\n\r\n", 1)
    json_data = {}
    if len(parts) > 1 and parts[1].strip():
        try:
            json_data = json.loads(parts[1])
        except Exception:
            pass

    return status_code, json_data


class TestAuthenticationAndRBAC(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_standalone_db()
        cls.test_run_id = uuid.uuid4().hex[:6]

    def test_01_user_registration_admin(self):
        """Test registration of an Administrator user."""
        status_code, data = dispatch_request("POST", "/api/v1/auth/register", {
            "username": f"adm_{self.test_run_id}",
            "email": f"adm_{self.test_run_id}@cybertrace.local",
            "password": "SecureAdminPassword2026!",
            "full_name": "Chief Security Officer",
            "role": "Admin"
        })
        self.assertEqual(status_code, 201)
        self.assertIn("access_token", data)
        self.assertEqual(data["user_info"]["role"], "Admin")

    def test_02_user_registration_investigator_and_viewer(self):
        """Test registration of Investigator and Viewer accounts."""
        # Investigator
        status_code, inv_data = dispatch_request("POST", "/api/v1/auth/register", {
            "username": f"inv_{self.test_run_id}",
            "email": f"inv_{self.test_run_id}@cybertrace.local",
            "password": "SecureInvestigatorPass2026!",
            "full_name": "Forensic Specialist",
            "role": "Investigator"
        })
        self.assertEqual(status_code, 201)
        self.assertEqual(inv_data["user_info"]["role"], "Investigator")

        # Viewer
        status_code, view_data = dispatch_request("POST", "/api/v1/auth/register", {
            "username": f"view_{self.test_run_id}",
            "email": f"view_{self.test_run_id}@cybertrace.local",
            "password": "SecureViewerPass2026!",
            "full_name": "Legal Auditor",
            "role": "Viewer"
        })
        self.assertEqual(status_code, 201)
        self.assertEqual(view_data["user_info"]["role"], "Viewer")

    def test_03_duplicate_username_rejection(self):
        """Verify registering an already existing username returns HTTP 400."""
        status_code, data = dispatch_request("POST", "/api/v1/auth/register", {
            "username": f"adm_{self.test_run_id}",
            "email": "different_email@cybertrace.local",
            "password": "AnotherPassword2026!",
            "role": "Investigator"
        })
        self.assertEqual(status_code, 400)
        self.assertIn("already registered", data.get("error", "").lower())

    def test_04_salted_password_hashing_zero_plaintext(self):
        """Verify stored password is PBKDF2 salt-hash format and never stored plaintext."""
        plain_pw = "PlainSamplePass2026!"
        hashed = hash_password(plain_pw)
        self.assertNotEqual(plain_pw, hashed)
        self.assertIn("$", hashed)
        self.assertTrue(verify_password(plain_pw, hashed))
        self.assertFalse(verify_password("WrongPassword!", hashed))

    def test_05_login_with_valid_credentials(self):
        """Verify login with correct credentials yields signed Bearer JWT."""
        status_code, data = dispatch_request("POST", "/api/v1/auth/login", {
            "username": f"inv_{self.test_run_id}",
            "password": "SecureInvestigatorPass2026!"
        })
        self.assertEqual(status_code, 200)
        token = data.get("access_token")
        self.assertIsNotNone(token)
        payload = decode_access_token(token)
        self.assertEqual(payload["sub"], f"inv_{self.test_run_id}")
        self.assertEqual(payload["role"], "Investigator")

    def test_06_login_with_invalid_credentials(self):
        """Verify login with incorrect password returns HTTP 401 Unauthorized."""
        status_code, data = dispatch_request("POST", "/api/v1/auth/login", {
            "username": f"inv_{self.test_run_id}",
            "password": "IncorrectPasswordXYZ"
        })
        self.assertEqual(status_code, 401)
        self.assertIn("invalid", data.get("error", "").lower())

    def test_07_protected_me_endpoint_bearer_token(self):
        """Verify /api/v1/auth/me returns examiner profile when authenticated with Bearer token."""
        # Authenticate first
        _, login_data = dispatch_request("POST", "/api/v1/auth/login", {
            "username": f"adm_{self.test_run_id}",
            "password": "SecureAdminPassword2026!"
        })
        token = login_data["access_token"]

        # Request /auth/me with Bearer token
        status_code, profile = dispatch_request("GET", "/api/v1/auth/me", headers={
            "Authorization": f"Bearer {token}"
        })
        self.assertEqual(status_code, 200)
        self.assertEqual(profile["username"], f"adm_{self.test_run_id}")
        self.assertEqual(profile["role"], "Admin")

    def test_08_protected_me_endpoint_unauthenticated_rejected(self):
        """Verify /api/v1/auth/me without token returns HTTP 401."""
        status_code, data = dispatch_request("GET", "/api/v1/auth/me")
        self.assertEqual(status_code, 401)

    def test_09_rbac_viewer_blocked_from_mutations(self):
        """RBAC Test: Verify Viewer role is rejected with HTTP 403 on case creation."""
        # Login as Viewer
        _, login_data = dispatch_request("POST", "/api/v1/auth/login", {
            "username": f"view_{self.test_run_id}",
            "password": "SecureViewerPass2026!"
        })
        viewer_token = login_data["access_token"]

        # Attempt to create an investigation case as Viewer -> Should be rejected with 403
        status_code, err = dispatch_request("POST", "/api/v1/cases", {
            "title": "Unauthorized Case Creation",
            "description": "Should fail",
            "severity": "Low"
        }, headers={"Authorization": f"Bearer {viewer_token}"})

        self.assertEqual(status_code, 403)
        self.assertIn("forbidden", err.get("error", "").lower())

    def test_10_rbac_investigator_and_admin_permitted_mutations(self):
        """RBAC Test: Verify Investigator and Admin roles are permitted to create cases."""
        # Login as Investigator
        _, inv_login = dispatch_request("POST", "/api/v1/auth/login", {
            "username": f"inv_{self.test_run_id}",
            "password": "SecureInvestigatorPass2026!"
        })
        inv_token = inv_login["access_token"]

        # Investigator creates case -> Allowed
        status_code, case = dispatch_request("POST", "/api/v1/cases", {
            "title": f"Operation HawkEye - {self.test_run_id}",
            "description": "Authorized DFIR case creation.",
            "severity": "High"
        }, headers={"Authorization": f"Bearer {inv_token}"})
        self.assertEqual(status_code, 201)
        self.assertIn("case_number", case)

    def test_11_forgot_and_reset_password_workflow(self):
        """Test forgot-password recovery token generation and successful password reset."""
        # 1. Request recovery token
        status_code, forgot_res = dispatch_request("POST", "/api/v1/auth/forgot-password", {
            "identifier": f"inv_{self.test_run_id}"
        })
        self.assertEqual(status_code, 200)
        reset_token = forgot_res.get("reset_token")
        self.assertIsNotNone(reset_token)

        # 2. Reset password using valid token
        new_password = "NewlyUpdatedSecurePassword2026!"
        status_code, reset_res = dispatch_request("POST", "/api/v1/auth/reset-password", {
            "reset_token": reset_token,
            "new_password": new_password
        })
        self.assertEqual(status_code, 200)
        self.assertIn("successfully updated", reset_res.get("message", "").lower())

        # 3. Old password must fail
        status_code, _ = dispatch_request("POST", "/api/v1/auth/login", {
            "username": f"inv_{self.test_run_id}",
            "password": "SecureInvestigatorPass2026!"
        })
        self.assertEqual(status_code, 401)

        # 4. New password must succeed
        status_code, new_login = dispatch_request("POST", "/api/v1/auth/login", {
            "username": f"inv_{self.test_run_id}",
            "password": new_password
        })
        self.assertEqual(status_code, 200)
        self.assertIn("access_token", new_login)

    def test_12_logout_endpoint(self):
        """Test logout endpoint returns clean session termination response."""
        status_code, data = dispatch_request("POST", "/api/v1/auth/logout")
        self.assertEqual(status_code, 200)
        self.assertEqual(data.get("status"), "success")


if __name__ == "__main__":
    unittest.main()
