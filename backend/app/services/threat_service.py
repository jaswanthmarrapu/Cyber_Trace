import re
from typing import List, Dict
from app.utils.constants import MITRE_TECHNIQUES

SQLI_PATTERNS = [
    re.compile(r'(\%27)|(\')|(--)|(\%23)|(#)', re.IGNORECASE),
    re.compile(r'\b(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table)\b', re.IGNORECASE),
    re.compile(r'\b(sleep\(|benchmark\(|waitfor\s+delay)\b', re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r'<script.*?>', re.IGNORECASE),
    re.compile(r'javascript:', re.IGNORECASE),
    re.compile(r'onerror\s*=', re.IGNORECASE),
    re.compile(r'onload\s*=', re.IGNORECASE),
]

TRAVERSAL_PATTERNS = [
    re.compile(r'(\.\./|\.\.\\)', re.IGNORECASE),
    re.compile(r'(/etc/passwd|win\.ini|boot\.ini)', re.IGNORECASE),
]

def analyze_log_entry_for_threats(raw_text: str) -> Dict[str, any]:
    """Inspect a log string for known attack vectors."""
    # Check SQLi
    for p in SQLI_PATTERNS:
        if p.search(raw_text):
            return {
                "is_threat": True,
                "event_type": "SQL Injection Attempt",
                "severity": "High",
                "mitre": f"{MITRE_TECHNIQUES['SQL_INJECTION']['id']} - {MITRE_TECHNIQUES['SQL_INJECTION']['name']}"
            }

    # Check Traversal
    for p in TRAVERSAL_PATTERNS:
        if p.search(raw_text):
            return {
                "is_threat": True,
                "event_type": "Directory Traversal",
                "severity": "High",
                "mitre": f"{MITRE_TECHNIQUES['DIRECTORY_TRAVERSAL']['id']} - {MITRE_TECHNIQUES['DIRECTORY_TRAVERSAL']['name']}"
            }

    # Check XSS
    for p in XSS_PATTERNS:
        if p.search(raw_text):
            return {
                "is_threat": True,
                "event_type": "Cross-Site Scripting (XSS)",
                "severity": "Medium",
                "mitre": f"{MITRE_TECHNIQUES['SQL_INJECTION']['id']} - Web Exploit"
            }

    # Check Failed SSH / Auth
    if "failed password" in raw_text.lower() or "authentication failure" in raw_text.lower():
        return {
            "is_threat": True,
            "event_type": "Failed Authentication (Brute Force Indicator)",
            "severity": "Medium",
            "mitre": f"{MITRE_TECHNIQUES['BRUTE_FORCE']['id']} - {MITRE_TECHNIQUES['BRUTE_FORCE']['name']}"
        }

    # Check Sudo / Privilege escalation
    if "sudo:" in raw_text.lower() and "user=root" in raw_text.lower():
        return {
            "is_threat": True,
            "event_type": "Elevated Privilege Execution",
            "severity": "High",
            "mitre": f"{MITRE_TECHNIQUES['PRIVILEGE_ESCALATION']['id']} - {MITRE_TECHNIQUES['PRIVILEGE_ESCALATION']['name']}"
        }

    # Check Log clearing
    if "1102" in raw_text and "audit log was cleared" in raw_text.lower():
        return {
            "is_threat": True,
            "event_type": "Audit Log Tampering / Clearing",
            "severity": "Critical",
            "mitre": f"{MITRE_TECHNIQUES['LOG_CLEARING']['id']} - {MITRE_TECHNIQUES['LOG_CLEARING']['name']}"
        }

    return {
        "is_threat": False,
        "event_type": "Standard Event",
        "severity": "Low",
        "mitre": None
    }

