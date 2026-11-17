"""CyberTrace Security and Forensic Constants."""

SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
CASE_STATUSES = ["Open", "Investigating", "Pending Review", "Closed", "Archived"]
INTEGRITY_STATUSES = ["Verified", "Compromised", "Unverified"]

MITRE_TECHNIQUES = {
    "BRUTE_FORCE": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "SQL_INJECTION": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "COMMAND_INJECTION": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "DIRECTORY_TRAVERSAL": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
    "PRIVILEGE_ESCALATION": {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "LOG_CLEARING": {"id": "T1070", "name": "Indicator Removal: Clear Windows Event Logs", "tactic": "Defense Evasion"},
    "NEW_SERVICE": {"id": "T1543.003", "name": "Create or Modify System Process: Windows Service", "tactic": "Persistence"},
    "PORT_SCAN": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "WEB_SHELL": {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence"},
}

ATTRIBUTION_DISCLAIMER = (
    "FORENSIC NOTICE (ISO/IEC 27037 Standard): An IP address indicates a network routing endpoint or intermediate "
    "relay (e.g., VPN, Proxy, Tor, or compromised node). Attribution to a specific individual or organization "
    "requires telecommunication subscriber logs, corroborating device-level telemetry, and lawful judicial warrants. "
    "Never treat IP geolocation as sole proof of attacker identity."
)

MAGIC_SIGNATURES = {
    b"\x7fELF": "application/x-executable (Linux ELF)",
    b"MZ": "application/x-dosexec (Windows PE/EXE/DLL)",
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"PK\x03\x04": "application/zip / docx / jar",
    b"%PDF-": "application/pdf",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"\x1f\x8b\x08": "application/gzip",
    b"BM": "image/bmp",
}

