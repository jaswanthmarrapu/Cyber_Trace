import re
from pathlib import Path
from typing import List, Dict

# Built-in signature rule set for passive malware detection
FORENSIC_SIGNATURE_RULES = [
    {
        "rule_name": "WebShell_Generic_PHP",
        "category": "Web Shell",
        "severity": "Critical",
        "mitre_id": "T1505.003",
        "patterns": [
            re.compile(r'eval\s*\(\s*(base64_decode|\$_POST|\$_GET|\$_REQUEST)', re.IGNORECASE),
            re.compile(r'system\s*\(\s*\$_(POST|GET|REQUEST)', re.IGNORECASE),
            re.compile(r'passthru\s*\(', re.IGNORECASE),
            re.compile(r'shell_exec\s*\(', re.IGNORECASE),
            re.compile(r'assert\s*\(\s*\$_(POST|GET)', re.IGNORECASE),
        ]
    },
    {
        "rule_name": "Reverse_Shell_Indicators",
        "category": "Command and Control",
        "severity": "Critical",
        "mitre_id": "T1059",
        "patterns": [
            re.compile(r'/bin/sh\s+-i', re.IGNORECASE),
            re.compile(r'/bin/bash\s+-i', re.IGNORECASE),
            re.compile(r'nc\s+-[e|c]\s+/bin/', re.IGNORECASE),
            re.compile(r'powershell.*-nop.*-w\s+hidden.*-enc', re.IGNORECASE),
        ]
    },
    {
        "rule_name": "Credential_Dumping_Signatures",
        "category": "Credential Access",
        "severity": "High",
        "mitre_id": "T1003",
        "patterns": [
            re.compile(r'sekurlsa::logonpasswords', re.IGNORECASE),
            re.compile(r'lsass\.exe', re.IGNORECASE),
            re.compile(r'samlib\.dll', re.IGNORECASE),
            re.compile(r'mimikatz', re.IGNORECASE),
        ]
    },
    {
        "rule_name": "Ransomware_Marker_Notes",
        "category": "Impact",
        "severity": "Critical",
        "mitre_id": "T1486",
        "patterns": [
            re.compile(r'all your files have been encrypted', re.IGNORECASE),
            re.compile(r'pay\s+bitcoin\s+to\s+decrypt', re.IGNORECASE),
            re.compile(r'\.onion.*decrypt', re.IGNORECASE),
        ]
    }
]

def scan_file_signatures(file_path: str | Path) -> List[Dict[str, any]]:
    """Scan file content against forensic signature rules."""
    path = Path(file_path)
    with open(path, "rb") as f:
        content = f.read(2 * 1024 * 1024)

    text_content = content.decode("latin1", errors="ignore")
    matches = []

    for rule in FORENSIC_SIGNATURE_RULES:
        hit_patterns = []
        for pattern in rule["patterns"]:
            if pattern.search(text_content):
                hit_patterns.append(pattern.pattern)

        if hit_patterns:
            matches.append({
                "rule_name": rule["rule_name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "mitre_id": rule["mitre_id"],
                "matched_patterns_count": len(hit_patterns),
                "matched_signatures": hit_patterns
            })

    return matches

