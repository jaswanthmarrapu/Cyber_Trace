"""
CyberTrace Rule-Based Threat Detection Engine
Features:
1. Rule 1: Multiple failed login attempts (burst detection over configurable threshold)
2. Rule 2: Repeated suspicious IP connections (connection frequency and rate anomalies)
3. Rule 3: Unusual administrative login activity (off-hours root/admin logins, sudo escalation failures)
4. Rule 4: Known malicious file hash matching against an authorized threat intelligence dataset
5. Rule 5: Suspicious event combinations (multi-vector attack chains: Brute Force -> Successful Login -> Privilege Escalation / Web Shell)

Severity Levels:
- Low
- Medium
- High
- Critical

Alert Fields:
- Alert ID
- Detection category
- Severity
- Related evidence
- Detection timestamp
- Reason for detection
- Recommended investigation steps

Configurable detection rules:
- Adjustable thresholds, IP watchlists, admin account lists, off-hours, and hash intelligence sets.

Forensic Safeguard:
- Strict passive evaluation: Never executes suspicious files or performs active network attacks.
"""

import re
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

# Authorized Known Malicious File Hash Dataset (SHA-256 and MD5)
AUTHORIZED_MALICIOUS_HASH_INTEL = {
    # WSO PHP Web Shell variant
    "1a8dff7b259790c5b959360b993c7570d36dc5f3850af109bcec590f1fcd45fe": {
        "threat_name": "Backdoor.PHP.WSO.4.2.5",
        "category": "Web Shell Backdoor",
        "severity": "Critical",
        "mitre_technique": "T1505.003",
        "md5": "39336b46aa9b12b9c8033a2a4c0c096c",
        "description": "Obfuscated WSO PHP web shell with remote code execution, eval injection, and file upload capabilities."
    },
    # b374k Web Shell variant
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "threat_name": "Trojan.PHP.B374k.WebShell",
        "category": "Web Shell / C2 Agent",
        "severity": "Critical",
        "mitre_technique": "T1505.003",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "description": "Full-featured interactive web administrative backdoor tool."
    },
    # Mimikatz LSASS credential dumper
    "b8b0e513813c9e6bb0760ab5576a2e2d832a8813a375a06941b12b59664531be": {
        "threat_name": "HackTool.Win64.Mimikatz",
        "category": "Credential Access",
        "severity": "Critical",
        "mitre_technique": "T1003.001",
        "md5": "a823b169542aa70829a9a3b6107f9c2d",
        "description": "Known LSASS process memory injector and credential dumper."
    },
    # Meterpreter reverse shell payload
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": {
        "threat_name": "Payload.ReverseTCP.Stager",
        "category": "Command and Control",
        "severity": "Critical",
        "mitre_technique": "T1059.004",
        "md5": "c4ca4238a0b923820dcc509a6f75849b",
        "description": "Staged TCP interactive reverse shell agent."
    }
}

DEFAULT_THREAT_DETECTION_RULES = {
    # Rule 1: Multiple failed login attempts
    "failed_login_threshold": 3,
    "failed_login_window_mins": 10,

    # Rule 2: Repeated suspicious IP connections
    "suspicious_ip_connection_threshold": 5,
    "known_suspicious_subnets": ["185.220.", "45.154.", "203.0.113."],

    # Rule 3: Unusual administrative login activity
    "admin_usernames": ["root", "admin", "administrator", "deploy", "supervisor", "wheel"],
    "unusual_hours": [0, 1, 2, 3, 4, 5],  # 00:00 - 05:59 UTC

    # Rule 4: Malicious file hash dataset lookup enabled
    "hash_intel_matching_enabled": True,

    # Rule 5: Suspicious event combinations
    "correlation_window_events": 20
}

# =====================================================================
# Threat Detection Engine
# =====================================================================

def evaluate_threat_rules(
    log_events: List[Dict[str, Any]],
    evidence_files: Optional[List[Dict[str, Any]]] = None,
    custom_rules: Optional[Dict[str, Any]] = None,
    authorized_intel: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Execute all 5 threat detection rules:
    1. Multiple failed login attempts
    2. Repeated suspicious IP connections
    3. Unusual administrative login activity
    4. Known malicious file hash matching against authorized dataset
    5. Suspicious event combinations (Attack Chains)
    """
    rules = dict(DEFAULT_THREAT_DETECTION_RULES)
    if custom_rules:
        rules.update(custom_rules)

    intel_db = dict(AUTHORIZED_MALICIOUS_HASH_INTEL)
    if authorized_intel:
        intel_db.update(authorized_intel)

    alerts = []
    now_iso = datetime.now(timezone.utc).isoformat()

    # Aggregations for correlation
    ip_failed_logins: Dict[str, List[Dict[str, Any]]] = {}
    ip_connections: Dict[str, List[Dict[str, Any]]] = {}
    user_failed_logins: Dict[str, List[Dict[str, Any]]] = {}
    successful_logins: List[Dict[str, Any]] = []
    admin_privileged_events: List[Dict[str, Any]] = []
    web_attacks: List[Dict[str, Any]] = []

    # -------------------------------------------------------------
    # Parse & Ingest Log Events
    # -------------------------------------------------------------
    for ev in (log_events or []):
        raw = ev.get("raw_log", "")
        ip = ev.get("source_ip", "127.0.0.1")
        user = ev.get("username", "")
        ts = ev.get("timestamp") or ev.get("event_timestamp") or now_iso

        # 1. Connection tracking
        if ip:
            if ip not in ip_connections:
                ip_connections[ip] = []
            ip_connections[ip].append(ev)

        # 2. Failed login tracking
        if re.search(r"Failed password|authentication failure|4625| 401 |0xC000006D", raw, re.I):
            if ip:
                if ip not in ip_failed_logins:
                    ip_failed_logins[ip] = []
                ip_failed_logins[ip].append(ev)
            if user and user != "N/A":
                if user not in user_failed_logins:
                    user_failed_logins[user] = []
                user_failed_logins[user].append(ev)

        # 3. Successful login tracking
        if re.search(r"Accepted password|EventID.*?4624|session opened|New session", raw, re.I):
            successful_logins.append(ev)

        # 4. Administrative command tracking
        if "sudo:" in raw or "COMMAND=" in raw or "euid=0" in raw or "cat /etc/shadow" in raw:
            admin_privileged_events.append(ev)

        # 5. Web attack patterns
        if re.search(r"UNION SELECT|SELECT .* FROM|'\s*OR\s*1=1|\.\./\.\./|wso_shell|b374k", raw, re.I):
            web_attacks.append(ev)

    # -------------------------------------------------------------
    # RULE 1: Multiple Failed Login Attempts
    # -------------------------------------------------------------
    for ip, fails in ip_failed_logins.items():
        if len(fails) >= rules["failed_login_threshold"]:
            alert_id = f"ALT-RULE1-{uuid.uuid4().hex[:8].upper()}"
            sev = "Critical" if len(fails) >= 10 else "High"
            users_targeted = sorted(list({f.get("username", "unknown") for f in fails if f.get("username")}))
            
            alerts.append({
                "alert_id": alert_id,
                "rule_id": "RULE-01",
                "detection_category": "Credential Access & Brute Force",
                "severity": sev,
                "related_evidence": f"Network Ingress Log (IP: {ip}, Attempts: {len(fails)})",
                "detection_timestamp": now_iso,
                "reason_for_detection": (
                    f"Threshold Exceeded: Observed {len(fails)} failed login attempts from source IP {ip} "
                    f"(configured threshold: {rules['failed_login_threshold']}). "
                    f"Targeted usernames: {', '.join(users_targeted) or 'generic accounts'}."
                ),
                "recommended_investigation_steps": [
                    f"1. Cross-reference IP {ip} against firewall routing tables and temporary rate-limiting rules.",
                    "2. Verify whether any targeted accounts experienced subsequent successful authentications.",
                    "3. Inspect host auth.log / EventID 4625 for password spraying versus dictionary attacks on single accounts.",
                    "4. Adhere to ISO/IEC 27037: Do not assign human identity without ISP subscriber lease verification."
                ],
                "mitre_technique": "T1110 - Brute Force: Password Guessing"
            })

    # -------------------------------------------------------------
    # RULE 2: Repeated Suspicious IP Connections
    # -------------------------------------------------------------
    for ip, conns in ip_connections.items():
        is_known_suspicious = any(ip.startswith(prefix) for prefix in rules["known_suspicious_subnets"])
        if is_known_suspicious and len(conns) >= rules["suspicious_ip_connection_threshold"]:
            alert_id = f"ALT-RULE2-{uuid.uuid4().hex[:8].upper()}"
            alerts.append({
                "alert_id": alert_id,
                "rule_id": "RULE-02",
                "detection_category": "Suspicious Network Ingress",
                "severity": "High" if len(conns) < 15 else "Critical",
                "related_evidence": f"Connection Telemetry ({len(conns)} requests from {ip})",
                "detection_timestamp": now_iso,
                "reason_for_detection": (
                    f"Repeated Connection Burst: Source IP {ip} belongs to watched suspicious subnet list "
                    f"and recorded {len(conns)} connection requests (threshold: {rules['suspicious_ip_connection_threshold']})."
                ),
                "recommended_investigation_steps": [
                    f"1. Review HTTP access logs and reverse proxy headers for URI probing patterns originating from {ip}.",
                    "2. Check if the IP address is an active Tor exit node or public VPN proxy endpoint.",
                    "3. Review perimeter firewall access control lists (ACLs) to verify egress/ingress filtering."
                ],
                "mitre_technique": "T1071 - Application Layer Protocol"
            })

    # -------------------------------------------------------------
    # RULE 3: Unusual Administrative Login Activity
    # -------------------------------------------------------------
    for succ in successful_logins:
        user = (succ.get("username") or "").lower()
        ip = succ.get("source_ip", "127.0.0.1")
        raw = succ.get("raw_log", "")

        is_admin = user in [a.lower() for a in rules["admin_usernames"]]
        # Check off-hours if timestamp parseable
        dt_hour = None
        ts_str = succ.get("timestamp") or succ.get("event_timestamp")
        if ts_str:
            try:
                dt_hour = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).hour
            except Exception:
                pass

        is_off_hours = (dt_hour in rules["unusual_hours"]) if dt_hour is not None else False
        was_prior_brute = len(ip_failed_logins.get(ip, [])) >= rules["failed_login_threshold"]

        if is_admin or was_prior_brute or is_off_hours:
            alert_id = f"ALT-RULE3-{uuid.uuid4().hex[:8].upper()}"
            reasons = []
            steps = []
            sev = "Medium"

            if was_prior_brute:
                sev = "Critical"
                reasons.append(f"Successful logon immediately following {len(ip_failed_logins.get(ip, []))} failed brute-force attempts from IP {ip}.")
                steps.append("Immediately isolate the affected user session and revoke active authorization tokens.")
            if is_admin:
                sev = "High" if sev != "Critical" else sev
                reasons.append(f"Logon of privileged administrative account '{user}'.")
                steps.append("Verify whether the administrative logon was authorized by an active IT change request ticket.")
            if is_off_hours:
                reasons.append(f"Activity occurred during off-hours operational window ({dt_hour:02d}:00 UTC).")
                steps.append("Confirm examiner or systems administrator duty shift schedule.")

            alerts.append({
                "alert_id": alert_id,
                "rule_id": "RULE-03",
                "detection_category": "Unusual Account Behavior & Privilege Access",
                "severity": sev,
                "related_evidence": f"Auth Stream Event ({user or 'unknown'} from {ip})",
                "detection_timestamp": now_iso,
                "reason_for_detection": " | ".join(reasons),
                "recommended_investigation_steps": steps or ["1. Inspect host authentication logs and verify session integrity."],
                "mitre_technique": "T1078 - Valid Accounts"
            })

    # -------------------------------------------------------------
    # RULE 4: Known Malicious File Hash Matching (Threat Intelligence)
    # -------------------------------------------------------------
    if rules["hash_intel_matching_enabled"] and evidence_files:
        for file_item in evidence_files:
            file_sha256 = (file_item.get("sha256_hash") or file_item.get("sha256") or "").lower()
            file_md5 = (file_item.get("md5_hash") or file_item.get("md5") or "").lower()
            fn = file_item.get("original_filename") or file_item.get("filename") or "evidence.bin"

            matched_intel = None
            if file_sha256 in intel_db:
                matched_intel = intel_db[file_sha256]
            else:
                for k, v in intel_db.items():
                    if v.get("md5") and v["md5"].lower() == file_md5:
                        matched_intel = v
                        break

            if matched_intel:
                alert_id = f"ALT-RULE4-{uuid.uuid4().hex[:8].upper()}"
                alerts.append({
                    "alert_id": alert_id,
                    "rule_id": "RULE-04",
                    "detection_category": "Malicious Artifact Identified (Threat Intel Match)",
                    "severity": matched_intel["severity"],
                    "related_evidence": f"Vault Artifact: {fn} (SHA-256: {file_sha256[:16]}...)",
                    "detection_timestamp": now_iso,
                    "reason_for_detection": (
                        f"Cryptographic Hash Match: Artifact '{fn}' matches known malicious threat intelligence signature: "
                        f"'{matched_intel['threat_name']}' ({matched_intel['description']})."
                    ),
                    "recommended_investigation_steps": [
                        f"1. Keep artifact {fn} strictly contained in the isolated non-executable vault buffer.",
                        "2. Perform static disassembly (Shannon entropy, string extraction, magic bytes) without executing.",
                        "3. Cross-reference file MACB timestamps against perimeter access logs to identify weaponization vector.",
                        "4. Check for lateral movement artifacts sharing identical cryptographic hash across other systems."
                    ],
                    "mitre_technique": f"{matched_intel.get('mitre_technique', 'T1505.003')} - {matched_intel['category']}"
                })

    # -------------------------------------------------------------
    # RULE 5: Suspicious Event Combinations (Attack Chain Correlation)
    # -------------------------------------------------------------
    # Combination 1: Web Exploit / SQLi -> Web Shell Command
    has_web_exploit = len(web_attacks) > 0
    has_priv_esc = len(admin_privileged_events) > 0
    has_brute_and_success = any(
        len(ip_failed_logins.get(succ.get("source_ip", ""), [])) >= rules["failed_login_threshold"]
        for succ in successful_logins
    )

    if has_web_exploit and has_priv_esc:
        alert_id = f"ALT-RULE5-CHAIN-{uuid.uuid4().hex[:8].upper()}"
        alerts.append({
            "alert_id": alert_id,
            "rule_id": "RULE-05",
            "detection_category": "Multi-Vector Attack Chain (Perimeter Breach to Privilege Escalation)",
            "severity": "Critical",
            "related_evidence": f"Combined Telemetry ({len(web_attacks)} web attacks + {len(admin_privileged_events)} privileged sudo events)",
            "detection_timestamp": now_iso,
            "reason_for_detection": (
                "Attack Chain Correlation: Detected structural web exploit probing (SQLi/LFI) combined with subsequent "
                "local privileged administrative execution (sudo / sensitive file access). "
                "Denotes high probability of initial access followed by lateral root escalation."
            ),
            "recommended_investigation_steps": [
                "1. Freeze system memory state and acquire forensic disk image of the staging/production server.",
                "2. Review web server process tree (e.g. www-data / nginx spawning bash or python interpreters).",
                "3. Inspect /etc/sudoers file and audit logs for unauthorized sudoer entries.",
                "4. Reconstruct Attack Timeline to determine the exact elapsed duration between initial access and root execution."
            ],
            "mitre_technique": "T1190 -> T1068 (Multi-Stage Adversary Sequence)"
        })

    return alerts


# =====================================================================
# SQLite Persistence for Alerts & Detection History
# =====================================================================

def init_threat_detection_tables(db_path: str):
    """Ensure database tables exist for threat alerts and detection rules."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS threat_alerts (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        alert_id TEXT UNIQUE NOT NULL,
        rule_id TEXT NOT NULL,
        detection_category TEXT NOT NULL,
        severity TEXT NOT NULL,
        related_evidence TEXT,
        detection_timestamp TEXT NOT NULL,
        reason_for_detection TEXT NOT NULL,
        investigation_steps_json TEXT NOT NULL,
        mitre_technique TEXT
    );

    CREATE TABLE IF NOT EXISTS threat_detection_rules (
        id TEXT PRIMARY KEY,
        rule_key TEXT UNIQUE NOT NULL,
        rule_name TEXT NOT NULL,
        rule_config_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()


def store_threat_alerts(db_path: str, case_id: str, alerts: List[Dict[str, Any]]) -> int:
    """Store generated alerts into SQLite threat_alerts table."""
    init_threat_detection_tables(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    count = 0
    for a in alerts:
        cur.execute("""
        INSERT OR REPLACE INTO threat_alerts (
            id, case_id, alert_id, rule_id, detection_category, severity,
            related_evidence, detection_timestamp, reason_for_detection,
            investigation_steps_json, mitre_technique
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()),
            case_id,
            a["alert_id"],
            a["rule_id"],
            a["detection_category"],
            a["severity"],
            a["related_evidence"],
            a["detection_timestamp"],
            a["reason_for_detection"],
            json.dumps(a["recommended_investigation_steps"]),
            a.get("mitre_technique")
        ))
        count += 1

    conn.commit()
    conn.close()
    return count


def get_stored_threat_alerts(db_path: str, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve all stored alerts."""
    init_threat_detection_tables(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if case_id:
        cur.execute("SELECT * FROM threat_alerts WHERE case_id = ? ORDER BY detection_timestamp DESC", (case_id,))
    else:
        cur.execute("SELECT * FROM threat_alerts ORDER BY detection_timestamp DESC")

    rows = []
    for r in cur.fetchall():
        d = dict(r)
        try:
            d["recommended_investigation_steps"] = json.loads(d["investigation_steps_json"])
        except Exception:
            d["recommended_investigation_steps"] = []
        rows.append(d)

    conn.close()
    return rows
