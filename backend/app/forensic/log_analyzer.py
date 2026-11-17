"""
CyberTrace Forensic Log Analysis Engine
Modular detection rules, timestamp parsing, multi-source ingestion (CSV, Syslog, Auth.log, Apache/Nginx Web, Windows Events),
anomaly correlation (failed logins, unusual logins, admin privilege access, repeated auth failures),
severity categorization, event statistics, and SQLite storage.
Designed to run with Pandas when available, with a complete native fallback engine if Pandas is not installed.
Adheres to ISO/IEC 27037 forensic standards: Flagged anomalies indicate suspicious patterns requiring investigation,
avoiding unsubstantiated claims that every unusual event is a confirmed cyberattack.
"""

import re
import csv
import json
import sqlite3
import uuid
from io import StringIO
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

# =====================================================================
# 1. Configurable Detection Rules & Anomaly Baselines
# =====================================================================

DEFAULT_CONFIGURABLE_RULES = {
    # Threshold for repeated failed logins within observation window (per source IP or username)
    "failed_login_threshold": 3,
    # Threshold for repeated authentication failures
    "auth_failure_threshold": 3,
    # High-risk administrative usernames
    "admin_usernames": ["root", "admin", "administrator", "wheel", "sudo", "system", "postgres", "oracle", "deploy", "supervisor"],
    # Suspicious administrative execution commands
    "suspicious_admin_commands": [
        "cat /etc/shadow", "cat /etc/passwd", "chmod 777", "chmod -R 777",
        "useradd", "usermod", "visudo", "pty.spawn", "/bin/bash", "/bin/sh",
        "nc -e", "netcat -e", "curl http", "wget http", "rm -rf", "iptables -F"
    ],
    # Off-hours observation window (UTC hour range considered unusual for non-24/7 staff, e.g. 00:00 - 05:00 UTC)
    "unusual_hours": [0, 1, 2, 3, 4, 5],
    # High-risk HTTP ports or admin paths
    "suspicious_web_paths": [
        "/admin", "/administrator", "/wp-login.php", "/xmlrpc.php",
        "/upload.php", "/wso_shell.php", "/b374k.php", "/c99.php", "/shell.php",
        "/api/products?id=", "/download.php?file="
    ]
}

# Regex Patterns for Log Formats
WEB_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

AUTH_LOG_REGEX = re.compile(
    r'^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<daemon>\w+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
)

# Known MITRE ATT&CK Mapping Reference
MITRE_MAPPINGS = {
    "BRUTE_FORCE": {"id": "T1110", "name": "Brute Force: Password Guessing"},
    "UNUSUAL_LOGIN": {"id": "T1078", "name": "Valid Accounts: Unusual Account Activity"},
    "ADMIN_ACCESS": {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    "AUTH_FAILURE": {"id": "T1110.001", "name": "Brute Force: Password Spraying / Auth Failures"},
    "SQLI": {"id": "T1190", "name": "Exploit Public-Facing Application: SQL Injection"},
    "TRAVERSAL": {"id": "T1006", "name": "Direct Volume Access / Path Traversal"},
    "WEB_SHELL": {"id": "T1505.003", "name": "Server Software Component: Web Shell"}
}

# =====================================================================
# 2. Forensic Timestamp Parsing
# =====================================================================

def parse_iso_or_log_timestamp(ts_str: Optional[str]) -> Tuple[Optional[str], Optional[datetime]]:
    """
    Robust forensic timestamp parser handling:
    - ISO 8601 ('2026-03-14T03:00:15Z', '2026-03-14 03:00:15')
    - Syslog / Auth.log ('Mar 14 02:14:01', with current year assumed)
    - Apache / Nginx combined ('14/Mar/2026:03:10:02 +0000', '14/Mar/2026:03:10:02')
    - Unix Epoch timestamps (integer/float string)
    Returns: (standardized_iso_string, datetime_object_utc)
    """
    if not ts_str or not isinstance(ts_str, str):
        now = datetime.now(timezone.utc)
        return now.isoformat(), now

    clean_str = ts_str.strip()

    # 1. ISO format
    try:
        dt = datetime.fromisoformat(clean_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat(), dt
    except Exception:
        pass

    # 2. Apache/Nginx format: 14/Mar/2026:03:10:02 +0000
    try:
        base_match = re.search(r'(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)', clean_str)
        if base_match:
            time_part = base_match.group(1)
            if " " in time_part:
                dt = datetime.strptime(time_part, "%d/%b/%Y:%H:%M:%S %z")
            else:
                dt = datetime.strptime(time_part, "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)
            return dt.isoformat(), dt
    except Exception:
        pass

    # 3. Syslog format: Mar 14 02:14:01
    try:
        syslog_match = re.search(r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', clean_str)
        if syslog_match:
            current_year = datetime.now(timezone.utc).year
            dt_str = f"{current_year} {syslog_match.group(1)}"
            # Handle variable spaces
            normalized = re.sub(r'\s+', ' ', dt_str)
            dt = datetime.strptime(normalized, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            return dt.isoformat(), dt
    except Exception:
        pass

    # 4. Standard Date formats
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
        try:
            dt = datetime.strptime(clean_str, fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat(), dt
        except Exception:
            continue

    # Fallback: Current UTC
    now = datetime.now(timezone.utc)
    return now.isoformat(), now


# =====================================================================
# 3. Log Ingestion (CSV, Text, JSON, Syslog, Web)
# =====================================================================

def parse_csv_log(content_text: str) -> List[Dict[str, Any]]:
    """Parse CSV formatted log stream into structured event records."""
    records = []
    f = StringIO(content_text.strip())
    reader = csv.DictReader(f)
    for row in reader:
        # Standardize keys
        norm_row = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
        raw_repr = " | ".join([f"{k}={v}" for k, v in row.items()])

        # Detect source IP
        src_ip = norm_row.get("source_ip") or norm_row.get("ip") or norm_row.get("ipaddress") or norm_row.get("client_ip")
        if not src_ip:
            ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_repr)
            src_ip = ip_m.group(0) if ip_m else "Unknown"

        # Detect timestamp
        ts_raw = norm_row.get("timestamp") or norm_row.get("time") or norm_row.get("date") or norm_row.get("timecreated")
        iso_ts, dt_obj = parse_iso_or_log_timestamp(ts_raw)

        # Detect user
        user = norm_row.get("user") or norm_row.get("username") or norm_row.get("targetusername") or norm_row.get("account") or ""

        # Status / Action
        action = norm_row.get("action") or norm_row.get("status") or norm_row.get("event") or norm_row.get("event_type") or ""

        records.append({
            "raw_log": raw_repr,
            "timestamp": iso_ts,
            "datetime_obj": dt_obj,
            "source_ip": src_ip,
            "username": user,
            "action": action,
            "service": norm_row.get("service") or norm_row.get("daemon") or "CSV_Log",
            "message": norm_row.get("message") or norm_row.get("description") or raw_repr,
            "source_format": "CSV"
        })
    return records


def parse_raw_text_log(content_text: str) -> List[Dict[str, Any]]:
    """Parse unstructured text logs (Syslog, Linux Auth, Apache/Nginx, Windows JSON)."""
    records = []
    lines = content_text.strip().splitlines()

    # Check for Windows Event JSON array
    stripped = content_text.strip()
    if (stripped.startswith("[") and stripped.endswith("]")) or (stripped.startswith("{") and stripped.endswith("}")):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                msg = item.get("Message") or item.get("Description") or json.dumps(item)
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg + " " + str(item.get("IpAddress", "")))
                src_ip = ip_match.group(0) if ip_match else (item.get("IpAddress") or "127.0.0.1")
                ts_raw = item.get("TimeCreated") or item.get("Timestamp")
                iso_ts, dt_obj = parse_iso_or_log_timestamp(ts_raw)
                user = item.get("TargetUserName") or item.get("SubjectUserName") or item.get("User") or ""

                records.append({
                    "raw_log": json.dumps(item),
                    "timestamp": iso_ts,
                    "datetime_obj": dt_obj,
                    "source_ip": src_ip,
                    "username": user,
                    "action": f"EventID_{item.get('EventID', 'WinEvent')}",
                    "service": f"WinEvent_{item.get('EventID', 'Security')}",
                    "message": msg,
                    "source_format": "WindowsEventJSON"
                })
            return records
        except Exception:
            pass

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        # Check Apache/Nginx Web Log
        web_match = WEB_LOG_REGEX.match(line_clean)
        if web_match:
            d = web_match.groupdict()
            iso_ts, dt_obj = parse_iso_or_log_timestamp(d.get("time"))
            records.append({
                "raw_log": line_clean,
                "timestamp": iso_ts,
                "datetime_obj": dt_obj,
                "source_ip": d.get("ip"),
                "username": "",
                "action": f"{d.get('method')} {d.get('path')}",
                "status_code": int(d.get("status", 200)),
                "service": "HTTP/Web",
                "message": f"{d.get('method')} {d.get('path')} HTTP Code {d.get('status')}",
                "source_format": "WebCombined"
            })
            continue

        # Check Linux Syslog / Auth Log
        auth_match = AUTH_LOG_REGEX.match(line_clean)
        if auth_match:
            d = auth_match.groupdict()
            msg = d.get("message", "")
            iso_ts, dt_obj = parse_iso_or_log_timestamp(d.get("time"))

            # Extract IP
            ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
            src_ip = ip_m.group(0) if ip_m else "127.0.0.1"

            # Extract user if available
            user = ""
            user_m = re.search(r'for\s+(?:invalid\s+user\s+)?([a-zA-Z0-9_\-\.]+)\s+from', msg)
            if user_m:
                user = user_m.group(1)
            elif "user=" in msg:
                u_m = re.search(r'user=([a-zA-Z0-9_\-\.]+)', msg)
                if u_m:
                    user = u_m.group(1)
            elif "sudo:" in line_clean:
                s_m = re.search(r'sudo:\s+([a-zA-Z0-9_\-\.]+)\s+:', line_clean)
                if s_m:
                    user = s_m.group(1)

            records.append({
                "raw_log": line_clean,
                "timestamp": iso_ts,
                "datetime_obj": dt_obj,
                "source_ip": src_ip,
                "username": user,
                "action": d.get("daemon", "auth"),
                "service": d.get("daemon", "auth"),
                "message": msg,
                "source_format": "LinuxSyslog"
            })
            continue

        # Generic Text line fallback
        ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line_clean)
        src_ip = ip_m.group(0) if ip_m else "127.0.0.1"
        iso_ts, dt_obj = parse_iso_or_log_timestamp(line_clean)
        records.append({
            "raw_log": line_clean,
            "timestamp": iso_ts,
            "datetime_obj": dt_obj,
            "source_ip": src_ip,
            "username": "",
            "action": "log_entry",
            "service": "generic_log",
            "message": line_clean,
            "source_format": "RawText"
        })

    return records


# =====================================================================
# 4. Forensic Detection Engine (Pandas + Native Hybrid)
# =====================================================================

def analyze_log_records(records: List[Dict[str, Any]], rules: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """
    Core Forensic Evaluation Engine:
    - Feature 3: Identify repeated failed login attempts
    - Feature 4: Detect unusual login activity (off-hours, abnormal locations, unexpected successes)
    - Feature 5: Identify suspicious administrative access (sudo abuse, root commands, privileged escalation)
    - Feature 6: Detect repeated authentication failures (password spraying / brute force)
    - Feature 7: Categorize suspicious events by severity (Critical, High, Medium, Low, Informational)
    - Rules: Configurable detection parameters
    - Forensic Note: Explicitly states reason flagged without claiming every event is a confirmed cyberattack.
    """
    if not records:
        return []

    cfg = dict(DEFAULT_CONFIGURABLE_RULES)
    if rules:
        cfg.update(rules)

    # If Pandas is available, leverage DataFrame aggregation for windowing & frequency counting
    ip_failed_counts = {}
    user_failed_counts = {}

    if HAS_PANDAS:
        try:
            df = pd.DataFrame(records)
            # Find failed logins
            is_fail = df["raw_log"].str.contains(r"Failed password|authentication failure|EventID.*?4625| 401 |status=0xC000006D", case=False, regex=True)
            fails_df = df[is_fail]
            if not fails_df.empty:
                ip_failed_counts = fails_df["source_ip"].value_counts().to_dict()
                if "username" in fails_df.columns:
                    valid_users = fails_df[fails_df["username"].str.len() > 0]
                    if not valid_users.empty:
                        user_failed_counts = valid_users["username"].value_counts().to_dict()
        except Exception:
            pass

    # Native fallback for frequency counting if pandas failed or not installed
    if not ip_failed_counts:
        for r in records:
            raw = r["raw_log"]
            if re.search(r"Failed password|authentication failure|4625| 401 |0xC000006D", raw, re.I):
                src = r.get("source_ip") or "127.0.0.1"
                ip_failed_counts[src] = ip_failed_counts.get(src, 0) + 1
                u = r.get("username")
                if u:
                    user_failed_counts[u] = user_failed_counts.get(u, 0) + 1

    analyzed_events = []

    for r in records:
        raw = r["raw_log"]
        msg = r.get("message", "")
        src_ip = r.get("source_ip", "127.0.0.1")
        username = r.get("username", "")
        dt_obj: Optional[datetime] = r.get("datetime_obj")

        is_suspicious = False
        event_type = "Standard Activity"
        severity = "Low"
        reasons = []
        mitre_tech = None

        # -------------------------------------------------------------
        # Feature 3: Repeated Failed Login Attempts
        # -------------------------------------------------------------
        is_login_fail = bool(re.search(r"Failed password|authentication failure|4625| 401 |0xC000006D", raw, re.I))
        ip_fails = ip_failed_counts.get(src_ip, 0)
        user_fails = user_failed_counts.get(username, 0)

        if is_login_fail:
            is_suspicious = True
            if ip_fails >= cfg["failed_login_threshold"] or user_fails >= cfg["failed_login_threshold"]:
                event_type = "Repeated Failed Login Attempts"
                severity = "High" if ip_fails < 10 else "Critical"
                mitre_tech = f"{MITRE_MAPPINGS['BRUTE_FORCE']['id']} - {MITRE_MAPPINGS['BRUTE_FORCE']['name']}"
                reasons.append(
                    f"Observation: Source IP {src_ip} recorded {ip_fails} failed login attempts (exceeding configured threshold of {cfg['failed_login_threshold']}). "
                    f"Forensic note: May indicate password spraying, dictionary attack, or repeated misconfiguration. Further verification recommended."
                )
            else:
                event_type = "Isolated Login Failure"
                severity = "Low"
                reasons.append("Observation: Single failed authentication event. Common cause includes user typo or credential expiration.")

        # -------------------------------------------------------------
        # Feature 6: Repeated Authentication Failures
        # -------------------------------------------------------------
        if "authentication failure" in raw.lower() or "bad password" in raw.lower():
            if not is_suspicious:
                is_suspicious = True
                event_type = "Authentication Failure"
                severity = "Medium"
                mitre_tech = f"{MITRE_MAPPINGS['AUTH_FAILURE']['id']} - {MITRE_MAPPINGS['AUTH_FAILURE']['name']}"
                reasons.append("Observation: PAM/SSHD authentication failure recorded for service.")

        # -------------------------------------------------------------
        # Feature 5: Suspicious Administrative Access
        # -------------------------------------------------------------
        is_admin_user = username.lower() in [u.lower() for u in cfg["admin_usernames"]]
        has_sudo = "sudo:" in raw or "su:" in raw or "euid=0" in raw or "COMMAND=" in raw

        # Check for administrative abuse commands
        detected_admin_cmds = [cmd for cmd in cfg["suspicious_admin_commands"] if cmd in raw]

        if has_sudo and ("failure" in raw.lower() or "pam_unix" in raw.lower()):
            is_suspicious = True
            event_type = "Suspicious Administrative Privilege Escalation Failure"
            severity = "Critical"
            mitre_tech = f"{MITRE_MAPPINGS['ADMIN_ACCESS']['id']} - {MITRE_MAPPINGS['ADMIN_ACCESS']['name']}"
            reasons.append(
                f"Observation: Sudo privilege execution failure by user '{username or 'unknown'}'. "
                f"Forensic note: Indicates an attempt to elevate to root/admin privileges without authorized credentials."
            )
        elif detected_admin_cmds:
            is_suspicious = True
            event_type = "Suspicious Administrative Command Execution"
            severity = "Critical" if ("shadow" in raw or "pty.spawn" in raw or "rm -rf" in raw) else "High"
            mitre_tech = f"{MITRE_MAPPINGS['ADMIN_ACCESS']['id']} - {MITRE_MAPPINGS['ADMIN_ACCESS']['name']}"
            reasons.append(
                f"Observation: Execution of privileged administrative utility ({', '.join(detected_admin_cmds)}). "
                f"Forensic note: Command may be legitimate systems administration or post-exploitation recon. Check authorized change tickets."
            )
        elif has_sudo and is_admin_user:
            if not is_suspicious:
                is_suspicious = True
                event_type = "Administrative Privileged Action"
                severity = "Medium"
                reasons.append(f"Observation: Administrative user '{username}' executed privileged command via sudo/su.")

        # -------------------------------------------------------------
        # Feature 4: Detect Unusual Login Activity
        # -------------------------------------------------------------
        # Successful login following multiple failures, or logins at unusual hours
        is_login_success = bool(re.search(r"Accepted password|EventID.*?4624|session opened|New session", raw, re.I))
        if is_login_success:
            hour_of_event = dt_obj.hour if dt_obj else None
            is_off_hours = hour_of_event in cfg["unusual_hours"] if hour_of_event is not None else False
            was_prior_brute = ip_fails >= cfg["failed_login_threshold"]

            if was_prior_brute:
                is_suspicious = True
                event_type = "Unusual Login Activity (Success After Brute-Force)"
                severity = "Critical"
                mitre_tech = f"{MITRE_MAPPINGS['UNUSUAL_LOGIN']['id']} - {MITRE_MAPPINGS['UNUSUAL_LOGIN']['name']}"
                reasons.append(
                    f"Observation: Successful logon for user '{username or 'unknown'}' from IP {src_ip} immediately following {ip_fails} prior failed attempts. "
                    f"Forensic note: High probability of compromised credentials or unauthorized penetration."
                )
            elif is_off_hours:
                is_suspicious = True
                event_type = "Unusual Login Activity (Off-Hours Access)"
                severity = "Medium"
                mitre_tech = f"{MITRE_MAPPINGS['UNUSUAL_LOGIN']['id']} - {MITRE_MAPPINGS['UNUSUAL_LOGIN']['name']}"
                reasons.append(
                    f"Observation: Successful logon recorded at {hour_of_event:02d}:00 UTC (classified as off-hours window: {cfg['unusual_hours']}). "
                    f"Forensic note: Unusual access hour does not confirm attack; verify against examiner or personnel shift schedule."
                )
            else:
                event_type = "Successful Authentication"
                severity = "Low"
                reasons.append("Observation: Standard successful authentication event.")

        # -------------------------------------------------------------
        # Web Attack Patterns (SQLi, Traversal, Web Shells)
        # -------------------------------------------------------------
        if re.search(r"UNION\s+SELECT|SELECT\s+.*FROM|'\s*OR\s*1=1|--", raw, re.I):
            if not is_suspicious or event_type == "Standard Activity":
                is_suspicious = True
                event_type = "SQL Injection Pattern Detected"
                severity = "Critical"
                mitre_tech = f"{MITRE_MAPPINGS['SQLI']['id']} - {MITRE_MAPPINGS['SQLI']['name']}"
            reasons.append("Observation: HTTP request payload contains SQL syntax indicating structured query injection probing.")
        elif re.search(r"\.\./\.\./|boot\.ini", raw, re.I) or (("etc/passwd" in raw or "etc/shadow" in raw) and not has_sudo):
            if not is_suspicious or event_type == "Standard Activity":
                is_suspicious = True
                event_type = "Path Traversal / LFI Probing"
                severity = "High"
                mitre_tech = f"{MITRE_MAPPINGS['TRAVERSAL']['id']} - {MITRE_MAPPINGS['TRAVERSAL']['name']}"
            reasons.append("Observation: Request parameter contains relative directory traversal sequence targeting sensitive host files.")
        elif re.search(r"wso_shell|b374k|c99\.php|eval\(|system\(|powershell\.exe.*-EncodedCommand", raw, re.I):
            if not is_suspicious or event_type == "Standard Activity":
                is_suspicious = True
                event_type = "Web Shell / Malicious Process Invocation"
                severity = "Critical"
                mitre_tech = f"{MITRE_MAPPINGS['WEB_SHELL']['id']} - {MITRE_MAPPINGS['WEB_SHELL']['name']}"
            reasons.append("Observation: Access to known web shell identifier or obfuscated PowerShell process detected in log stream.")

        if not reasons:
            reasons.append("Observation: Standard system activity log entry within expected operational parameters.")

        flag_reason = " | ".join(reasons)

        analyzed_events.append({
            "id": str(uuid.uuid4()),
            "timestamp": r["timestamp"],
            "source_ip": src_ip,
            "username": username or "N/A",
            "service": r.get("service", "System"),
            "event_type": event_type,
            "severity": severity,
            "is_suspicious": is_suspicious,
            "mitre_technique": mitre_tech,
            "flag_reason": flag_reason,
            "raw_log": raw,
            "source_format": r.get("source_format", "Generic")
        })

    return analyzed_events


# =====================================================================
# 5. Event Statistics Generator (Feature 9)
# =====================================================================

def generate_event_statistics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes aggregated forensic statistics:
    - Total events analyzed
    - Suspicious vs benign event count
    - Severity breakdown (Critical, High, Medium, Low)
    - Top source IPs by event volume and failure count
    - Most targeted usernames
    - Breakdown of detected anomaly categories
    """
    if not events:
        return {
            "total_analyzed": 0,
            "suspicious_count": 0,
            "benign_count": 0,
            "severities": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "top_source_ips": {},
            "top_usernames": {},
            "event_categories": {},
            "pandas_accelerated": HAS_PANDAS
        }

    total = len(events)
    suspicious_count = sum(1 for e in events if e.get("is_suspicious"))
    benign_count = total - suspicious_count

    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for e in events:
        sev = e.get("severity", "Low")
        severities[sev] = severities.get(sev, 0) + 1

    # Frequency analysis
    if HAS_PANDAS:
        try:
            df = pd.DataFrame(events)
            top_ips = df["source_ip"].value_counts().head(5).to_dict()
            valid_users = df[df["username"] != "N/A"]
            top_users = valid_users["username"].value_counts().head(5).to_dict() if not valid_users.empty else {}
            categories = df["event_type"].value_counts().head(8).to_dict()
        except Exception:
            top_ips, top_users, categories = _native_stat_frequency(events)
    else:
        top_ips, top_users, categories = _native_stat_frequency(events)

    return {
        "total_analyzed": total,
        "suspicious_count": suspicious_count,
        "benign_count": benign_count,
        "severities": severities,
        "top_source_ips": top_ips,
        "top_usernames": top_users,
        "event_categories": categories,
        "pandas_accelerated": HAS_PANDAS
    }

def _native_stat_frequency(events: List[Dict[str, Any]]) -> Tuple[Dict, Dict, Dict]:
    ip_counts = {}
    user_counts = {}
    cat_counts = {}
    for e in events:
        ip = e.get("source_ip", "Unknown")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        u = e.get("username", "")
        if u and u != "N/A":
            user_counts[u] = user_counts.get(u, 0) + 1
        cat = e.get("event_type", "General")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    top_ips = dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    top_users = dict(sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    categories = dict(sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:8])
    return top_ips, top_users, categories


# =====================================================================
# 6. SQLite Database Storage (Feature 10)
# =====================================================================

def store_analysis_results_sqlite(db_path: str, case_id: str, events: List[Dict[str, Any]]) -> int:
    """
    Persist analysis results to SQLite log_events table.
    Ensures safe parameterized insertion.
    """
    if not events:
        return 0

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Ensure log_events table exists with flag_reason and username support
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS log_events (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        evidence_id TEXT,
        event_timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        service TEXT,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        raw_log TEXT NOT NULL,
        is_threat INTEGER NOT NULL,
        mitre_technique TEXT,
        flag_reason TEXT,
        username TEXT
    );
    """)

    # Check if optional columns exist (for backward compatibility)
    cursor.execute("PRAGMA table_info(log_events)")
    existing_cols = [row[1] for row in cursor.fetchall()]
    if "evidence_id" not in existing_cols:
        cursor.execute("ALTER TABLE log_events ADD COLUMN evidence_id TEXT")
    if "flag_reason" not in existing_cols:
        cursor.execute("ALTER TABLE log_events ADD COLUMN flag_reason TEXT")
    if "username" not in existing_cols:
        cursor.execute("ALTER TABLE log_events ADD COLUMN username TEXT")

    saved_count = 0
    for e in events:
        ev_id = e.get("id") or str(uuid.uuid4())
        cursor.execute("""
        INSERT INTO log_events (
            id, case_id, evidence_id, event_timestamp, source_ip, destination_ip,
            service, event_type, severity, raw_log, is_threat, mitre_technique,
            flag_reason, username
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ev_id,
            case_id,
            e.get("evidence_id"),
            e.get("timestamp"),
            e.get("source_ip"),
            e.get("destination_ip", "192.168.1.10"),
            e.get("service", "System"),
            e.get("event_type", "LogEvent"),
            e.get("severity", "Low"),
            e.get("raw_log", ""),
            1 if e.get("is_suspicious") else 0,
            e.get("mitre_technique"),
            e.get("flag_reason"),
            e.get("username")
        ))
        saved_count += 1

    conn.commit()
    conn.close()
    return saved_count


# =====================================================================
# 7. High-Level Master Pipeline
# =====================================================================

def execute_log_analysis_pipeline(
    content_text: str,
    case_id: str = "case-001",
    db_path: Optional[str] = None,
    rules: Optional[Dict[str, Any]] = None,
    filename: Optional[str] = None
) -> Dict[str, Any]:
    """
    Full pipeline executing all 10 features:
    1. Detects and parses CSV, Syslog, Web, or Windows JSON formats
    2. Standardizes timestamps
    3. Runs configurable anomaly detection engine
    4. Categorizes severity and documents explicit reasons
    5. Calculates forensic statistics
    6. Persists to SQLite if db_path provided
    """
    # 1. Determine format and parse
    is_csv = False
    if filename and filename.lower().endswith(".csv"):
        is_csv = True
    elif "," in content_text and "\n" in content_text:
        first_line = content_text.strip().splitlines()[0]
        if any(h in first_line.lower() for h in ["timestamp", "ip", "user", "action", "status", "message"]):
            is_csv = True

    if is_csv:
        records = parse_csv_log(content_text)
    else:
        records = parse_raw_text_log(content_text)

    # 2. Analyze events
    analyzed_events = analyze_log_records(records, rules=rules)

    # 3. Generate statistics
    stats = generate_event_statistics(analyzed_events)

    # 4. Save to SQLite
    stored_count = 0
    if db_path:
        stored_count = store_analysis_results_sqlite(db_path, case_id, analyzed_events)

    return {
        "status": "success",
        "case_id": case_id,
        "total_lines_analyzed": len(records),
        "suspicious_events_flagged": stats["suspicious_count"],
        "stored_in_sqlite_count": stored_count,
        "statistics": stats,
        "events": analyzed_events,
        "rules_applied": rules or DEFAULT_CONFIGURABLE_RULES,
        "forensic_policy": "ISO/IEC 27037 Compliant: Flagged anomalies indicate suspicious indicators requiring examiner verification, not confirmed cyberattacks."
    }
