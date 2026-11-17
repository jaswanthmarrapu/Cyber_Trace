import re
import json
from datetime import datetime
from typing import List, Dict

# Regex patterns for various log formats
COMBINED_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

AUTH_LOG_REGEX = re.compile(
    r'^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<daemon>\w+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
)

def parse_web_log(lines: List[str]) -> List[Dict]:
    """Parse Apache/Nginx access log lines."""
    parsed_events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        match = COMBINED_LOG_REGEX.match(line)
        if match:
            data = match.groupdict()
            parsed_events.append({
                "source_ip": data["ip"],
                "timestamp_str": data["time"],
                "method": data["method"],
                "path": data["path"],
                "status_code": int(data["status"]),
                "user_agent": data.get("user_agent", ""),
                "service": "HTTP/Web",
                "raw_log": line
            })
        else:
            # Fallback simple extractor
            parsed_events.append({
                "source_ip": None,
                "timestamp_str": None,
                "service": "Unknown Web",
                "raw_log": line
            })
    return parsed_events

def parse_auth_log(lines: List[str]) -> List[Dict]:
    """Parse Linux auth.log / secure log lines."""
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        match = AUTH_LOG_REGEX.match(line)
        if match:
            data = match.groupdict()
            msg = data["message"]
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
            events.append({
                "source_ip": ip_match.group(0) if ip_match else None,
                "timestamp_str": data["time"],
                "host": data["host"],
                "daemon": data["daemon"],
                "service": data["daemon"],
                "message": msg,
                "raw_log": line
            })
        else:
            events.append({
                "source_ip": None,
                "service": "Auth",
                "raw_log": line
            })
    return events

def parse_windows_event_json(content: str) -> List[Dict]:
    """Parse exported Windows Event Log JSON array."""
    try:
        raw_items = json.loads(content)
        events = []
        for item in raw_items:
            msg = item.get("Message", "")
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
            events.append({
                "event_id": item.get("EventID"),
                "timestamp_str": item.get("TimeCreated"),
                "computer": item.get("Computer"),
                "severity": item.get("Severity", "Information"),
                "source_ip": ip_match.group(0) if ip_match else None,
                "service": f"WinEvent_{item.get('EventID')}",
                "message": msg,
                "raw_log": json.dumps(item)
            })
        return events
    except Exception:
        return []

