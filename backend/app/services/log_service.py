import json
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.log_event import LogEvent
from app.forensic.log_analyzer import execute_log_analysis_pipeline, DEFAULT_CONFIGURABLE_RULES

def ingest_and_parse_log_file(
    db: Session,
    case_id: str,
    file_content: str,
    filename: str,
    evidence_id: Optional[str] = None,
    custom_rules: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Ingest log file content, execute forensic detection pipeline, and persist records in SQLite.
    Returns full analysis summary including event statistics, reasons, and detection metrics.
    """
    result = execute_log_analysis_pipeline(
        content_text=file_content,
        case_id=case_id,
        rules=custom_rules,
        filename=filename
    )

    events_to_add = []
    for entry in result["events"]:
        # Parse timestamp or fallback
        ts_val = None
        if entry.get("timestamp"):
            try:
                ts_val = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
            except Exception:
                ts_val = datetime.now(timezone.utc)
        else:
            ts_val = datetime.now(timezone.utc)

        event = LogEvent(
            case_id=case_id,
            evidence_id=evidence_id,
            event_timestamp=ts_val,
            source_ip=entry.get("source_ip"),
            destination_ip="192.168.1.10",
            source_port=entry.get("source_port"),
            destination_port=80 if "HTTP" in entry.get("service", "") else 22,
            protocol="TCP",
            service=entry.get("service", "System"),
            event_type=entry.get("event_type", "SecurityEvent"),
            severity=entry.get("severity", "Low"),
            raw_log=entry.get("raw_log", ""),
            parsed_json=json.dumps(entry),
            is_threat=entry.get("is_suspicious", False),
            mitre_technique=entry.get("mitre_technique"),
            flag_reason=entry.get("flag_reason"),
            username=entry.get("username")
        )
        events_to_add.append(event)

    db.bulk_save_objects(events_to_add)
    db.commit()

    return {
        "count": len(events_to_add),
        "suspicious_count": result["suspicious_events_flagged"],
        "statistics": result["statistics"],
        "forensic_policy": result["forensic_policy"]
    }
