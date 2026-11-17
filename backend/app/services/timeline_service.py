from typing import List
from sqlalchemy.orm import Session
from app.models.timeline_event import TimelineEvent
from app.models.log_event import LogEvent

def get_case_timeline(db: Session, case_id: str) -> List[TimelineEvent]:
    """Retrieve full chronological attack timeline for a case."""
    return db.query(TimelineEvent).filter(
        TimelineEvent.case_id == case_id
    ).order_by(TimelineEvent.event_timestamp.asc()).all()

def add_manual_timeline_event(db: Session, case_id: str, event_data: dict) -> TimelineEvent:
    """Manually add an investigator verified milestone to timeline."""
    event = TimelineEvent(case_id=case_id, **event_data)
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def reconstruct_timeline_from_logs(db: Session, case_id: str) -> int:
    """Analyze high-severity threat logs and compile into unified attack timeline."""
    threat_logs = db.query(LogEvent).filter(
        LogEvent.case_id == case_id,
        LogEvent.is_threat == True
    ).order_by(LogEvent.event_timestamp.asc()).all()

    created_count = 0
    for log in threat_logs:
        category = "Execution"
        if "Brute Force" in log.event_type:
            category = "Initial Access / Credential Guessing"
        elif "SQL" in log.event_type or "Traversal" in log.event_type:
            category = "Exploitation of Public Application"
        elif "Privilege" in log.event_type:
            category = "Privilege Escalation"
        elif "Log Clearing" in log.event_type:
            category = "Defense Evasion"

        timeline_item = TimelineEvent(
            case_id=case_id,
            event_timestamp=log.event_timestamp,
            event_source=f"Log Analysis ({log.service})",
            event_category=category,
            actor=log.source_ip or "Remote Threat Actor",
            target=log.destination_ip or "Forensic Server",
            description=f"Detected: {log.event_type} - {log.raw_log[:150]}",
            mitre_tactic=log.mitre_technique,
            confidence_level="Verified"
        )
        db.add(timeline_item)
        created_count += 1

    db.commit()
    return created_count

