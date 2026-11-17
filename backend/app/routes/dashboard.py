from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.log_event import LogEvent
from app.models.timeline_event import TimelineEvent

router = APIRouter(prefix="/dashboard", tags=["Dashboard & Telemetry"])

@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Fetch high-level forensic metrics and attack telemetry."""
    total_cases = db.query(Case).count()
    active_cases = db.query(Case).filter(Case.status.in_(["Open", "Investigating"])).count()
    total_evidence = db.query(Evidence).count()
    verified_evidence = db.query(Evidence).filter(Evidence.integrity_status == "Verified").count()
    compromised_evidence = db.query(Evidence).filter(Evidence.integrity_status == "Compromised").count()
    total_threats = db.query(LogEvent).filter(LogEvent.is_threat == True).count()
    total_timeline_events = db.query(TimelineEvent).count()

    # Recent cases
    recent_cases = db.query(Case).order_by(Case.created_at.desc()).limit(5).all()

    # Severity distribution
    critical_threats = db.query(LogEvent).filter(LogEvent.severity == "Critical").count()
    high_threats = db.query(LogEvent).filter(LogEvent.severity == "High").count()
    medium_threats = db.query(LogEvent).filter(LogEvent.severity == "Medium").count()
    low_threats = db.query(LogEvent).filter(LogEvent.severity == "Low").count()

    return {
        "metrics": {
            "total_cases": total_cases,
            "active_cases": active_cases,
            "total_evidence": total_evidence,
            "verified_evidence": verified_evidence,
            "compromised_evidence": compromised_evidence,
            "total_threats": total_threats,
            "total_timeline_events": total_timeline_events,
        },
        "severity_distribution": {
            "Critical": critical_threats,
            "High": high_threats,
            "Medium": medium_threats,
            "Low": low_threats,
        },
        "recent_cases": [
            {
                "id": c.id,
                "case_number": c.case_number,
                "title": c.title,
                "status": c.status,
                "severity": c.severity,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in recent_cases
        ]
    }

