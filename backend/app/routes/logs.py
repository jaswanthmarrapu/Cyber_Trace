from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, Body
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.log_event import LogEvent
from app.services.log_service import ingest_and_parse_log_file
from app.forensic.log_analyzer import DEFAULT_CONFIGURABLE_RULES, execute_log_analysis_pipeline

router = APIRouter(prefix="/logs", tags=["Log Analysis"])

@router.post("/upload")
def upload_log_file(
    case_id: str = Form(...),
    evidence_id: Optional[str] = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Upload and parse log file (CSV, Web access, Syslog/Auth, Windows Events JSON)."""
    try:
        content_bytes = file.file.read()
        content_text = content_bytes.decode("utf-8", errors="replace")
        summary = ingest_and_parse_log_file(
            db=db,
            case_id=case_id,
            file_content=content_text,
            filename=file.filename,
            evidence_id=evidence_id
        )
        return {
            "message": f"Successfully parsed and ingested {summary['count']} log events",
            "count": summary["count"],
            "suspicious_count": summary["suspicious_count"],
            "statistics": summary["statistics"],
            "forensic_policy": summary["forensic_policy"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log parsing error: {str(e)}")

@router.post("/analyze")
def analyze_log_stream(
    payload: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db)
):
    """
    Direct log analysis endpoint:
    Accepts log_text, case_id, optional filename and configurable detection rules.
    """
    log_text = payload.get("log_text", "")
    case_id = payload.get("case_id", "case-001")
    filename = payload.get("filename")
    rules = payload.get("rules")

    if not log_text.strip():
        raise HTTPException(status_code=400, detail="log_text parameter is required")

    try:
        summary = ingest_and_parse_log_file(
            db=db,
            case_id=case_id,
            file_content=log_text,
            filename=filename or "stream.log",
            custom_rules=rules
        )
        # Fetch newly inserted events
        events = db.query(LogEvent).filter(LogEvent.case_id == case_id).order_by(LogEvent.event_timestamp.desc()).limit(100).all()
        return {
            "total_lines_analyzed": summary["count"],
            "threats_detected": summary["suspicious_count"],
            "statistics": summary["statistics"],
            "parsed_events": [
                {
                    "id": ev.id,
                    "timestamp": ev.event_timestamp.isoformat() if ev.event_timestamp else None,
                    "source_ip": ev.source_ip,
                    "username": ev.username,
                    "service": ev.service,
                    "event_type": ev.event_type,
                    "severity": ev.severity,
                    "is_threat": ev.is_threat,
                    "mitre_technique": ev.mitre_technique,
                    "flag_reason": ev.flag_reason,
                    "raw_log": ev.raw_log
                }
                for ev in events
            ],
            "forensic_policy": summary["forensic_policy"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")

@router.get("/rules")
def get_detection_rules():
    """Retrieve currently active configurable detection rules."""
    return DEFAULT_CONFIGURABLE_RULES

@router.get("/summary")
def get_log_summary(case_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Retrieve statistical summary of analyzed logs."""
    query = db.query(LogEvent)
    if case_id:
        query = query.filter(LogEvent.case_id == case_id)

    events = query.all()
    from app.forensic.log_analyzer import generate_event_statistics
    dict_events = [
        {
            "source_ip": e.source_ip,
            "username": e.username or "N/A",
            "event_type": e.event_type,
            "severity": e.severity,
            "is_suspicious": e.is_threat
        }
        for e in events
    ]
    return generate_event_statistics(dict_events)

@router.get("/events")
def query_log_events(
    case_id: Optional[str] = None,
    is_threat: Optional[bool] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Query parsed log events with filters and pagination."""
    query = db.query(LogEvent)

    if case_id:
        query = query.filter(LogEvent.case_id == case_id)
    if is_threat is not None:
        query = query.filter(LogEvent.is_threat == is_threat)
    if severity:
        query = query.filter(LogEvent.severity == severity)
    if source_ip:
        query = query.filter(LogEvent.source_ip == source_ip)
    if search:
        query = query.filter(LogEvent.raw_log.ilike(f"%{search}%"))

    total = query.count()
    events = query.order_by(LogEvent.event_timestamp.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [
            {
                "id": ev.id,
                "timestamp": ev.event_timestamp.isoformat() if ev.event_timestamp else None,
                "source_ip": ev.source_ip,
                "username": ev.username,
                "service": ev.service,
                "event_type": ev.event_type,
                "severity": ev.severity,
                "is_threat": ev.is_threat,
                "mitre_technique": ev.mitre_technique,
                "flag_reason": ev.flag_reason,
                "raw_log": ev.raw_log
            }
            for ev in events
        ]
    }
