from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database.connection import get_db, DB_PATH
from app.models.log_event import LogEvent
from app.models.evidence import Evidence
from app.forensic.timeline_engine import (
    extract_and_normalize_timeline_events,
    identify_suspicious_event_sequences,
    filter_timeline_events,
    generate_timeline_pdf_content,
    store_timeline_events,
    get_timeline_events_from_db
)

router = APIRouter(prefix="/timeline", tags=["Attack Timeline Reconstruction"])

class ReconstructRequest(BaseModel):
    case_id: Optional[str] = "case-001"

@router.get("/{case_id}")
def get_timeline(
    case_id: str,
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    evidence_source: Optional[str] = Query(None)
):
    """
    Retrieve chronologically ordered incident timeline for a case with optional filters.
    (Requirements 4 & 8)
    """
    events = get_timeline_events_from_db(DB_PATH, case_id)
    if not events:
        # If no events yet stored for this case, synthesize from logs
        return {"total_events": 0, "events": [], "inferred_sequences": []}

    # Filter events if parameters provided
    filtered = filter_timeline_events(
        events,
        start_date=start_date,
        end_date=end_date,
        severity=severity,
        evidence_source=evidence_source
    )

    sequences = identify_suspicious_event_sequences(events)

    return {
        "case_id": case_id,
        "total_events": len(events),
        "filtered_count": len(filtered),
        "events": filtered,
        "inferred_sequences": sequences
    }

@router.post("/{case_id}/reconstruct")
def auto_reconstruct_timeline(case_id: str, payload: Optional[ReconstructRequest] = None, db: Session = Depends(get_db)):
    """
    Collect events from analysed logs and evidence vault files, normalize timestamps into UTC,
    sort chronologically, group related events, identify suspicious attack sequences,
    and persist into SQLite. (Requirements 1, 2, 3, 4, 5, 6, 9)
    """
    target_case = case_id or (payload.case_id if payload else "case-001")

    # Fetch logs from DB
    log_query = db.query(LogEvent)
    if target_case and target_case != "GLOBAL":
        log_query = log_query.filter(LogEvent.case_id == target_case)
    raw_logs = log_query.order_by(LogEvent.event_timestamp.asc()).all()

    log_events = [
        {
            "id": l.id,
            "raw_log": l.raw_log,
            "source_ip": l.source_ip,
            "destination_ip": l.destination_ip,
            "username": l.username,
            "timestamp": l.event_timestamp.isoformat() if l.event_timestamp else None,
            "event_type": l.event_type,
            "service": l.service,
            "severity": l.severity,
            "is_threat": l.is_threat,
            "mitre_technique": l.mitre_technique,
            "case_id": l.case_id
        }
        for l in raw_logs
    ]

    # Fetch evidence vault records
    ev_query = db.query(Evidence)
    if target_case and target_case != "GLOBAL":
        ev_query = ev_query.filter(Evidence.case_id == target_case)
    raw_evidence = ev_query.all()

    evidence_items = [
        {
            "evidence_id": e.evidence_id,
            "original_filename": e.original_filename,
            "sha256_hash": e.sha256_hash,
            "upload_timestamp": e.upload_timestamp.isoformat() if e.upload_timestamp else None,
            "investigator_name": e.investigator_name
        }
        for e in raw_evidence
    ]

    # Run Timeline Engine
    timeline = extract_and_normalize_timeline_events(
        log_events=log_events,
        evidence_vault_items=evidence_items,
        case_id=target_case
    )

    # Persist to database
    store_timeline_events(DB_PATH, case_id=target_case, events=timeline)

    # Identify suspicious sequences
    sequences = identify_suspicious_event_sequences(timeline)

    return {
        "status": "success",
        "case_id": target_case,
        "total_events": len(timeline),
        "inferred_sequences_count": len(sequences),
        "timeline": timeline,
        "inferred_sequences": sequences
    }

@router.get("/{case_id}/export/pdf")
def export_timeline_pdf(case_id: str):
    """
    Export the timeline report in PDF format. (Requirement 10)
    """
    events = get_timeline_events_from_db(DB_PATH, case_id)
    sequences = identify_suspicious_event_sequences(events)

    case_info = {
        "case_id": case_id,
        "investigator_name": "Senior Forensic Examiner"
    }

    pdf_bytes = generate_timeline_pdf_content(
        case_info=case_info,
        timeline_events=events,
        suspicious_sequences=sequences
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=Attack_Timeline_{case_id}.pdf"}
    )
