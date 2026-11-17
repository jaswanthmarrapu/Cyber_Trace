from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.ip_record import IPRecord
from app.models.timeline_event import TimelineEvent
from app.models.log_event import LogEvent
from app.services.ip_service import investigate_ip_address, extract_and_analyze_ips_from_log
from app.forensic.ip_analyzer import get_related_timeline_events_for_ip

router = APIRouter(prefix="/ip", tags=["IP Investigation"])

class IPInvestigateRequest(BaseModel):
    ip_address: str
    case_id: Optional[str] = "case-001"
    enable_public_intel: Optional[bool] = True

class IPExtractRequest(BaseModel):
    log_text: str
    case_id: Optional[str] = "case-001"

@router.post("/investigate")
def investigate_ip(payload: IPInvestigateRequest, db: Session = Depends(get_db)):
    """
    Manually investigate an IP address.
    Strictly separates:
    - Observed information (scope, validation, PTR)
    - Reputation-based information (country, ASN, ISP, abuse score)
    Applies ISO/IEC 27037 attribution safeguard.
    """
    result = investigate_ip_address(
        ip_str=payload.ip_address,
        enable_public_intel=payload.enable_public_intel
    )
    if not result.get("is_valid", False):
        raise HTTPException(status_code=400, detail=result.get("error", "Invalid IP address"))

    # Persist in SQLite IP investigation history
    obs = result.get("observed_information", {})
    rep = result.get("reputation_information", {})

    record = IPRecord(
        case_id=payload.case_id,
        ip_address=result["ip_address"],
        ip_type=obs.get("scope", "Public IPv4"),
        country=rep.get("country"),
        country_code=rep.get("country_code"),
        city=rep.get("city"),
        asn=rep.get("asn"),
        isp=rep.get("isp"),
        abuse_confidence_score=rep.get("abuse_confidence_score", 0),
        reverse_dns=obs.get("reverse_dns"),
        attribution_caveat=result.get("forensic_attribution_safeguard")
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # Fetch related timeline/log events
    related_events = []
    # 1. Timeline events
    tl_events = db.query(TimelineEvent).filter(
        (TimelineEvent.actor.ilike(f"%{result['ip_address']}%")) |
        (TimelineEvent.target.ilike(f"%{result['ip_address']}%")) |
        (TimelineEvent.description.ilike(f"%{result['ip_address']}%"))
    ).all()
    for t in tl_events:
        related_events.append({
            "id": t.id,
            "timestamp": t.event_timestamp,
            "source": t.event_source,
            "category": t.event_category,
            "actor": t.actor,
            "target": t.target,
            "description": t.description,
            "confidence": t.confidence_level
        })

    # 2. Log events
    log_evs = db.query(LogEvent).filter(
        (LogEvent.source_ip == result['ip_address']) |
        (LogEvent.raw_log.ilike(f"%{result['ip_address']}%"))
    ).order_by(LogEvent.event_timestamp.desc()).limit(15).all()
    for l in log_evs:
        related_events.append({
            "id": l.id,
            "timestamp": l.event_timestamp.isoformat() if l.event_timestamp else None,
            "source": f"Log ({l.service})",
            "category": l.event_type,
            "actor": l.source_ip,
            "target": l.destination_ip,
            "description": l.flag_reason or l.raw_log,
            "confidence": "Empirical (Observed in Log)"
        })

    result["related_timeline_events"] = related_events
    result["history_record_id"] = record.id
    return result

@router.post("/extract-from-log")
def extract_ips_from_log_endpoint(payload: IPExtractRequest):
    """
    Feature 1, 4 & 5: Extract all IP addresses from uploaded log content,
    validate IPv4, classify scope, and calculate connection attempts and failed login counts.
    """
    if not payload.log_text.strip():
        raise HTTPException(status_code=400, detail="log_text is required")
    return extract_and_analyze_ips_from_log(payload.log_text)

@router.get("/history")
def list_investigated_ips(case_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Feature 6: Display IP investigation history from SQLite."""
    query = db.query(IPRecord)
    if case_id:
        query = query.filter(IPRecord.case_id == case_id)
    records = query.order_by(IPRecord.investigated_at.desc()).all()
    return [
        {
            "id": r.id,
            "case_id": r.case_id,
            "ip_address": r.ip_address,
            "ip_type": r.ip_type,
            "country": r.country,
            "country_code": r.country_code,
            "city": r.city,
            "asn": r.asn,
            "isp": r.isp,
            "abuse_confidence_score": r.abuse_confidence_score,
            "reverse_dns": r.reverse_dns,
            "attribution_caveat": r.attribution_caveat,
            "investigated_at": r.investigated_at.isoformat() if r.investigated_at else None
        }
        for r in records
    ]

@router.get("/{ip_address}/related-events")
def get_ip_related_events(ip_address: str, db: Session = Depends(get_db)):
    """Feature 7: Show related timeline and log events for an IP."""
    events = []
    # Timeline
    tl = db.query(TimelineEvent).filter(
        (TimelineEvent.actor.ilike(f"%{ip_address}%")) |
        (TimelineEvent.target.ilike(f"%{ip_address}%"))
    ).all()
    for t in tl:
        events.append({
            "id": t.id,
            "timestamp": t.event_timestamp,
            "source": t.event_source,
            "category": t.event_category,
            "actor": t.actor,
            "target": t.target,
            "description": t.description,
            "confidence": t.confidence_level
        })

    # Logs
    logs = db.query(LogEvent).filter(
        (LogEvent.source_ip == ip_address) |
        (LogEvent.raw_log.ilike(f"%{ip_address}%"))
    ).limit(20).all()
    for l in logs:
        events.append({
            "id": l.id,
            "timestamp": l.event_timestamp.isoformat() if l.event_timestamp else None,
            "source": f"Log Stream ({l.service})",
            "category": l.event_type,
            "actor": l.source_ip,
            "target": l.destination_ip,
            "description": l.flag_reason or l.raw_log,
            "confidence": "Empirical (Observed in Log)"
        })

    return {"ip_address": ip_address, "total_related_events": len(events), "events": events}
