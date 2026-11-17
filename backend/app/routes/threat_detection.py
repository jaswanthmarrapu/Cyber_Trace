from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database.connection import get_db, DB_PATH
from app.models.log_event import LogEvent
from app.models.evidence import Evidence
from app.forensic.threat_engine import (
    evaluate_threat_rules,
    DEFAULT_THREAT_DETECTION_RULES,
    AUTHORIZED_MALICIOUS_HASH_INTEL,
    store_threat_alerts,
    get_stored_threat_alerts,
    init_threat_detection_tables
)

router = APIRouter(prefix="/threats", tags=["Threat Detection"])

class ThreatEvaluationRequest(BaseModel):
    case_id: Optional[str] = None
    custom_rules: Optional[Dict[str, Any]] = None

class ThreatRulesUpdateRequest(BaseModel):
    rules: Dict[str, Any]

@router.get("/rules")
def get_threat_rules():
    """Get active detection rules and configurable thresholds."""
    return {
        "rules": DEFAULT_THREAT_DETECTION_RULES,
        "authorized_hash_intel_signatures": len(AUTHORIZED_MALICIOUS_HASH_INTEL),
        "threat_subnets": DEFAULT_THREAT_DETECTION_RULES["known_suspicious_subnets"],
        "admin_usernames": DEFAULT_THREAT_DETECTION_RULES["admin_usernames"]
    }

@router.post("/rules")
def update_threat_rules(payload: ThreatRulesUpdateRequest):
    """Update configurable thresholds for threat detection rules."""
    updated = dict(DEFAULT_THREAT_DETECTION_RULES)
    updated.update(payload.rules)
    return {
        "status": "success",
        "message": "Threat detection rules updated successfully.",
        "rules": updated
    }

@router.post("/evaluate")
def evaluate_threats(payload: ThreatEvaluationRequest, db: Session = Depends(get_db)):
    """
    Run passive rule-based detection engine across logs and evidence vault files.
    Evaluates:
    - Multiple failed login attempts
    - Repeated suspicious IP connections
    - Unusual administrative login activity
    - Known malicious file hash matching against threat intelligence
    - Multi-stage attack chain combinations
    """
    init_threat_detection_tables(DB_PATH)
    case_id = payload.case_id or "GLOBAL"

    # Fetch relevant logs from database
    log_query = db.query(LogEvent)
    if payload.case_id:
        log_query = log_query.filter(LogEvent.case_id == payload.case_id)
    raw_logs = log_query.order_by(LogEvent.event_timestamp.asc()).limit(500).all()

    log_events = [
        {
            "id": l.id,
            "raw_log": l.raw_log,
            "source_ip": l.source_ip,
            "username": l.username,
            "timestamp": l.event_timestamp.isoformat() if l.event_timestamp else None,
            "severity": l.severity
        }
        for l in raw_logs
    ]

    # Fetch evidence files for hash matching
    ev_query = db.query(Evidence)
    if payload.case_id:
        ev_query = ev_query.filter(Evidence.case_id == payload.case_id)
    raw_evidence = ev_query.all()

    evidence_files = [
        {
            "evidence_id": e.evidence_id,
            "original_filename": e.original_filename,
            "sha256_hash": e.sha256_hash,
            "md5_hash": getattr(e, "md5_hash", None)
        }
        for e in raw_evidence
    ]

    # Run detection engine
    alerts = evaluate_threat_rules(
        log_events=log_events,
        evidence_files=evidence_files,
        custom_rules=payload.custom_rules
    )

    # Persist alerts to SQLite
    store_threat_alerts(DB_PATH, case_id=case_id, alerts=alerts)

    return {
        "status": "success",
        "case_id": case_id,
        "logs_evaluated": len(log_events),
        "evidence_files_evaluated": len(evidence_files),
        "alerts_count": len(alerts),
        "alerts": alerts
    }

@router.get("/alerts")
def get_alerts(case_id: Optional[str] = Query(None)):
    """Retrieve all threat alerts with mandatory forensic details."""
    init_threat_detection_tables(DB_PATH)
    alerts = get_stored_threat_alerts(DB_PATH, case_id=case_id)
    
    # Calculate severity breakdown
    severity_breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in alerts:
        sev = a.get("severity", "Low")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    return {
        "total_alerts": len(alerts),
        "severity_breakdown": severity_breakdown,
        "alerts": alerts
    }

@router.get("/detections")
def get_threat_detections(case_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Fetch flagged threat detections mapped to MITRE ATT&CK (legacy compatibility)."""
    query = db.query(LogEvent).filter(LogEvent.is_threat == True)
    if case_id:
        query = query.filter(LogEvent.case_id == case_id)

    threats = query.order_by(LogEvent.event_timestamp.desc()).limit(200).all()

    mitre_summary = {}
    for t in threats:
        tech = t.mitre_technique or "Uncategorized Threat"
        mitre_summary[tech] = mitre_summary.get(tech, 0) + 1

    return {
        "total_threats": len(threats),
        "mitre_matrix": mitre_summary,
        "threats": threats
    }
