from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database.connection import get_db, DB_PATH
from app.forensic.case_engine import (
    create_investigation_case,
    update_case_lifecycle_status,
    assign_case_investigator,
    add_case_investigation_note,
    link_suspicious_event_to_case,
    get_case_audit_history,
    generate_case_summary_dossier,
    generate_unique_case_number,
    init_case_management_tables,
    VALID_CASE_STATUSES
)
from app.models.case import Case

router = APIRouter(prefix="/cases", tags=["Case Management"])

class CaseCreateSchema(BaseModel):
    title: str
    description: Optional[str] = ""
    investigator_name: str = "Senior Forensic Examiner"
    severity: str = "Medium"
    incident_type: str = "Data Breach"
    case_number: Optional[str] = None

class CaseUpdateStatusSchema(BaseModel):
    status: str
    investigator_name: Optional[str] = "Senior Forensic Examiner"
    notes: Optional[str] = None

class CaseAssignInvestigatorSchema(BaseModel):
    investigator_name: str
    assigned_by: Optional[str] = "Lead Forensic Examiner"

class CaseNoteCreateSchema(BaseModel):
    author: str = "Senior Forensic Examiner"
    note_text: str

class CaseEventLinkSchema(BaseModel):
    event_id: str
    event_type: str
    event_summary: str
    linked_by: Optional[str] = "Senior Forensic Examiner"

@router.get("")
def list_cases(status: Optional[str] = None, db: Session = Depends(get_db)):
    """List all investigation cases with optional status filter."""
    init_case_management_tables(DB_PATH)
    query = db.query(Case)
    if status and status != "All":
        query = query.filter(Case.status == status)
    cases = query.order_by(Case.created_at.desc()).all()
    return cases

@router.post("")
def add_case(payload: CaseCreateSchema):
    """
    Feature 1, 2, 3, 4:
    Create a new investigation case, generating a unique case ID if none is supplied.
    """
    case = create_investigation_case(
        db_path=DB_PATH,
        title=payload.title,
        description=payload.description,
        investigator_name=payload.investigator_name,
        severity=payload.severity,
        incident_type=payload.incident_type,
        case_number=payload.case_number
    )
    return case

@router.get("/{case_id}")
def retrieve_case(case_id: str):
    """
    Feature 10:
    Retrieve comprehensive case summary with metrics, attached evidence, notes, and events.
    """
    try:
        summary = generate_case_summary_dossier(DB_PATH, case_id)
        return summary
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.patch("/{case_id}/status")
def change_case_status(case_id: str, payload: CaseUpdateStatusSchema):
    """
    Feature 7:
    Track and update case lifecycle status across:
    - Open
    - Under Investigation
    - Evidence Review
    - Completed
    Maintains an audit trail.
    """
    try:
        updated = update_case_lifecycle_status(
            db_path=DB_PATH,
            case_id=case_id,
            new_status=payload.status,
            investigator_name=payload.investigator_name,
            notes=payload.notes
        )
        return updated
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.patch("/{case_id}/assign")
def assign_investigator(case_id: str, payload: CaseAssignInvestigatorSchema):
    """
    Feature 4:
    Assign or reassign an investigator to a case.
    """
    try:
        assigned = assign_case_investigator(
            db_path=DB_PATH,
            case_id=case_id,
            new_investigator=payload.investigator_name,
            assigned_by=payload.assigned_by
        )
        return assigned
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/{case_id}/notes")
def add_note(case_id: str, payload: CaseNoteCreateSchema):
    """
    Feature 6:
    Add investigation notes to a case.
    """
    try:
        note = add_case_investigation_note(
            db_path=DB_PATH,
            case_id=case_id,
            author=payload.author,
            note_text=payload.note_text
        )
        return note
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/{case_id}/link-event")
def link_event(case_id: str, payload: CaseEventLinkSchema):
    """
    Feature 9:
    Link suspicious events (log alert, IOC, timeline node) to the case.
    """
    try:
        link = link_suspicious_event_to_case(
            db_path=DB_PATH,
            case_id=case_id,
            event_id=payload.event_id,
            event_type=payload.event_type,
            event_summary=payload.event_summary,
            linked_by=payload.linked_by
        )
        return link
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/{case_id}/audit-trail")
def get_audit_trail(case_id: str):
    """
    Feature 8 & Audit Trail requirement:
    Display complete chronological activity history for a case.
    """
    history = get_case_audit_history(DB_PATH, case_id)
    return {
        "case_id": case_id,
        "total_audit_events": len(history),
        "history": history
    }
