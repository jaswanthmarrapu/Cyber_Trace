from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.evidence import Evidence
from app.models.chain_of_custody import ChainOfCustody
from app.services.evidence_service import ingest_evidence, verify_evidence_by_id
from app.schemas.evidence_schema import ChainOfCustodyCreateSchema

router = APIRouter(prefix="/evidence", tags=["Evidence & Chain of Custody"])

@router.get("", summary="List Evidence Artifacts")
def list_evidence(
    case_id: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieve all digital evidence records registered to a case with cryptographic hashes."""
    query = db.query(Evidence)
    if case_id:
        query = query.filter(Evidence.case_id == case_id)
    if search:
        query = query.filter(
            (Evidence.original_filename.ilike(f"%{search}%")) |
            (Evidence.evidence_number.ilike(f"%{search}%")) |
            (Evidence.sha256_hash.ilike(f"%{search}%"))
        )
    return query.order_by(Evidence.acquired_at.desc()).all()

@router.post("/upload", summary="Ingest Digital Evidence", status_code=status.HTTP_201_CREATED)
def upload_evidence(
    case_id: str = Form(..., description="Target Case ID"),
    acquired_by: str = Form("Senior Forensic Examiner", description="Name of investigator"),
    source_device: str = Form("Target Host / Server", description="Physical or logical origin device"),
    description: Optional[str] = Form(None, description="Forensic context and acquisition notes"),
    file: UploadFile = File(..., description="Authorized evidence file"),
    db: Session = Depends(get_db)
):
    """
    Securely upload and enroll digital evidence:
    - Enforces extension allowlist & file size boundaries
    - Stores file with random UUID in non-executable vault
    - Calculates SHA-256, SHA-1, and MD5 immediately on stream
    - Creates initial Chain-of-Custody record
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename missing from upload payload")

    try:
        evidence = ingest_evidence(
            db=db,
            case_id=case_id,
            file_obj=file.file,
            original_filename=file.filename,
            acquired_by=acquired_by,
            source_device=source_device,
            description=description
        )
        return evidence
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evidence vault storage failure: {str(e)}")

@router.get("/{evidence_id}", summary="Get Evidence Dossier")
def get_evidence_detail(evidence_id: str, db: Session = Depends(get_db)):
    """Retrieve detailed metadata and custody records for a specific evidence artifact."""
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence item not found")
    return evidence

@router.post("/{evidence_id}/verify", summary="Verify Evidence Integrity")
def verify_evidence(
    evidence_id: str,
    verifier_name: str = Form("Senior Forensic Examiner"),
    db: Session = Depends(get_db)
):
    """
    Recalculate cryptographic hash directly from vault file to verify integrity against acquisition baseline.
    Logs verification attempt permanently in Chain of Custody.
    """
    try:
        verification = verify_evidence_by_id(db, evidence_id, verifier_name)
        return verification
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failure: {str(e)}")

@router.get("/{evidence_id}/chain-of-custody", summary="Get Chain of Custody Audit Log")
def get_chain_of_custody(evidence_id: str, db: Session = Depends(get_db)):
    """Retrieve the immutable chronological chain-of-custody log for an evidence item."""
    coc_entries = db.query(ChainOfCustody).filter(
        ChainOfCustody.evidence_id == evidence_id
    ).order_by(ChainOfCustody.timestamp.asc()).all()
    return coc_entries

@router.post("/{evidence_id}/chain-of-custody", summary="Log Custody Transfer", status_code=status.HTTP_201_CREATED)
def add_chain_of_custody_entry(
    evidence_id: str,
    payload: ChainOfCustodyCreateSchema,
    db: Session = Depends(get_db)
):
    """Log an evidence transfer, analysis, checkout, or court export in the Chain of Custody."""
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    entry = ChainOfCustody(
        evidence_id=evidence_id,
        action=payload.action,
        performed_by=payload.performed_by,
        reason=payload.reason,
        location=payload.location,
        verified_hash=evidence.sha256_hash,
        notes=payload.notes
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
