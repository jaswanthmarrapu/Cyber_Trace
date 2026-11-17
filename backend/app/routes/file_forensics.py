import base64
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, Body
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database.connection import get_db, SessionLocal
from app.models.evidence import Evidence
from app.models.forensic_result import ForensicResult
from app.forensic.file_analyzer import (
    process_file_forensics_upload,
    verify_evidence_hash_comparison,
    record_file_analysis_to_sqlite,
    record_verification_log_to_sqlite,
    get_file_forensic_history,
    get_file_verification_audit_trail,
    calculate_bytes_hashes,
    extract_file_metadata
)
from app.config import settings

router = APIRouter(prefix="/files", tags=["File Forensics & Evidence Integrity"])

class FileVerifyRequest(BaseModel):
    filename: str
    baseline_sha256: str
    original_md5: Optional[str] = None
    original_sha1: Optional[str] = None
    current_content_base64: Optional[str] = None
    current_content_text: Optional[str] = None
    verifier: Optional[str] = "Senior Forensic Examiner"

class DirectAnalysisRequest(BaseModel):
    filename: str
    content: str
    is_base64: Optional[bool] = False
    case_id: Optional[str] = "case-001"

@router.post("/analyze")
def analyze_uploaded_file_payload(payload: DirectAnalysisRequest):
    """
    Feature 1, 2, 3, 4, 5: Run passive static file forensics:
    - Calculates SHA-256 and MD5
    - Extracts file metadata and identifies size in bytes, KB, MB
    - Detects true file type from magic bytes
    - Persists initial baseline in SQLite
    - Zero execution safeguard
    """
    if payload.is_base64:
        try:
            data_bytes = base64.b64decode(payload.content)
        except Exception:
            data_bytes = payload.content.encode("latin1", errors="ignore")
    else:
        data_bytes = payload.content.encode("latin1", errors="ignore")

    res = process_file_forensics_upload(
        data_bytes=data_bytes,
        filename=payload.filename,
        db_path=str(settings.SQLITE_DB_PATH),
        case_id=payload.case_id
    )
    return res

@router.post("/upload")
def upload_file_forensics(
    file: UploadFile = File(...),
    case_id: str = Form("case-001"),
    evidence_id: Optional[str] = Form(None),
    examiner: str = Form("Senior Forensic Examiner")
):
    """Upload a file directly to compute hashes and enroll in forensics history."""
    try:
        content_bytes = file.file.read()
        res = process_file_forensics_upload(
            data_bytes=content_bytes,
            filename=file.filename,
            db_path=str(settings.SQLITE_DB_PATH),
            case_id=case_id,
            evidence_id=evidence_id,
            examiner=examiner
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File forensics processing error: {str(e)}")

@router.post("/verify")
def verify_file_integrity_endpoint(payload: FileVerifyRequest):
    """
    Features 6 & 7: Re-calculate hash and compare with original.
    Returns: original hash, current hash, integrity status (Verified vs Compromised), and verification timestamp.
    Logs verification attempt in SQLite audit trail.
    """
    if payload.current_content_base64:
        try:
            data_bytes = base64.b64decode(payload.current_content_base64)
        except Exception:
            data_bytes = payload.current_content_base64.encode("latin1", errors="ignore")
    elif payload.current_content_text is not None:
        data_bytes = payload.current_content_text.encode("latin1", errors="ignore")
    else:
        raise HTTPException(status_code=400, detail="Either current_content_base64 or current_content_text must be provided")

    verif_res = verify_evidence_hash_comparison(
        current_data_bytes=data_bytes,
        baseline_sha256=payload.baseline_sha256,
        original_md5=payload.original_md5,
        original_sha1=payload.original_sha1
    )

    # Record verification in SQLite audit log
    record_verification_log_to_sqlite(
        db_path=str(settings.SQLITE_DB_PATH),
        verification_result=verif_res,
        filename=payload.filename,
        verifier=payload.verifier
    )

    return verif_res

@router.get("/history")
def get_forensic_analysis_history(case_id: Optional[str] = None):
    """Feature 8: Display file analysis history."""
    return get_file_forensic_history(str(settings.SQLITE_DB_PATH), case_id=case_id)

@router.get("/verification-logs")
def get_verification_logs(filename: Optional[str] = None):
    """Retrieve all re-verification logs and audit trails."""
    return get_file_verification_audit_trail(str(settings.SQLITE_DB_PATH), filename=filename)
