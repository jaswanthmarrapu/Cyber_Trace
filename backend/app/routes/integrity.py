from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from app.forensic.hasher import calculate_stream_hashes

router = APIRouter(prefix="/integrity", tags=["Evidence Integrity Verification"])

@router.post("/verify-file")
def quick_hash_check(
    expected_sha256: str = Form(""),
    file: UploadFile = File(...)
):
    """Calculate SHA-256, SHA-1, and MD5 on demand and optionally check against expected hash."""
    hashes = calculate_stream_hashes(file.file)
    expected_clean = expected_sha256.strip().lower()
    
    is_match = None
    if expected_clean:
        is_match = (hashes["sha256"].lower() == expected_clean)

    return {
        "filename": file.filename,
        "sha256": hashes["sha256"],
        "sha1": hashes["sha1"],
        "md5": hashes["md5"],
        "matches_expected": is_match,
        "integrity_status": "Verified (Match)" if is_match is True else ("Compromised (Mismatch)" if is_match is False else "Calculated")
    }

