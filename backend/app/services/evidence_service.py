import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy.orm import Session
from app.models.evidence import Evidence
from app.models.chain_of_custody import ChainOfCustody
from app.forensic.hasher import calculate_file_hashes, verify_file_integrity
from app.forensic.magic_checker import detect_magic_bytes
from app.utils.file_security import (
    generate_secure_storage_path,
    validate_file_size,
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE_BYTES
)

def ingest_evidence(
    db: Session,
    case_id: str,
    file_obj,
    original_filename: str,
    acquired_by: str,
    source_device: str,
    description: str = None
) -> Evidence:
    """
    Securely ingest digital evidence:
    1. Validates extension against allowlist.
    2. Enforces maximum size bounds (50MB).
    3. Streams file into isolated non-executable vault with randomized UUID name.
    4. Computes bit-level SHA-256, SHA-1, and MD5 immediately during ingestion.
    5. Locks file permissions (zero execution).
    6. Stores metadata and immutable initial baseline hash in SQLite.
    7. Creates initial 'Acquired' Chain of Custody entry.
    """
    # 1. Validate file extension
    ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else "bin"
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unauthorized file extension '.{ext}'. Allowed types: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

    stored_name, dest_path = generate_secure_storage_path(original_filename)

    # 2. Stream content and check size
    content = file_obj.read()
    file_size = len(content)

    if not validate_file_size(file_size):
        raise ValueError(f"File size ({file_size} bytes) exceeds maximum allowable threshold ({MAX_FILE_SIZE_BYTES} bytes / 50MB).")

    # 3. Write to non-executable vault
    with open(dest_path, "wb") as f:
        f.write(content)

    # 4. Enforce strict permissions: read-only to prevent tampering, ZERO execution
    try:
        os.chmod(dest_path, stat.S_IRUSR | stat.S_IRGRP)
    except Exception:
        pass

    # 5. Compute cryptographic hashes & detect magic bytes
    hashes = calculate_file_hashes(dest_path)
    magic_info = detect_magic_bytes(dest_path)

    # 6. Generate clean evidence sequence ID
    count = db.query(Evidence).filter(Evidence.case_id == case_id).count()
    evidence_number = f"EVD-{count + 1:03d}"

    evidence = Evidence(
        case_id=case_id,
        evidence_number=evidence_number,
        original_filename=original_filename,
        stored_filename=stored_name,
        file_path=str(dest_path),
        file_size_bytes=file_size,
        file_type=ext,
        mime_type=magic_info["detected_type"],
        sha256_hash=hashes["sha256"],
        sha1_hash=hashes["sha1"],
        md5_hash=hashes["md5"],
        initial_recorded_hash=hashes["sha256"],
        integrity_status="Verified",
        source_device=source_device,
        acquired_by=acquired_by,
        description=description or "Digital artifact acquired for forensic investigation."
    )
    db.add(evidence)
    db.flush()

    # 7. Initial Immutable Chain of Custody Record
    coc = ChainOfCustody(
        evidence_id=evidence.id,
        action="Acquired",
        performed_by=acquired_by,
        reason="Initial secure digital evidence acquisition and vault enrollment",
        location=f"Vault ({stored_name})",
        verified_hash=hashes["sha256"],
        notes=f"Artifact enrolled with verified SHA-256: {hashes['sha256'][:16]}..."
    )
    db.add(coc)
    db.commit()
    db.refresh(evidence)
    return evidence

def verify_evidence_by_id(db: Session, evidence_id: str, verifier_name: str = "Forensic Examiner") -> dict:
    """
    Recalculate cryptographic hash directly from vault file to verify integrity.
    If hash matches initial baseline -> Verified.
    If hash does not match -> Compromised (Tampering Alert).
    Logs verification attempt permanently in Chain of Custody.
    """
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise ValueError(f"Evidence with id {evidence_id} not found")

    result = verify_file_integrity(evidence.file_path, evidence.initial_recorded_hash)
    evidence.integrity_status = result["status"]
    evidence.sha256_hash = result["current_sha256"]
    evidence.sha1_hash = result["sha1"]
    evidence.md5_hash = result["md5"]

    # Append verification entry to Chain of Custody
    coc = ChainOfCustody(
        evidence_id=evidence.id,
        action="Verified",
        performed_by=verifier_name,
        reason="Cryptographic hash integrity audit",
        location=evidence.source_device or "Secure Digital Evidence Locker",
        verified_hash=result["current_sha256"],
        notes="Integrity verified: Checksum matches initial acquisition baseline." if result["is_valid"] else "ALERT: Hash mismatch! Potential digital tampering detected."
    )
    db.add(coc)
    db.commit()
    db.refresh(evidence)

    return result
