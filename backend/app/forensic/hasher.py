import hashlib
from pathlib import Path
from typing import Dict, BinaryIO

CHUNK_SIZE = 64 * 1024  # 64 KB read buffer

def calculate_stream_hashes(stream: BinaryIO) -> Dict[str, str]:
    """Calculate SHA-256, SHA-1, and MD5 simultaneously over a byte stream."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    stream.seek(0)
    while chunk := stream.read(CHUNK_SIZE):
        sha256.update(chunk)
        sha1.update(chunk)
        md5.update(chunk)

    stream.seek(0)
    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }

def calculate_file_hashes(file_path: str | Path) -> Dict[str, str]:
    """Calculate cryptographic hashes of an on-disk file in streaming mode."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    with open(path, "rb") as f:
        return calculate_stream_hashes(f)

def verify_file_integrity(file_path: str | Path, baseline_sha256: str) -> Dict[str, any]:
    """Recalculate file hash and compare against recorded baseline."""
    current_hashes = calculate_file_hashes(file_path)
    is_match = current_hashes["sha256"].lower() == baseline_sha256.lower()

    return {
        "is_valid": is_match,
        "baseline_sha256": baseline_sha256,
        "current_sha256": current_hashes["sha256"],
        "sha1": current_hashes["sha1"],
        "md5": current_hashes["md5"],
        "status": "Verified" if is_match else "Compromised",
    }

