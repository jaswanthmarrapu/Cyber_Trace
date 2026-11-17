import os
import re
import uuid
from pathlib import Path
from app.config import settings

# Base upload and report storage paths driven by central Settings
UPLOADS_DIR = settings.UPLOAD_DIR
REPORTS_DIR = settings.REPORTS_DIR

UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB threshold for web uploads

# Allowed extensions for evidence ingestion
ALLOWED_EXTENSIONS = {
    "log", "txt", "evtx", "json", "csv", "pcap", "pcapng",
    "bin", "dat", "dump", "raw", "img", "mem", "dll", "exe",
    "pdf", "png", "jpg", "jpeg", "zip", "tar", "gz"
}

def sanitize_filename(filename: str) -> str:
    """Sanitize original user-supplied filename to prevent directory traversal or unsafe chars."""
    basename = os.path.basename(filename)
    clean_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', basename)
    return clean_name or "unnamed_evidence.bin"

def generate_secure_storage_path(original_filename: str) -> tuple[str, Path]:
    """Generate a random UUID stored filename to completely isolate execution risk on disk."""
    sanitized = sanitize_filename(original_filename)
    extension = sanitized.rsplit(".", 1)[-1].lower() if "." in sanitized else "bin"
    safe_uuid_name = f"{uuid.uuid4().hex}.{extension}.vault"
    stored_path = UPLOADS_DIR / safe_uuid_name
    return safe_uuid_name, stored_path

def validate_file_size(size_bytes: int) -> bool:
    """Verify file does not exceed maximum allowable threshold."""
    return 0 < size_bytes <= MAX_FILE_SIZE_BYTES

