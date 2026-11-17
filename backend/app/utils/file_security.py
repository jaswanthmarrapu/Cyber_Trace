import os
import re
import uuid
import logging
from pathlib import Path
from app.config import settings

logger = logging.getLogger("cybertrace.file_security")

# Dynamic directory resolution without module import-time crashes
def get_uploads_dir() -> Path:
    """Retrieve and safely ensure the active writable upload storage directory."""
    d = settings.UPLOAD_DIR
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        logger.warning(f"Storage directory warning: {err}")
    return d

def get_reports_dir() -> Path:
    """Retrieve and safely ensure the active writable reports storage directory."""
    d = settings.REPORTS_DIR
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        logger.warning(f"Storage directory warning: {err}")
    return d

# Transparent Path Proxy providing backwards compatibility without import-time side effects
class _StoragePathProxy:
    def __init__(self, getter):
        self._getter = getter
    def __truediv__(self, other):
        return self._getter() / other
    def __fspath__(self):
        return str(self._getter())
    def __str__(self):
        return str(self._getter())
    def __repr__(self):
        return repr(self._getter())
    def mkdir(self, *args, **kwargs):
        try:
            return self._getter().mkdir(*args, **kwargs)
        except OSError as err:
            logger.warning(f"Proxy mkdir notice: {err}")
    def __getattr__(self, item):
        return getattr(self._getter(), item)

UPLOADS_DIR = _StoragePathProxy(get_uploads_dir)
REPORTS_DIR = _StoragePathProxy(get_reports_dir)

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
    stored_path = get_uploads_dir() / safe_uuid_name
    return safe_uuid_name, stored_path

def validate_file_size(size_bytes: int) -> bool:
    """Verify file does not exceed maximum allowable threshold."""
    return 0 < size_bytes <= MAX_FILE_SIZE_BYTES

