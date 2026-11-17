import os
import sys
import uuid
import logging
from pathlib import Path
from typing import List, Tuple, Optional

logger = logging.getLogger("cybertrace.config")

BASE_DIR = Path(__file__).resolve().parent.parent

def is_storage_path_writable(target_path: Path) -> bool:
    """
    Check if a storage directory exists and is writable, or can be safely created and written to.
    Prevents crashing on cloud environments (e.g. Render) when a persistent disk is not yet mounted.
    """
    try:
        if target_path.exists():
            if not target_path.is_dir():
                return False
            probe = target_path / f".perm_probe_{os.getpid()}_{uuid.uuid4().hex[:4]}.tmp"
            probe.write_text("probe")
            probe.unlink(missing_ok=True)
            return True
        else:
            target_path.mkdir(parents=True, exist_ok=True)
            probe = target_path / f".perm_probe_{os.getpid()}_{uuid.uuid4().hex[:4]}.tmp"
            probe.write_text("probe")
            probe.unlink(missing_ok=True)
            return True
    except (PermissionError, FileNotFoundError, OSError):
        return False

# Persistent Storage & Database Path Resolution:
# Priority for SQLite Database Path:
# 1. DATABASE_PATH environment variable (explicit override)
# 2. Render cloud production environment (/var/data/cybertrace.db if mounted and writable)
# 3. DATA_DIR environment variable (DATA_DIR / cybertrace.db if writable)
# 4. Writable application directory fallback (BASE_DIR / cybertrace.db)
def _resolve_storage_and_database() -> Tuple[Path, Path, bool, Optional[str]]:
    """
    Safely resolve database and storage directory paths.
    Checks whether target persistent volumes (such as /var/data on Render)
    are actually mounted and writable. If not writable, gracefully falls back
    to the writable application root directory without crashing worker startup.
    """
    db_path_env = os.getenv("DATABASE_PATH", "").strip()
    data_dir_env = os.getenv("DATA_DIR", "").strip()
    is_render = bool(os.getenv("RENDER"))
    
    # 1. Determine prospective target paths
    if db_path_env:
        candidate_db = Path(db_path_env)
        candidate_dir = candidate_db.parent
    elif is_render:
        candidate_dir = Path("/var/data")
        candidate_db = candidate_dir / "cybertrace.db"
    elif data_dir_env:
        candidate_dir = Path(data_dir_env)
        candidate_db = candidate_dir / "cybertrace.db"
    else:
        candidate_dir = BASE_DIR
        candidate_db = BASE_DIR / "cybertrace.db"

    # 2. Test if candidate directory is writable
    if is_storage_path_writable(candidate_dir):
        return candidate_db, candidate_dir, True, None
    else:
        # Fallback to local writable application directory
        fallback_dir = BASE_DIR
        fallback_db = fallback_dir / "cybertrace.db"
        warning_msg = (
            f"[CYBERTRACE STORAGE NOTICE]: Target persistent storage path '{candidate_dir}' is not "
            f"writable or persistent disk is not mounted. Falling back to local writable application "
            f"directory: '{fallback_dir}'. Note: SQLite database records and uploaded evidence files "
            f"will NOT persist across Render service restarts until a persistent disk is attached "
            f"and mounted at '/var/data' in the Render Dashboard."
        )
        logger.warning(warning_msg)
        return fallback_db, fallback_dir, False, warning_msg

def _resolve_sqlite_db_path() -> Path:
    return _resolve_storage_and_database()[0]

def _resolve_data_dir(db_path: Optional[Path] = None) -> Path:
    if db_path is not None:
        if db_path.parent != BASE_DIR and str(db_path.parent) != ".":
            return db_path.parent
        return BASE_DIR
    return _resolve_storage_and_database()[1]

def _resolve_database_url(db_path: Path, is_persistent: bool = True) -> str:
    explicit_url = os.getenv("DATABASE_URL", "").strip()
    # Only use explicit DATABASE_URL if the target storage is actually writable
    if explicit_url and is_persistent:
        return explicit_url
    
    posix_path = db_path.as_posix()
    return f"sqlite:///{posix_path}"

# Core application settings with environment variable overrides
class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "CyberTrace – Digital Forensics Platform")
    VERSION: str = os.getenv("VERSION", "1.0.0")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", os.getenv("ENV", "production" if os.getenv("RENDER") else "development"))
    API_V1_PREFIX: str = "/api/v1"
    
    # Dynamic SQLite Database Configuration & Permanent Storage
    @property
    def storage_info(self) -> Tuple[Path, Path, bool, Optional[str]]:
        return _resolve_storage_and_database()

    @property
    def SQLITE_DB_PATH(self) -> Path:
        return self.storage_info[0]

    @property
    def DATA_DIR(self) -> Path:
        return self.storage_info[1]

    @property
    def IS_PERSISTENT_STORAGE(self) -> bool:
        return self.storage_info[2]

    @property
    def STORAGE_WARNING(self) -> Optional[str]:
        return self.storage_info[3]

    @property
    def DATABASE_URL(self) -> str:
        return _resolve_database_url(self.SQLITE_DB_PATH, self.IS_PERSISTENT_STORAGE)

    @property
    def UPLOAD_DIR(self) -> Path:
        return self.DATA_DIR / "uploads"

    @property
    def REPORTS_DIR(self) -> Path:
        return self.DATA_DIR / "reports"

    MAX_UPLOAD_SIZE_BYTES: int = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(50 * 1024 * 1024)))  # 50 MB

    # Security & Authentication
    SECRET_KEY: str = os.getenv("SECRET_KEY", "cybertrace-forensic-secret-key-super-secure-token-9817234")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 Hours

    # Initial Administrator Credentials (configurable via env)
    ADMIN_INITIAL_USERNAME: str = os.getenv("ADMIN_INITIAL_USERNAME", "admin_examiner")
    ADMIN_INITIAL_PASSWORD: str = os.getenv("ADMIN_INITIAL_PASSWORD", "CyberTraceAdmin2026!")
    ADMIN_INITIAL_EMAIL: str = os.getenv("ADMIN_INITIAL_EMAIL", "admin@cybertrace.local")

    # Upload restrictions
    ALLOWED_EXTENSIONS: set = {
        "log", "txt", "evtx", "json", "csv", "pcap", "pcapng",
        "bin", "dat", "dump", "raw", "img", "mem", "dll", "exe",
        "pdf", "png", "jpg", "jpeg", "zip", "tar", "gz"
    }

    # Safe runtime directory creation
    def ensure_storage_directories(self) -> bool:
        """Create upload and report storage directories safely at runtime."""
        try:
            self.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            self.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            return True
        except OSError as ex:
            logger.warning(f"Could not initialize storage directories: {ex}")
            return False

    # Production CORS Configuration
    @property
    def cors_origins(self) -> List[str]:
        default_origins = [
            "https://cyber-trace-gamma.vercel.app",
            "https://cyber-trace-2htc.onrender.com",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ]
        custom_origins = os.getenv("CORS_ORIGINS", "")
        if custom_origins:
            parsed = [o.strip().rstrip("/") for o in custom_origins.split(",") if o.strip()]
            for origin in parsed:
                # Disallow wildcard '*' when allow_credentials=True is enabled
                if origin and origin != "*" and origin not in default_origins:
                    default_origins.append(origin)
        return default_origins

    @property
    def cors_origin_regex(self) -> str:
        # Regex matching Vercel preview and production deployments
        regex_env = os.getenv("CORS_ORIGIN_REGEX", "").strip()
        if regex_env:
            # Normalize double backslashes that can occur in YAML or shell environment exports
            return regex_env.replace(r"\\.", r"\.").replace(r"\/", "/")
        return r"^https:\/\/.*\.vercel\.app$"

settings = Settings()
# NOTE: Do NOT call .mkdir() at module import time to prevent crash on unwritable cloud volumes.

