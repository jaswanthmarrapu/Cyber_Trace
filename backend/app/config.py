import os
import sys
from pathlib import Path
from typing import List

BASE_DIR = Path(__file__).resolve().parent.parent

# Persistent Storage & Database Path Resolution:
# Priority for SQLite Database Path:
# 1. DATABASE_PATH environment variable (explicit override)
# 2. Render cloud production environment (default to /var/data/cybertrace.db)
# 3. DATA_DIR environment variable (DATA_DIR / cybertrace.db)
# 4. Local development fallback (BASE_DIR / cybertrace.db)
def _resolve_sqlite_db_path() -> Path:
    db_path_env = os.getenv("DATABASE_PATH", "").strip()
    if db_path_env:
        return Path(db_path_env)
    
    if os.getenv("RENDER"):
        return Path("/var/data/cybertrace.db")
        
    data_dir_env = os.getenv("DATA_DIR", "").strip()
    if data_dir_env:
        return Path(data_dir_env) / "cybertrace.db"
        
    return BASE_DIR / "cybertrace.db"

def _resolve_data_dir(db_path: Path) -> Path:
    data_dir_env = os.getenv("DATA_DIR", "").strip()
    if data_dir_env:
        return Path(data_dir_env)
    if os.getenv("RENDER"):
        return Path("/var/data")
    if db_path.parent != BASE_DIR and str(db_path.parent) != ".":
        return db_path.parent
    return BASE_DIR

def _resolve_database_url(db_path: Path) -> str:
    explicit_url = os.getenv("DATABASE_URL", "").strip()
    if explicit_url:
        return explicit_url
    
    posix_path = db_path.as_posix()
    return f"sqlite:///{posix_path}"

# Core application settings with environment variable overrides
class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "CyberTrace – Digital Forensics Platform")
    VERSION: str = os.getenv("VERSION", "1.0.0")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", os.getenv("ENV", "production" if os.getenv("RENDER") else "development"))
    API_V1_PREFIX: str = "/api/v1"
    
    # SQLite Database Configuration & Permanent Storage
    @property
    def SQLITE_DB_PATH(self) -> Path:
        return _resolve_sqlite_db_path()

    @property
    def DATABASE_URL(self) -> str:
        return _resolve_database_url(self.SQLITE_DB_PATH)

    @property
    def DATA_DIR(self) -> Path:
        return _resolve_data_dir(self.SQLITE_DB_PATH)

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
    ADMIN_INITIAL_PASSWORD: str = os.getenv("ADMIN_INITIAL_PASSWORD", "")
    ADMIN_INITIAL_EMAIL: str = os.getenv("ADMIN_INITIAL_EMAIL", "examiner@cybertrace.local")

    # Upload restrictions
    ALLOWED_EXTENSIONS: set = {
        "log", "txt", "evtx", "json", "csv", "pcap", "pcapng",
        "bin", "dat", "dump", "raw", "img", "mem", "dll", "exe",
        "pdf", "png", "jpg", "jpeg", "zip", "tar", "gz"
    }

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

# Ensure storage and database parent directories exist safely
try:
    settings.SQLITE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

