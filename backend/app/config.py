import os
from pathlib import Path

import os
import sys
from pathlib import Path
from typing import List

BASE_DIR = Path(__file__).resolve().parent.parent

# Persistent storage mount directory (e.g. /data on Render or Docker)
DATA_DIR_ENV = os.getenv("DATA_DIR")
DATA_DIR = Path(DATA_DIR_ENV).resolve() if DATA_DIR_ENV else BASE_DIR

# Core application settings with environment variable overrides
class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "CyberTrace – Digital Forensics Platform")
    VERSION: str = os.getenv("VERSION", "1.0.0")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", os.getenv("ENV", "production" if os.getenv("RENDER") else "development"))
    API_V1_PREFIX: str = "/api/v1"
    
    # SQLite Database Configuration
    SQLITE_DB_PATH: Path = DATA_DIR / "cybertrace.db"
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        f"sqlite:///{DATA_DIR / 'cybertrace.db'}"
    )

    # Security & Authentication
    SECRET_KEY: str = os.getenv("SECRET_KEY", "cybertrace-forensic-secret-key-super-secure-token-9817234")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 Hours

    # Initial Administrator Credentials (configurable via env)
    ADMIN_INITIAL_USERNAME: str = os.getenv("ADMIN_INITIAL_USERNAME", "admin_examiner")
    ADMIN_INITIAL_PASSWORD: str = os.getenv("ADMIN_INITIAL_PASSWORD", "")
    ADMIN_INITIAL_EMAIL: str = os.getenv("ADMIN_INITIAL_EMAIL", "examiner@cybertrace.local")

    # Secure Evidence Vault & Report Storage
    UPLOAD_DIR: Path = DATA_DIR / "uploads"
    REPORTS_DIR: Path = DATA_DIR / "reports"
    MAX_UPLOAD_SIZE_BYTES: int = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(50 * 1024 * 1024)))  # 50 MB

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

# Ensure storage directories exist
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

