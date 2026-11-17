import os
import sys
import time
import secrets
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional

# Ensure 'backend' directory is always present on sys.path so 'app' imports resolve regardless of cwd
CURRENT_FILE = Path(__file__).resolve()
BACKEND_DIR = CURRENT_FILE.parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from app.config import settings
from app.database.connection import init_db, SessionLocal
from app.models.case import Case
from app.models.user import User
from app.utils.security import hash_password
from app.routes import (
    auth_router,
    dashboard_router,
    cases_router,
    evidence_router,
    logs_router,
    ip_router,
    forensics_router,
    threats_router,
    timeline_router,
    integrity_router,
    reports_router,
    ai_router,
)

# Configure Production Logging
log_level = logging.INFO if settings.ENVIRONMENT == "production" else logging.DEBUG
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("cybertrace")

def seed_initial_demo_case():
    """Seed initial administrator and realistic demo case if database is empty."""
    db = SessionLocal()
    try:
        # Seed default investigator user with secure password handling
        if db.query(User).count() == 0:
            admin_username = settings.ADMIN_INITIAL_USERNAME
            admin_email = settings.ADMIN_INITIAL_EMAIL
            admin_password = settings.ADMIN_INITIAL_PASSWORD

            if not admin_password:
                if settings.ENVIRONMENT == "production":
                    # In production, never use a static default password
                    admin_password = secrets.token_urlsafe(16)
                    logger.warning(
                        "\n" + "=" * 64 + "\n"
                        "[CYBERTRACE SECURITY NOTICE - FIRST RUN INITIALIZATION]\n"
                        f"Admin User: {admin_username}\n"
                        f"Temporary Password: {admin_password}\n"
                        "Note: Set ADMIN_INITIAL_PASSWORD in production environment variables.\n"
                        + "=" * 64
                    )
                else:
                    admin_password = "CyberTrace2026!"

            default_user = User(
                username=admin_username,
                email=admin_email,
                hashed_password=hash_password(admin_password),
                full_name="Senior Forensic Examiner",
                role="Lead Examiner",
                is_active=True
            )
            db.add(default_user)
            logger.info(f"Initialized administrative investigator account: '{admin_username}'")

        # Seed initial realistic forensic investigation case with valid lifecycle status
        if db.query(Case).count() == 0:
            demo_case = Case(
                case_number="CT-2026-001",
                title="Operation DarkHydra - Web Perimeter Breach & Privilege Escalation",
                description="Investigating unauthorized SQL injection penetration, subsequent web shell deployment, and lateral root privilege escalation on production staging infrastructure.",
                investigator_name="Senior Forensic Examiner",
                status="Under Investigation",
                severity="Critical",
                incident_type="Data Breach & Web Shell"
            )
            db.add(demo_case)
            logger.info("Initialized baseline forensic demonstration case 'CT-2026-001'")

        db.commit()
    except Exception as ex:
        db.rollback()
        logger.error(f"Error initializing database records: {ex}")
        raise
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure evidence and reports directories exist
    logger.info(f"Starting CyberTrace Engine v{settings.VERSION} [{settings.ENVIRONMENT.upper()} MODE]")
    logger.info(f"Storage Vault Path: {settings.UPLOAD_DIR}")
    logger.info(f"Database Target: {settings.SQLITE_DB_PATH}")
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    # Initialize SQLite tables and seed default case
    init_db()
    seed_initial_demo_case()
    yield
    # Shutdown hook for clean resource termination
    try:
        from app.database.connection import engine
        engine.dispose()
        logger.info("CyberTrace database engine connections gracefully released.")
    except Exception:
        pass

# OpenAPI Tags Metadata for Professional Swagger Documentation
tags_metadata = [
    {"name": "System", "description": "Service health probe and platform telemetry status."},
    {"name": "Authentication & Access Control", "description": "JWT-based examiner authentication and RBAC."},
    {"name": "Dashboard & Telemetry", "description": "Aggregated forensic incident metrics and telemetry feed."},
    {"name": "Case Management", "description": "Lifecycle tracking and triage of digital forensics cases."},
    {"name": "Evidence & Chain of Custody", "description": "Non-executable vault storage, streaming SHA-256 calculation, and immutable audit logs."},
    {"name": "Evidence Integrity Verification", "description": "Bit-level cryptographic integrity verification and tamper detection."},
    {"name": "Log Analysis", "description": "Multi-format correlation for Apache/Nginx, Linux auth.log, and Windows Event logs."},
    {"name": "IP Investigation", "description": "Routing endpoint intelligence, ASN, WHOIS, and ISO/IEC 27037 attribution safeguards."},
    {"name": "File Forensics & Evidence Integrity", "description": "Passive binary disassembly: magic byte detection, Shannon entropy, string IOC extraction, and YARA signatures."},
    {"name": "Threat Detection", "description": "Automated security anomaly mapping to MITRE ATT&CK tactics."},
    {"name": "Attack Timeline Reconstruction", "description": "Chronological multi-vector event sequencing from initial access to exfiltration."},
    {"name": "Automated Report Generation", "description": "Judicial-grade forensic PDF report generation via ReportLab with cryptographic sign-off blocks."},
    {"name": "AI-Assisted Investigation Summary", "description": "Forensic executive summary, attack chain narrative, and remediation checklist."},
]

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""
### CyberTrace Digital Forensics & Cyber Incident Investigation Platform API

Welcome to the **CyberTrace REST API Engine**. This service powers digital forensics examiners, incident responders, and SOC analysts with:

* **Cryptographic Evidence Integrity**: Ingestion-time SHA-256 baseline calculation and on-demand bit-level verification.
* **Non-Executable Vault**: Strict UUID-based safe storage ensuring uploaded evidence files are never executed on the host.
* **Responsible IP Attribution**: Built-in adherence to **ISO/IEC 27037** standards regarding routing endpoints vs individual identity.
* **Attack Reconstruction**: Multi-source log correlation mapped into the **MITRE ATT&CK Framework**.
* **Court-Grade Reporting**: Automated PDF generation featuring examiner signature blocks.
    """,
    version=settings.VERSION,
    openapi_tags=tags_metadata,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Allowed CORS headers explicitly defined without wildcards for credentialed security
ALLOWED_CORS_HEADERS = [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "Accept",
    "Origin",
    "Access-Control-Request-Method",
    "Access-Control-Request-Headers",
    "X-CSRF-Token",
    "Cache-Control"
]

# Enable Production CORS for Frontend Communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=settings.cors_origin_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=ALLOWED_CORS_HEADERS,
    expose_headers=["Content-Disposition"]
)

# Production Request Performance & Access Logging Middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration_ms = (time.time() - start_time) * 1000
    if request.url.path not in ("/api/v1/health", "/"):
        logger.info(
            f"{request.method} {request.url.path} -> {response.status_code} ({duration_ms:.1f}ms)"
        )
    return response

# Global Exception Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "detail": exc.errors(),
            "message": "Input validation failed. Please check field formats and data types."
        }
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Forensic Server Error",
            "message": str(exc)
        }
    )

# Health Check & Root System Endpoints
@app.get("/", tags=["System"])
def root():
    """Root platform discovery endpoint with links to interactive documentation."""
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "health_endpoint": f"{settings.API_V1_PREFIX}/health"
    }

@app.get(f"{settings.API_V1_PREFIX}/health", tags=["System"])
def health_check():
    """System health probe, storage metrics, and integrity mode verification."""
    from app.database.connection import check_db_health
    db_healthy = check_db_health()
    return {
        "status": "healthy" if db_healthy else "degraded",
        "service": "CyberTrace Digital Forensics Engine",
        "version": settings.VERSION,
        "database": "SQLite (ACID Compliant)",
        "database_path": str(settings.SQLITE_DB_PATH),
        "database_healthy": db_healthy,
        "vault_storage": "Non-Executable Isolated Vault",
        "storage_path": str(settings.DATA_DIR),
        "forensic_integrity_mode": "Active (SHA-256 NIST FIPS 180-4)",
        "active_modules": 12
    }

# Mount All 12 Modular Routers Under /api/v1
app.include_router(auth_router, prefix=settings.API_V1_PREFIX)
app.include_router(dashboard_router, prefix=settings.API_V1_PREFIX)
app.include_router(cases_router, prefix=settings.API_V1_PREFIX)
app.include_router(evidence_router, prefix=settings.API_V1_PREFIX)
app.include_router(integrity_router, prefix=settings.API_V1_PREFIX)
app.include_router(logs_router, prefix=settings.API_V1_PREFIX)
app.include_router(ip_router, prefix=settings.API_V1_PREFIX)
app.include_router(forensics_router, prefix=settings.API_V1_PREFIX)
app.include_router(threats_router, prefix=settings.API_V1_PREFIX)
app.include_router(timeline_router, prefix=settings.API_V1_PREFIX)
app.include_router(reports_router, prefix=settings.API_V1_PREFIX)
app.include_router(ai_router, prefix=settings.API_V1_PREFIX)

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0" if settings.ENVIRONMENT == "production" else "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    reload = settings.ENVIRONMENT == "development"
    uvicorn.run("app.main:app", host=host, port=port, reload=reload)
