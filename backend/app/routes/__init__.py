from app.routes.auth import router as auth_router
from app.routes.dashboard import router as dashboard_router
from app.routes.cases import router as cases_router
from app.routes.evidence import router as evidence_router
from app.routes.logs import router as logs_router
from app.routes.ip_investigation import router as ip_router
from app.routes.file_forensics import router as forensics_router
from app.routes.threat_detection import router as threats_router
from app.routes.timeline import router as timeline_router
from app.routes.integrity import router as integrity_router
from app.routes.reports import router as reports_router
from app.routes.ai_summary import router as ai_router

__all__ = [
    "auth_router",
    "dashboard_router",
    "cases_router",
    "evidence_router",
    "logs_router",
    "ip_router",
    "forensics_router",
    "threats_router",
    "timeline_router",
    "integrity_router",
    "reports_router",
    "ai_router",
]
