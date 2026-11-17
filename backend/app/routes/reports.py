from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.report import Report
from app.services.report_service import generate_pdf_report

router = APIRouter(prefix="/reports", tags=["Automated Report Generation"])

class GenerateReportSchema(BaseModel):
    case_id: str
    generated_by: str = "Senior Forensic Examiner"

@router.post("/generate")
def create_report(payload: GenerateReportSchema, db: Session = Depends(get_db)):
    """Generate official court-grade forensic PDF report."""
    try:
        report = generate_pdf_report(db, payload.case_id, payload.generated_by)
        return report
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation error: {str(e)}")

@router.get("")
def list_reports(case_id: Optional[str] = None, db: Session = Depends(get_db)):
    """List generated forensic reports."""
    query = db.query(Report)
    if case_id:
        query = query.filter(Report.case_id == case_id)
    return query.order_by(Report.generated_at.desc()).all()

@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    """Download generated PDF report."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report or not Path(report.file_path).exists():
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(
        path=report.file_path,
        media_type="application/pdf",
        filename=f"{report.report_number}.pdf"
    )

