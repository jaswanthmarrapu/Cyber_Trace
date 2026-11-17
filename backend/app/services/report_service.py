import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.evidence import Evidence
from app.models.report import Report
from app.utils.file_security import REPORTS_DIR
from app.forensic.report_generator import (
    generate_complete_investigation_report_pdf,
    query_case_report_dossier
)
from app.database.connection import DB_PATH

def generate_pdf_report(db: Session, case_id: str, generated_by: str = "Senior Forensic Examiner") -> Report:
    """Build court-admissible-grade PDF forensic investigation report containing all 12 sections."""
    case = db.query(Case).filter((Case.id == case_id) | (Case.case_number == case_id)).first()
    if not case:
        raise ValueError(f"Case with id {case_id} not found")

    # Generate the professional 12-section PDF using ReportLab (with standalone fallback)
    report_dict = generate_complete_investigation_report_pdf(
        str(DB_PATH),
        case.id,
        generated_by=generated_by
    )

    # Sync with SQLAlchemy Report model
    report_record = db.query(Report).filter(Report.id == report_dict["id"]).first()
    if not report_record:
        report_record = Report(
            id=report_dict["id"],
            case_id=case.id,
            report_number=report_dict["report_number"],
            report_title=report_dict["report_title"],
            generated_by=generated_by,
            file_path=report_dict["file_path"],
            sha256_hash=report_dict["sha256_hash"],
            executive_summary=(
                f"Official forensic incident investigation report for {case.title}. "
                f"Evaluation conducted pursuant to ISO/IEC 27037 and NIST SP 800-86 standards."
            )
        )
        db.add(report_record)
        db.commit()
        db.refresh(report_record)

    return report_record
