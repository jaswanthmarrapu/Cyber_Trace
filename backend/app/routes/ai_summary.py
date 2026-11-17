from fastapi import APIRouter, Depends, HTTPException, Query, Body
from pydantic import BaseModel
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.database.connection import get_db, DB_PATH
from app.forensic.ai_assistant import (
    synthesize_case_ai_summary_from_db,
    generate_grounded_ai_summary
)

router = APIRouter(prefix="/ai", tags=["AI-Assisted Investigation Summary"])

class AISummaryRequest(BaseModel):
    case_id: Optional[str] = "case-001"

@router.get("/summary/{case_id}")
def get_ai_summary(case_id: str):
    """
    Generate grounded AI forensic synthesis for a case:
    - Factual findings grounded strictly in verified evidence
    - Explanation of why events were flagged
    - Inferred attack relationships & hypotheses
    - Chronological timeline summary
    - Actionable DFIR investigation recommendations
    """
    try:
        summary = synthesize_case_ai_summary_from_db(DB_PATH, case_id)
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI synthesis error: {str(e)}")

@router.post("/summary")
def post_ai_summary(payload: AISummaryRequest):
    """
    POST variant for generating or re-evaluating an AI investigation summary for an active case.
    """
    case_id = payload.case_id or "case-001"
    try:
        summary = synthesize_case_ai_summary_from_db(DB_PATH, case_id)
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI synthesis error: {str(e)}")
