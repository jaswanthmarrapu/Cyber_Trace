from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class CaseCreateSchema(BaseModel):
    case_number: str = Field(..., min_length=3, max_length=50, example="CT-2026-001")
    title: str = Field(..., min_length=5, max_length=200, example="Operation DarkHydra")
    description: Optional[str] = Field(None, example="Staging web breach investigation.")
    investigator_name: str = Field("Senior Forensic Examiner", max_length=100)
    severity: str = Field("Medium", pattern="^(Low|Medium|High|Critical)$")
    incident_type: str = Field("Data Breach", max_length=50)

class CaseStatusUpdateSchema(BaseModel):
    status: str = Field(..., pattern="^(Open|Investigating|Pending Review|Closed|Archived)$")

class CaseResponseSchema(BaseModel):
    id: str
    case_number: str
    title: str
    description: Optional[str]
    investigator_name: str
    status: str
    severity: str
    incident_type: str
    created_at: Optional[datetime]

    class Config:
        from_attributes = True

