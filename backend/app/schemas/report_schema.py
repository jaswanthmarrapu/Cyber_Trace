from pydantic import BaseModel, Field

class ReportGenerateSchema(BaseModel):
    case_id: str
    generated_by: str = Field("Senior Forensic Examiner", max_length=100)

