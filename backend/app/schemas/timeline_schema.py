from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class TimelineCreateSchema(BaseModel):
    event_timestamp: datetime
    event_source: str = Field(..., max_length=50)
    event_category: str = Field(..., max_length=100)
    actor: Optional[str] = Field(None, max_length=100)
    target: Optional[str] = Field(None, max_length=150)
    description: str = Field(..., min_length=5)
    mitre_tactic: Optional[str] = None
    confidence_level: str = Field("High", pattern="^(Low|Medium|High|Verified)$")

