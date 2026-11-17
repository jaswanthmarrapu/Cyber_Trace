from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class ChainOfCustodyCreateSchema(BaseModel):
    action: str = Field(..., pattern="^(Acquired|Transferred|Analyzed|Verified|Checked Out|Exported)$")
    performed_by: str = Field(..., min_length=2, max_length=100)
    reason: Optional[str] = Field(None, max_length=255)
    location: Optional[str] = Field("Secure Digital Evidence Locker", max_length=150)
    notes: Optional[str] = None

class QuickVerifyFileResponseSchema(BaseModel):
    filename: str
    sha256: str
    sha1: str
    md5: str
    matches_expected: Optional[bool]
    integrity_status: str

