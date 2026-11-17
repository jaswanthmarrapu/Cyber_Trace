from pydantic import BaseModel, Field
from typing import Optional

class IPInvestigateSchema(BaseModel):
    ip_address: str = Field(..., min_length=7, max_length=45, example="203.0.113.45")
    case_id: Optional[str] = None

class IPResponseSchema(BaseModel):
    ip_address: str
    ip_type: str
    is_private: bool
    country: str
    country_code: str
    city: str
    asn: str
    isp: str
    abuse_confidence_score: int
    reverse_dns: str
    attribution_caveat: str

