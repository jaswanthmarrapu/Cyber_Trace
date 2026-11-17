import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.connection import Base

class IPRecord(Base):
    __tablename__ = "ip_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=True, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    ip_type = Column(String(30), nullable=False, default="Public IPv4")  # Public IPv4, RFC 1918 Private, Loopback
    country = Column(String(100), nullable=True)
    country_code = Column(String(10), nullable=True)
    city = Column(String(100), nullable=True)
    latitude = Column(String(30), nullable=True)
    longitude = Column(String(30), nullable=True)
    asn = Column(String(100), nullable=True)
    isp = Column(String(150), nullable=True)
    abuse_confidence_score = Column(Integer, nullable=False, default=0)
    reverse_dns = Column(String(255), nullable=True)
    attribution_caveat = Column(
        Text,
        nullable=False,
        default="Notice: IP addresses indicate routing origin or relay endpoints (proxies, VPNs, NAT). Attribution to an individual requires corroborating telecommunication subscriber logs and legal warrants."
    )
    investigated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    case = relationship("Case", back_populates="ip_records")

