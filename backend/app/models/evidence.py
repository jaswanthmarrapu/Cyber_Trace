import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.connection import Base

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=False, index=True)
    evidence_number = Column(String(50), unique=True, nullable=False, index=True)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    file_type = Column(String(50), nullable=False, default="unknown")
    mime_type = Column(String(100), nullable=False, default="application/octet-stream")
    
    # Cryptographic integrity hashes
    sha256_hash = Column(String(64), nullable=False, index=True)
    sha1_hash = Column(String(40), nullable=False)
    md5_hash = Column(String(32), nullable=False)
    initial_recorded_hash = Column(String(64), nullable=False)
    integrity_status = Column(String(30), nullable=False, default="Verified")  # Verified, Compromised, Unverified
    
    source_device = Column(String(100), nullable=True, default="Target Host / Server")
    acquired_by = Column(String(100), nullable=False, default="Incident Responder")
    acquired_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    description = Column(Text, nullable=True)

    # Relationships
    case = relationship("Case", back_populates="evidence")
    chain_of_custody = relationship("ChainOfCustody", back_populates="evidence", cascade="all, delete-orphan")
    forensic_results = relationship("ForensicResult", back_populates="evidence", cascade="all, delete-orphan")
    log_events = relationship("LogEvent", back_populates="evidence")

