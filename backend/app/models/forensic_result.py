import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.connection import Base

class ForensicResult(Base):
    __tablename__ = "forensic_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_id = Column(String(36), ForeignKey("evidence.id"), nullable=False, index=True)
    magic_bytes = Column(String(100), nullable=True)
    detected_mime = Column(String(100), nullable=True)
    entropy_score = Column(Float, nullable=True)
    is_packed_or_encrypted = Column(Boolean, default=False)
    yara_matches_json = Column(Text, nullable=True)
    extracted_strings_sample = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)
    analyzed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    evidence = relationship("Evidence", back_populates="forensic_results")

