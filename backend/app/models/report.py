import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.connection import Base

class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=False, index=True)
    report_number = Column(String(50), unique=True, nullable=False, index=True)
    report_title = Column(String(200), nullable=False)
    generated_by = Column(String(100), nullable=False, default="Forensic Analyst")
    file_path = Column(String(500), nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    executive_summary = Column(Text, nullable=True)
    generated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    case = relationship("Case", back_populates="reports")

