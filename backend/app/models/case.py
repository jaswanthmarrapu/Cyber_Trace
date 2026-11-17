import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime
from sqlalchemy.orm import relationship
from app.database.connection import Base

class Case(Base):
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_number = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    investigator_name = Column(String(100), nullable=False, default="Senior Forensic Examiner")
    status = Column(String(30), nullable=False, default="Open")  # Open, Investigating, Pending Review, Closed
    severity = Column(String(20), nullable=False, default="Medium")  # Low, Medium, High, Critical
    incident_type = Column(String(50), nullable=False, default="Malware Infection")  # Data Breach, Unauthorized Access, Ransomware, DDoS
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    closed_at = Column(DateTime, nullable=True)

    # Relationships
    evidence = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    log_events = relationship("LogEvent", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="case", cascade="all, delete-orphan")
    ip_records = relationship("IPRecord", back_populates="case", cascade="all, delete-orphan")

