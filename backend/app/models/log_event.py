import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from app.database.connection import Base

class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=False, index=True)
    evidence_id = Column(String(36), ForeignKey("evidence.id"), nullable=True, index=True)
    event_timestamp = Column(DateTime, nullable=True, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True, default="TCP")
    service = Column(String(50), nullable=True, default="HTTP")
    event_type = Column(String(100), nullable=False, default="SecurityEvent")
    severity = Column(String(20), nullable=False, default="Low")  # Low, Medium, High, Critical
    raw_log = Column(Text, nullable=False)
    parsed_json = Column(Text, nullable=True)
    is_threat = Column(Boolean, default=False, index=True)
    mitre_technique = Column(String(100), nullable=True)
    flag_reason = Column(Text, nullable=True)
    username = Column(String(100), nullable=True, index=True)

    # Relationships
    case = relationship("Case", back_populates="log_events")
    evidence = relationship("Evidence", back_populates="log_events")

