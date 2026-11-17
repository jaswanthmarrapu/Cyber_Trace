import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.connection import Base

class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=False, index=True)
    event_timestamp = Column(DateTime, nullable=False, index=True)
    event_source = Column(String(50), nullable=False)  # Web Log, Auth Log, File System MACB, Network PCAP, Analyst Note
    event_category = Column(String(100), nullable=False)  # Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Exfiltration
    actor = Column(String(100), nullable=True)  # Source IP / Username
    target = Column(String(150), nullable=True)  # System hostname, file path, endpoint
    description = Column(Text, nullable=False)
    mitre_tactic = Column(String(100), nullable=True)
    confidence_level = Column(String(20), nullable=False, default="High")  # Low, Medium, High, Verified

    # Relationships
    case = relationship("Case", back_populates="timeline_events")

