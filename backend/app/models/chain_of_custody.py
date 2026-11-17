import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.connection import Base

class ChainOfCustody(Base):
    __tablename__ = "chain_of_custody"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_id = Column(String(36), ForeignKey("evidence.id"), nullable=False, index=True)
    action = Column(String(50), nullable=False)  # Acquired, Transferred, Analyzed, Verified, Checked Out, Exported
    performed_by = Column(String(100), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    reason = Column(String(255), nullable=True)
    location = Column(String(150), nullable=True, default="Secure Digital Evidence Locker")
    verified_hash = Column(String(64), nullable=True)
    notes = Column(Text, nullable=True)

    # Relationships
    evidence = relationship("Evidence", back_populates="chain_of_custody")

