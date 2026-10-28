import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text, JSON
from app.db.session import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

class ImportRecord(Base):
    __tablename__ = "imports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    file_format = Column(String(64), nullable=False) # CYCLONEDX_JSON, SARIF, CSV, GENERIC_JSON
    file_hash = Column(String(64), nullable=False)
    status = Column(String(32), default="PENDING", nullable=False, index=True) # PENDING, PROCESSING, COMPLETED, FAILED
    records_total = Column(Integer, default=0, nullable=False)
    records_accepted = Column(Integer, default=0, nullable=False)
    records_rejected = Column(Integer, default=0, nullable=False)
    records_skipped = Column(Integer, default=0, nullable=False)
    error_details = Column(JSON, default=list)
    imported_by_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

class BackgroundJob(Base):
    __tablename__ = "background_jobs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    job_type = Column(String(64), nullable=False, index=True) # INTELLIGENCE_SYNC_KEV, INTELLIGENCE_SYNC_EPSS, REPORT_INGESTION, EVALUATION_RUN
    status = Column(String(32), default="QUEUED", nullable=False, index=True) # QUEUED, RUNNING, SUCCESS, FAILED
    progress_pct = Column(Float, default=0.0, nullable=False)
    result_payload = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
