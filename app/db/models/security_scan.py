from datetime import datetime
from typing import Optional
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow


class SecurityScanSummary(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "security_scans"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("test_runs.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    security_score: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fixed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    regression_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ci_gate_status: Mapped[str] = mapped_column(String(32), default="passed", nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
