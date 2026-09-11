from datetime import datetime
from typing import Optional
from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow


class FixVerification(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "fix_verifications"

    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    previous_status: Mapped[str] = mapped_column(String(32), nullable=False)
    new_status: Mapped[str] = mapped_column(String(32), nullable=False)
    result: Mapped[str] = mapped_column(String(32), default="fixed", nullable=False)  # fixed, not_fixed, regression, inconclusive
    diff_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    finding: Mapped["VulnerabilityFinding"] = relationship("VulnerabilityFinding", back_populates="verifications")
