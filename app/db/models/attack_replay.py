from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow


class AttackReplay(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "attack_replays"

    original_execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attack_executions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    replayed_execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attack_executions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="reproduced", nullable=False)  # reproduced, changed, error
    diff_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    replayed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
