from typing import Any, Optional
from sqlalchemy import ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RawExecutionResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "raw_execution_results"

    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attack_executions.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    stdout: Mapped[str] = mapped_column(Text, default="", nullable=False)
    stderr: Mapped[str] = mapped_column(Text, default="", nullable=False)
    exit_code: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    raw_json: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    # Relationships
    execution: Mapped["AttackExecution"] = relationship("AttackExecution", back_populates="raw_result")
