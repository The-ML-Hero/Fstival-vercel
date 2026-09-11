from typing import Any, List, Optional
from sqlalchemy import Float, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AttackStepExecution(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "attack_step_executions"

    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attack_executions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    step_name: Mapped[str] = mapped_column(String(255), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    request_headers: Mapped[Any] = mapped_column(JSON, default=dict, nullable=False)
    request_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Redacted
    response_headers: Mapped[Any] = mapped_column(JSON, default=dict, nullable=False)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    assertion_results: Mapped[List[Any]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="passed", nullable=False)  # passed, failed, error
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    execution: Mapped["AttackExecution"] = relationship("AttackExecution", back_populates="steps")
