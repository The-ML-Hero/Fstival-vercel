from typing import List, Optional
from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AttackExecution(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "attack_executions"

    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("test_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attack_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # ATK-001 or adaptive ATK-001-ADAPT-1
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)  # passed, failed, error, skipped
    severity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    priority: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    expected_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    actual_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    parent_attack_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_adaptive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_replay: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    objective: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expected_secure_behavior: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    run: Mapped["TestRun"] = relationship("TestRun", back_populates="attack_executions")
    steps: Mapped[List["AttackStepExecution"]] = relationship(
        "AttackStepExecution", back_populates="execution", cascade="all, delete-orphan", order_by="AttackStepExecution.step_number"
    )
    raw_result: Mapped[Optional["RawExecutionResult"]] = relationship(
        "RawExecutionResult", back_populates="execution", cascade="all, delete-orphan", uselist=False
    )
