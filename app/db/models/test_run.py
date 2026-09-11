from datetime import datetime
from typing import List, Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class TestRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "test_runs"
    __test__ = False  # Prevent pytest from treating model as test class

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    target_authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    environment: Mapped[str] = mapped_column(String(32), default="local", nullable=False)  # local, staging, authorized
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)  # pending, running, completed, failed, stopped
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    total_attacks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    passed_attacks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_attacks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_attacks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    collection_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    project: Mapped["Project"] = relationship("Project", backref="test_runs")
    attack_executions: Mapped[List["AttackExecution"]] = relationship(
        "AttackExecution", back_populates="run", cascade="all, delete-orphan", order_by="AttackExecution.created_at"
    )
