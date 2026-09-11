from typing import Any, Optional
from sqlalchemy import ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RegressionRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "regression_records"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    current_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("test_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    previous_run_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    finding_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    regression_type: Mapped[str] = mapped_column(String(64), nullable=False)  # reopened_vulnerability, score_drop, new_vulnerability
    details_json: Mapped[Any] = mapped_column(JSON, default=dict, nullable=False)
