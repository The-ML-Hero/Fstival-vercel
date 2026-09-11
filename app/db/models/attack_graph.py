from typing import Any, List
from sqlalchemy import ForeignKey, String, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AttackGraphModel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "attack_graphs"

    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("test_runs.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    nodes_json: Mapped[Any] = mapped_column(JSON, default=list, nullable=False)
    edges_json: Mapped[Any] = mapped_column(JSON, default=list, nullable=False)
