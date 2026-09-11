from typing import List, Optional, Any
from sqlalchemy import Float, ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Workflow(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "workflows"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workflow_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.8, nullable=False)
    steps: Mapped[List[Any]] = mapped_column(JSON, default=list, nullable=False)
    parameter_mappings: Mapped[List[Any]] = mapped_column(JSON, default=list, nullable=False)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="workflows")
