from typing import List, Any
from sqlalchemy import Float, ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class InferredRole(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "inferred_roles"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_name: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)  # 0.0 to 1.0
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[List[Any]] = mapped_column(JSON, default=list, nullable=False)
    associated_endpoints: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="inferred_roles")
