from typing import List, Optional, Any
from sqlalchemy import Boolean, ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Endpoint(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "endpoints"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    method: Mapped[str] = mapped_column(String(10), nullable=False)  # GET, POST, PUT, PATCH, DELETE, HEAD
    path: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    operation_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    security_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    security_schemes: Mapped[List[Any]] = mapped_column(JSON, default=list, nullable=False)
    responses_summary: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="endpoints")
    parameters: Mapped[List["Parameter"]] = relationship(
        "Parameter", back_populates="endpoint", cascade="all, delete-orphan"
    )
    schemas: Mapped[List["SchemaModel"]] = relationship(
        "SchemaModel", back_populates="endpoint", cascade="all, delete-orphan"
    )
