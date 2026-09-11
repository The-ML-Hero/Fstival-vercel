from typing import Optional
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ApiSpec(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "api_specs"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    openapi_version: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_content: Mapped[str] = mapped_column(Text, nullable=False)
    spec_format: Mapped[str] = mapped_column(String(16), default="yaml", nullable=False)  # "json" or "yaml"

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="api_spec")
