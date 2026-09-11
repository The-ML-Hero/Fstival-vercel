from typing import Optional, Any
from sqlalchemy import Boolean, ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Parameter(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "parameters"

    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    location: Mapped[str] = mapped_column(String(32), nullable=False)  # "path", "query", "header", "cookie"
    param_type: Mapped[str] = mapped_column(String(64), default="string", nullable=False)  # "string", "integer", "number", "boolean", "array", "object"
    required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    default_value: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    enum_values: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    schema_def: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    endpoint: Mapped["Endpoint"] = relationship("Endpoint", back_populates="parameters")
