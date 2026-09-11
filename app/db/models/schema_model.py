from typing import Optional, Any
from sqlalchemy import ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class SchemaModel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "schema_models"

    endpoint_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    schema_type: Mapped[str] = mapped_column(String(32), nullable=False)  # "request_body" or "response_body"
    status_code: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # e.g., "200", "201", "400", "default"
    content_type: Mapped[str] = mapped_column(String(128), default="application/json", nullable=False)
    schema_json: Mapped[Any] = mapped_column(JSON, default=dict, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    endpoint: Mapped["Endpoint"] = relationship("Endpoint", back_populates="schemas")
