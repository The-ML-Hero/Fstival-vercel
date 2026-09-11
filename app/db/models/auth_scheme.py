from typing import Optional, Any
from sqlalchemy import Boolean, ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AuthScheme(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "auth_schemes"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scheme_name: Mapped[str] = mapped_column(String(128), nullable=False)
    scheme_type: Mapped[str] = mapped_column(String(64), nullable=False)  # bearer, apikey, basic, oauth2, none
    security_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    token_location: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # "header", "query", "cookie", "Authorization"
    header_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    bearer_format: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # "JWT", etc.
    scopes: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="auth_schemes")
