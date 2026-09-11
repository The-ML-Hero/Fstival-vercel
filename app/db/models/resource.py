from typing import List, Optional, Any
from sqlalchemy import ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ResourceEntity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "resource_entities"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)  # User, Patient, Order, Payment
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    endpoints: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)  # paths associated
    crud_operations: Mapped[Any] = mapped_column(JSON, default=dict, nullable=False)  # {"create": "/orders", "read": "/orders/{id}"...}
    relationships: Mapped[List[Any]] = mapped_column(JSON, default=list, nullable=False)  # [{"target": "Order", "type": "has_many"}]

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="resources")
