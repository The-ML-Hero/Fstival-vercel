from typing import List, Optional
from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Project(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_base_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    target_authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    api_spec: Mapped[Optional["ApiSpec"]] = relationship(
        "ApiSpec", back_populates="project", cascade="all, delete-orphan", uselist=False
    )
    endpoints: Mapped[List["Endpoint"]] = relationship(
        "Endpoint", back_populates="project", cascade="all, delete-orphan"
    )
    auth_schemes: Mapped[List["AuthScheme"]] = relationship(
        "AuthScheme", back_populates="project", cascade="all, delete-orphan"
    )
    inferred_roles: Mapped[List["InferredRole"]] = relationship(
        "InferredRole", back_populates="project", cascade="all, delete-orphan"
    )
    resources: Mapped[List["ResourceEntity"]] = relationship(
        "ResourceEntity", back_populates="project", cascade="all, delete-orphan"
    )
    workflows: Mapped[List["Workflow"]] = relationship(
        "Workflow", back_populates="project", cascade="all, delete-orphan"
    )
    attack_hypotheses: Mapped[List["AttackHypothesis"]] = relationship(
        "AttackHypothesis", back_populates="project", cascade="all, delete-orphan"
    )
