from typing import List, Optional, Any
from sqlalchemy import Float, ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AttackHypothesis(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "attack_hypotheses"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attack_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # e.g., ATK-001
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # BOLA, Role Escalation, etc.
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    preconditions: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    steps: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    expected_secure_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    # Prioritization Metrics
    severity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)  # critical, high, medium, low, info
    exploitability: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)  # 0.0 to 1.0
    impact: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)  # 0.0 to 1.0
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)  # 0.0 to 1.0
    priority_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    priority_level: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="attack_hypotheses")
    mutations: Mapped[List["AttackMutation"]] = relationship(
        "AttackMutation", back_populates="hypothesis", cascade="all, delete-orphan"
    )


class AttackMutation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "attack_mutations"

    hypothesis_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attack_hypotheses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    parameter_name: Mapped[str] = mapped_column(String(255), nullable=False)
    parameter_location: Mapped[str] = mapped_column(String(32), nullable=False)  # path, query, header, body
    mutation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_sample: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationships
    hypothesis: Mapped["AttackHypothesis"] = relationship("AttackHypothesis", back_populates="mutations")
