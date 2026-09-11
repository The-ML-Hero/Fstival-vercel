from typing import Any
from sqlalchemy import Float, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AttackChainModel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "attack_chains"

    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("test_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # CHAIN-001
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    overall_risk: Mapped[int] = mapped_column(Integer, default=70, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    nodes_json: Mapped[Any] = mapped_column(JSON, default=list, nullable=False)
    edges_json: Mapped[Any] = mapped_column(JSON, default=list, nullable=False)
