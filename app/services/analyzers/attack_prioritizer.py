from typing import Dict, List, Tuple
from app.core.config import settings
from app.schemas.ai_models import AIAttackHypothesis

SEVERITY_WEIGHT_MAP = {
    "critical": 1.0,
    "high": 0.80,
    "medium": 0.50,
    "low": 0.25,
    "info": 0.10,
}


class AttackPrioritizer:
    """
    Computes deterministic, configurable priority scores for attack hypotheses
    based on severity, exploitability, confidence, and potential impact.
    """

    def __init__(
        self,
        w_sev: float | None = None,
        w_exp: float | None = None,
        w_conf: float | None = None,
        w_imp: float | None = None
    ):
        self.w_sev = w_sev if w_sev is not None else settings.PRIORITY_WEIGHT_SEVERITY
        self.w_exp = w_exp if w_exp is not None else settings.PRIORITY_WEIGHT_EXPLOITABILITY
        self.w_conf = w_conf if w_conf is not None else settings.PRIORITY_WEIGHT_CONFIDENCE
        self.w_imp = w_imp if w_imp is not None else settings.PRIORITY_WEIGHT_IMPACT

    def calculate_score(
        self,
        severity: str,
        exploitability: float,
        confidence: float,
        impact: float
    ) -> Tuple[float, str]:
        """
        Calculates normalized score between 0.0 and 10.0 and returns (score, level).
        """
        sev_factor = SEVERITY_WEIGHT_MAP.get(severity.lower(), 0.50)
        exp_clamped = max(0.0, min(1.0, exploitability))
        conf_clamped = max(0.0, min(1.0, confidence))
        imp_clamped = max(0.0, min(1.0, impact))

        # Weighted calculation
        total_weight = self.w_sev + self.w_exp + self.w_conf + self.w_imp
        if total_weight <= 0:
            total_weight = 1.0

        raw_score = (
            (self.w_sev * sev_factor)
            + (self.w_exp * exp_clamped)
            + (self.w_conf * conf_clamped)
            + (self.w_imp * imp_clamped)
        ) / total_weight

        # Scale to 0.0 - 10.0
        final_score = round(raw_score * 10.0, 2)

        if final_score >= 8.0:
            level = "critical"
        elif final_score >= 6.0:
            level = "high"
        elif final_score >= 4.0:
            level = "medium"
        else:
            level = "low"

        return final_score, level

    def prioritize_hypotheses(
        self,
        hypotheses: List[AIAttackHypothesis]
    ) -> List[Tuple[AIAttackHypothesis, float, str]]:
        """
        Calculates scores for all hypotheses and sorts them descending by priority score.
        """
        scored_list: List[Tuple[AIAttackHypothesis, float, str]] = []

        for h in hypotheses:
            score, level = self.calculate_score(
                severity=h.severity,
                exploitability=h.exploitability,
                confidence=h.confidence,
                impact=h.impact,
            )
            scored_list.append((h, score, level))

        # Sort descending by priority_score
        scored_list.sort(key=lambda item: item[1], reverse=True)
        return scored_list
