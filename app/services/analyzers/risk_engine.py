from typing import Dict, List, Tuple
from app.schemas.module3.risk import RiskBreakdown, RiskAssessmentResponse, SecurityScoreResponse


class RiskEngine:
    """
    Transparent Risk Scoring Engine for Module 3.
    Evaluates individual finding risk (0-100) and overall project security health score (0-100).
    """

    SEVERITY_WEIGHTS = {
        "critical": 40.0,
        "high": 25.0,
        "medium": 15.0,
        "low": 5.0,
    }

    SENSITIVITY_FACTORS = {
        "high": 10.0,
        "medium": 6.0,
        "low": 2.0,
    }

    CONFIDENCE_FACTORS = {
        "confirmed": 15.0,
        "likely": 12.0,
        "inconclusive": 6.0,
        "false-positive": 0.0,
    }

    def calculate_finding_risk(
        self,
        severity: str,
        confidence_status: str,
        data_sensitivity: str = "medium",
        exploitability: float = 0.8,
        reach_level: str = "Tenant"
    ) -> RiskAssessmentResponse:
        """
        Calculates transparent 0-100 risk score with detailed component breakdown.
        """
        sev_norm = severity.lower()
        conf_norm = confidence_status.lower()
        sens_norm = data_sensitivity.lower()

        sev_weight = self.SEVERITY_WEIGHTS.get(sev_norm, 15.0)
        conf_factor = self.CONFIDENCE_FACTORS.get(conf_norm, 10.0)
        sens_factor = self.SENSITIVITY_FACTORS.get(sens_norm, 6.0)
        exploit_factor = round(max(0.0, min(1.0, exploitability)) * 25.0, 1)

        reach_factor = 3.0
        if "all" in reach_level.lower() or "system" in reach_level.lower():
            reach_factor = 10.0
        elif "tenant" in reach_level.lower() or "database" in reach_level.lower() or "10,000" in reach_level:
            reach_factor = 7.0

        raw_score = sev_weight + exploit_factor + conf_factor + sens_factor + reach_factor
        final_risk_score = int(round(min(100.0, max(0.0, raw_score))))

        formula = (
            f"Risk ({final_risk_score}) = Severity ({sev_weight}) + Exploitability ({exploit_factor}) + "
            f"Confidence ({conf_factor}) + Sensitivity ({sens_factor}) + Reach ({reach_factor})"
        )

        reasoning = (
            f"Calculated {sev_norm.upper()} risk score of {final_risk_score}/100. "
            f"Driven by {sev_weight} pts for {sev_norm} severity, {exploit_factor} pts for active exploitability, "
            f"{conf_factor} pts for {conf_norm} evidence, {sens_factor} pts for {sens_norm} data sensitivity, "
            f"and {reach_factor} pts for estimated blast reach ({reach_level})."
        )

        breakdown = RiskBreakdown(
            severity_weight=sev_weight,
            exploitability_factor=exploit_factor,
            confidence_factor=conf_factor,
            data_sensitivity_factor=sens_factor,
            reach_factor=reach_factor,
            calculation_formula=formula,
        )

        return RiskAssessmentResponse(
            risk_score=final_risk_score,
            severity=sev_norm,
            confidence=round(conf_factor / 15.0, 2),
            breakdown=breakdown,
            reasoning=reasoning,
        )

    def calculate_project_security_score(
        self,
        run_id: str,
        findings_severities: List[str]
    ) -> SecurityScoreResponse:
        """
        Calculates aggregate project security score: 100 = perfect, 0 = critical risk.
        """
        critical_count = sum(1 for s in findings_severities if s.lower() == "critical")
        high_count = sum(1 for s in findings_severities if s.lower() == "high")
        medium_count = sum(1 for s in findings_severities if s.lower() == "medium")
        low_count = sum(1 for s in findings_severities if s.lower() == "low")
        total = len(findings_severities)

        deductions = (critical_count * 25.0) + (high_count * 12.0) + (medium_count * 5.0) + (low_count * 1.5)
        score = max(0, int(round(100.0 - deductions)))

        if score >= 90:
            level = "low"
        elif score >= 70:
            level = "medium"
        elif score >= 50:
            level = "high"
        else:
            level = "critical"

        return SecurityScoreResponse(
            run_id=run_id,
            security_score=score,
            risk_level=level,
            total_findings=total,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            score_calculation_details={
                "base_score": 100.0,
                "critical_deductions": float(critical_count * 25),
                "high_deductions": float(high_count * 12),
                "medium_deductions": float(medium_count * 5),
                "low_deductions": float(low_count * 1.5),
                "total_deductions": float(deductions),
            }
        )
