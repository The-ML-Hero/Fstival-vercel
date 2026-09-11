from typing import List, Optional
from app.db.models.vulnerability import VulnerabilityFinding
from app.schemas.module3.security_gate import SecurityGatePolicy, SecurityGateResponse


class CIGateEngine:
    """
    Evaluates configurable CI/CD security gate policies against test run findings.
    """

    def evaluate(
        self,
        findings: List[VulnerabilityFinding],
        security_score: int,
        policy: Optional[SecurityGatePolicy] = None
    ) -> SecurityGateResponse:
        """
        Applies policy rules to determine CI/CD build pass/fail status.
        """
        active_policy = policy or SecurityGatePolicy()
        blocking_findings: List[str] = []
        failure_reasons: List[str] = []

        confirmed_criticals = [
            f for f in findings if f.severity.lower() == "critical" and f.status in {"confirmed", "likely"}
        ]
        confirmed_highs = [
            f for f in findings if f.severity.lower() == "high" and f.status in {"confirmed", "likely"}
        ]
        confirmed_mediums = [
            f for f in findings if f.severity.lower() == "medium" and f.status in {"confirmed", "likely"}
        ]

        # 1. Critical Check
        if active_policy.fail_on_critical and len(confirmed_criticals) > 0:
            for f in confirmed_criticals:
                blocking_findings.append(f"{f.finding_id} ({f.title})")
            failure_reasons.append(f"{len(confirmed_criticals)} confirmed Critical vulnerability(ies) detected")

        # 2. High Threshold Check
        if len(confirmed_highs) > active_policy.max_allowed_high:
            for f in confirmed_highs:
                blocking_findings.append(f"{f.finding_id} ({f.title})")
            failure_reasons.append(
                f"{len(confirmed_highs)} High vulnerabilities exceed allowed threshold of {active_policy.max_allowed_high}"
            )

        # 3. Medium Threshold Check
        if len(confirmed_mediums) > active_policy.max_allowed_medium:
            failure_reasons.append(
                f"{len(confirmed_mediums)} Medium vulnerabilities exceed allowed threshold of {active_policy.max_allowed_medium}"
            )

        # 4. Security Score Check
        if security_score < active_policy.min_security_score:
            failure_reasons.append(
                f"Security score ({security_score}) is below required minimum threshold ({active_policy.min_security_score})"
            )

        # Deduplicate blocking findings
        unique_blocking = list(dict.fromkeys(blocking_findings))
        passed = len(failure_reasons) == 0

        status_str = "passed" if passed else "failed"
        exit_code = 0 if passed else 1
        reason_str = "All security gate policies satisfied." if passed else " ; ".join(failure_reasons)

        return SecurityGateResponse(
            status=status_str,
            exit_code=exit_code,
            reason=reason_str,
            security_score=security_score,
            blocking_findings=unique_blocking,
            policy_applied=active_policy,
        )
