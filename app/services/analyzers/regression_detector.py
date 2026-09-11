from typing import Any, Dict, List, Optional
from app.db.models.vulnerability import VulnerabilityFinding
from app.schemas.module3.regression import (
    RegressionResponse,
    ApiChangeImpactResponse,
)


class RegressionDetector:
    """
    Detects regressions, newly introduced vulnerabilities, and resolved security flaws
    across sequential scan runs and API revisions.
    """

    def compare_runs(
        self,
        project_id: str,
        current_run_id: str,
        current_findings: List[VulnerabilityFinding],
        current_score: int,
        previous_run_id: Optional[str],
        previous_findings: List[VulnerabilityFinding],
        previous_score: Optional[int]
    ) -> RegressionResponse:
        """
        Calculates diff between current findings and baseline/previous scan.
        """
        prev_map = {f"{f.endpoint}:{f.method}:{f.type}": f for f in previous_findings}
        curr_map = {f"{f.endpoint}:{f.method}:{f.type}": f for f in current_findings}

        new_vulns: List[Dict[str, Any]] = []
        fixed_vulns: List[Dict[str, Any]] = []
        regressions: List[Dict[str, Any]] = []

        # Check current findings
        for key, curr_f in curr_map.items():
            if key not in prev_map:
                new_vulns.append({
                    "finding_id": curr_f.finding_id,
                    "title": curr_f.title,
                    "endpoint": curr_f.endpoint,
                    "severity": curr_f.severity,
                    "status": curr_f.status,
                })
            else:
                prev_f = prev_map[key]
                # If previously fixed or passing, but now broken again -> REGRESSION
                if prev_f.verification_status == "fixed" or prev_f.status == "false-positive":
                    regressions.append({
                        "finding_id": curr_f.finding_id,
                        "title": curr_f.title,
                        "endpoint": curr_f.endpoint,
                        "severity": curr_f.severity,
                        "note": "Re-opened vulnerability: Was previously marked as fixed or secure.",
                    })

        # Check resolved findings
        for key, prev_f in prev_map.items():
            if key not in curr_map:
                fixed_vulns.append({
                    "finding_id": prev_f.finding_id,
                    "title": prev_f.title,
                    "endpoint": prev_f.endpoint,
                    "severity": prev_f.severity,
                    "note": "No longer detected in current scan run.",
                })

        score_delta = current_score - (previous_score if previous_score is not None else current_score)

        summary = (
            f"Regression Analysis: {len(new_vulns)} new, {len(fixed_vulns)} fixed, "
            f"{len(regressions)} regressions. Security score delta: {score_delta:+d} pts."
        )

        return RegressionResponse(
            project_id=project_id,
            current_run_id=current_run_id,
            previous_run_id=previous_run_id,
            new_vulnerabilities=new_vulns,
            fixed_vulnerabilities=fixed_vulns,
            regressions=regressions,
            score_delta=score_delta,
            summary=summary,
        )

    def analyze_api_change_impact(
        self,
        project_id: str,
        changed_endpoints: List[str],
        all_findings: List[VulnerabilityFinding]
    ) -> ApiChangeImpactResponse:
        """
        Maps modified API endpoints to affected workflows, findings, and recommended re-test scenarios.
        """
        affected_findings: List[str] = []
        affected_workflows: List[str] = []
        retest_scenarios: List[str] = []

        for f in all_findings:
            if any(ep in f.endpoint or f.endpoint in ep for ep in changed_endpoints):
                affected_findings.append(f"{f.finding_id}: {f.title}")
                retest_scenarios.append(f"Retest {f.attack_id} on {f.endpoint}")

        return ApiChangeImpactResponse(
            project_id=project_id,
            changed_endpoints=changed_endpoints,
            affected_workflows=affected_workflows,
            affected_findings=affected_findings,
            recommended_retest_scenarios=list(set(retest_scenarios)),
        )
