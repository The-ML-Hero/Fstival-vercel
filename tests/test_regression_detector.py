from app.db.models.vulnerability import VulnerabilityFinding
from app.services.analyzers.regression_detector import RegressionDetector


def test_regression_detector_finds_reopened_and_new_flaws():
    detector = RegressionDetector()

    # Prior findings: f1 was marked fixed
    prior_f1 = VulnerabilityFinding(
        id="f-1",
        run_id="run-1",
        project_id="proj-1",
        finding_id="VULN-001",
        attack_id="ATK-001",
        title="BOLA on /orders/{id}",
        type="BOLA / IDOR",
        endpoint="/orders/{id}",
        method="GET",
        severity="critical",
        confidence=0.95,
        status="confirmed",
        verification_status="fixed",
        risk_score=90,
        data_sensitivity="high",
        blast_radius_reach="Tenant",
        blast_radius_confidence=0.8,
        remediation_json={},
        evidence_json={},
        steps_json=[],
    )

    # Current findings: f1 re-appeared (REGRESSION), and f2 is newly discovered
    curr_f1 = VulnerabilityFinding(
        id="f-1-new",
        run_id="run-2",
        project_id="proj-1",
        finding_id="VULN-001",
        attack_id="ATK-001",
        title="BOLA on /orders/{id}",
        type="BOLA / IDOR",
        endpoint="/orders/{id}",
        method="GET",
        severity="critical",
        confidence=0.95,
        status="confirmed",
        verification_status="unverified",
        risk_score=90,
        data_sensitivity="high",
        blast_radius_reach="Tenant",
        blast_radius_confidence=0.8,
        remediation_json={},
        evidence_json={},
        steps_json=[],
    )
    curr_f2 = VulnerabilityFinding(
        id="f-2-new",
        run_id="run-2",
        project_id="proj-1",
        finding_id="VULN-002",
        attack_id="ATK-002",
        title="New Flaw",
        type="Authentication Weakness",
        endpoint="/admin/login",
        method="POST",
        severity="high",
        confidence=0.9,
        status="confirmed",
        verification_status="unverified",
        risk_score=80,
        data_sensitivity="high",
        blast_radius_reach="Global",
        blast_radius_confidence=0.9,
        remediation_json={},
        evidence_json={},
        steps_json=[],
    )

    reg_resp = detector.compare_runs(
        project_id="proj-1",
        current_run_id="run-2",
        current_findings=[curr_f1, curr_f2],
        current_score=60,
        previous_run_id="run-1",
        previous_findings=[prior_f1],
        previous_score=90,
    )

    assert len(reg_resp.regressions) == 1
    assert "Re-opened" in reg_resp.regressions[0]["note"]
    assert len(reg_resp.new_vulnerabilities) == 1
    assert reg_resp.score_delta == -30
