from app.db.models.vulnerability import VulnerabilityFinding
from app.schemas.module3.security_gate import SecurityGatePolicy
from app.services.analyzers.ci_gate_engine import CIGateEngine


def test_ci_security_gate_fails_on_confirmed_critical():
    engine = CIGateEngine()
    findings = [
        VulnerabilityFinding(
            id="f-1",
            run_id="run-1",
            project_id="proj-1",
            finding_id="VULN-001",
            attack_id="ATK-001",
            title="Critical BOLA",
            type="BOLA / IDOR",
            endpoint="/patients/102",
            method="GET",
            severity="critical",
            confidence=0.95,
            status="confirmed",
            verification_status="unverified",
            risk_score=95,
            data_sensitivity="high",
            blast_radius_reach="Tenant",
            blast_radius_confidence=0.8,
            remediation_json={},
            evidence_json={},
            steps_json=[],
        )
    ]

    policy = SecurityGatePolicy(fail_on_critical=True, min_security_score=80)
    res = engine.evaluate(findings, security_score=70, policy=policy)

    assert res.status == "failed"
    assert res.exit_code == 1
    assert len(res.blocking_findings) == 1
    assert "Critical vulnerability" in res.reason


def test_ci_security_gate_passes_clean_scan():
    engine = CIGateEngine()
    policy = SecurityGatePolicy(fail_on_critical=True, min_security_score=80)
    res = engine.evaluate([], security_score=100, policy=policy)

    assert res.status == "passed"
    assert res.exit_code == 0
    assert len(res.blocking_findings) == 0
