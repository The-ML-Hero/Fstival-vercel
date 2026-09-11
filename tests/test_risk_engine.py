from app.services.analyzers.risk_engine import RiskEngine


def test_finding_risk_score_and_breakdown():
    engine = RiskEngine()
    assessment = engine.calculate_finding_risk(
        severity="critical",
        confidence_status="confirmed",
        data_sensitivity="high",
        exploitability=1.0,
        reach_level="All System",
    )

    assert assessment.risk_score == 100
    assert assessment.severity == "critical"
    assert "Severity (40.0)" in assessment.breakdown.calculation_formula
    assert "Exploitability (25.0)" in assessment.breakdown.calculation_formula
    assert "Confidence (15.0)" in assessment.breakdown.calculation_formula
    assert "Sensitivity (10.0)" in assessment.breakdown.calculation_formula
    assert "Reach (10.0)" in assessment.breakdown.calculation_formula
    assert len(assessment.reasoning) > 0


def test_project_security_score_calculation():
    engine = RiskEngine()

    # Clean project (no findings) -> 100 score
    clean_score = engine.calculate_project_security_score(run_id="run-1", findings_severities=[])
    assert clean_score.security_score == 100
    assert clean_score.risk_level == "low"

    # Vulnerable project with 2 criticals + 1 high -> 100 - (2*25 + 1*12) = 38 score
    vuln_score = engine.calculate_project_security_score(
        run_id="run-2",
        findings_severities=["critical", "critical", "high"]
    )
    assert vuln_score.security_score == 38
    assert vuln_score.risk_level == "critical"
    assert vuln_score.critical_count == 2
    assert vuln_score.high_count == 1
