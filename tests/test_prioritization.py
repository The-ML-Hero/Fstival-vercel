from app.schemas.ai_models import AIAttackHypothesis
from app.services.analyzers.attack_prioritizer import AttackPrioritizer


def test_attack_prioritization_and_scoring():
    prioritizer = AttackPrioritizer(
        w_sev=0.40,
        w_exp=0.30,
        w_conf=0.15,
        w_imp=0.15
    )

    score_crit, level_crit = prioritizer.calculate_score(
        severity="critical",
        exploitability=0.95,
        confidence=0.90,
        impact=0.95
    )
    assert score_crit >= 8.0
    assert level_crit == "critical"

    score_low, level_low = prioritizer.calculate_score(
        severity="low",
        exploitability=0.30,
        confidence=0.40,
        impact=0.20
    )
    assert score_low < 4.0
    assert level_low == "low"

    hypotheses = [
        AIAttackHypothesis(
            attack_id="ATK-001",
            category="HTTP Method Abuse",
            endpoint="/info",
            method="DELETE",
            objective="Method test",
            expected_secure_behavior="405",
            reason="Reason",
            severity="low",
            exploitability=0.2,
            impact=0.2,
            confidence=0.5
        ),
        AIAttackHypothesis(
            attack_id="ATK-002",
            category="BOLA",
            endpoint="/patients/{id}",
            method="GET",
            objective="BOLA test",
            expected_secure_behavior="403",
            reason="Reason",
            severity="critical",
            exploitability=0.9,
            impact=0.9,
            confidence=0.9
        )
    ]

    prioritized = prioritizer.prioritize_hypotheses(hypotheses)
    assert len(prioritized) == 2
    # Highest score first
    assert prioritized[0][0].attack_id == "ATK-002"
    assert prioritized[0][2] == "critical"
    assert prioritized[1][0].attack_id == "ATK-001"
