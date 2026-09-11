import re
from typing import Any, Dict, List, Optional
from app.core.config import settings
from app.core.logging import logger
from app.schemas.execution_plan import AttackScenario, AttackScenarioStep, ExecutionResultSummary


class AdaptiveAttackEngine:
    """
    Adaptive Attack Engine for Module 2.
    Evaluates attack execution results. When an unexpected response indicates potential vulnerability
    (e.g., BOLA returns 200 on another user's ID, or unauthenticated route returns data),
    it dynamically generates depth-limited follow-up scenarios with strict safety bounds.
    """

    def __init__(
        self,
        max_depth: Optional[int] = None,
        max_requests_per_attack: Optional[int] = None
    ):
        self.max_depth = max_depth if max_depth is not None else settings.MAX_ADAPTIVE_DEPTH
        self.max_requests = max_requests_per_attack if max_requests_per_attack is not None else settings.MAX_ADAPTIVE_REQUESTS_PER_ATTACK

    def evaluate_and_generate_followup(
        self,
        exec_result: ExecutionResultSummary,
        current_depth: int = 1
    ) -> List[AttackScenario]:
        """
        Inspects execution outcome. If safety limit allows and response suggests vulnerability,
        spawns adaptive follow-up scenarios.
        """
        followups: List[AttackScenario] = []

        if current_depth > self.max_depth:
            logger.info(f"Adaptive depth limit reached ({current_depth} > {self.max_depth}). Halting adaptive tree.")
            return followups

        scenario = exec_result.scenario
        actual_status = exec_result.actual_status
        category = scenario.category.lower()

        # 1. BOLA / IDOR Success Detection
        if ("bola" in category or "authorization" in category) and actual_status == 200:
            logger.info(f"Potential BOLA vulnerability on {scenario.attack_id}. Spawning adaptive exploration.")
            endpoint = scenario.endpoint

            for step in scenario.steps:
                path = step.path
                num_matches = re.findall(r"/(\d+)", path)
                if num_matches:
                    current_id = int(num_matches[-1])
                    for offset in range(1, min(self.max_requests + 1, 4)):
                        next_id = current_id + offset
                        new_path = re.sub(r"/\d+", f"/{next_id}", path, count=1)

                        followups.append(AttackScenario(
                            scenario_id=f"{scenario.scenario_id}-ADAPT-ID-{next_id}",
                            attack_id=f"{scenario.attack_id}-ADAPT-{offset}",
                            category="BOLA",
                            endpoint=endpoint,
                            method=step.method,
                            objective=f"Adaptive BOLA test: Verify access boundary on adjacent object ID {next_id}",
                            preconditions=scenario.preconditions,
                            steps=[
                                AttackScenarioStep(
                                    step_number=1,
                                    step_name=f"test_adjacent_id_{next_id}",
                                    method=step.method,
                                    path=new_path,
                                    headers=step.headers,
                                    query_params=step.query_params,
                                    body=step.body,
                                    expected_status=403,
                                )
                            ],
                            mutations=[],
                            expected_secure_behavior="Server enforces object-level authorization and returns HTTP 403 Forbidden.",
                            expected_status=403,
                            severity="critical",
                            priority="critical",
                            role_required=scenario.role_required,
                            is_adaptive=True,
                            parent_attack_id=scenario.attack_id,
                            reason=f"Adaptive follow-up triggered because initial test on ID {current_id} returned HTTP 200 without authorization barrier.",
                        ))

        # 2. Role Escalation / Mass Assignment Success
        elif "role escalation" in category and actual_status == 200:
            logger.info(f"Potential Role Escalation on {scenario.attack_id}. Spawning administrative verification test.")
            followups.append(AttackScenario(
                scenario_id=f"{scenario.scenario_id}-ADAPT-ADMIN-VERIFY",
                attack_id=f"{scenario.attack_id}-ADAPT-1",
                category="Role Escalation",
                endpoint="/admin/dashboard",
                method="GET",
                objective="Verify if self-escalated role enables access to administrative resources",
                preconditions=["User profile successfully updated with role=admin"],
                steps=[
                    AttackScenarioStep(
                        step_number=1,
                        step_name="access_admin_dashboard_with_tampered_role",
                        method="GET",
                        path="/admin/dashboard",
                        headers=scenario.steps[0].headers if scenario.steps else {},
                        expected_status=403,
                    )
                ],
                mutations=[],
                expected_secure_behavior="Server rejects access to administrative console with HTTP 403 Forbidden.",
                expected_status=403,
                severity="critical",
                priority="critical",
                role_required=scenario.role_required,
                is_adaptive=True,
                parent_attack_id=scenario.attack_id,
                reason="Adaptive follow-up verifying persistent administrative access after role property modification.",
            ))

        return followups
