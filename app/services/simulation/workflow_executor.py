from typing import Any, Dict, List, Optional, TYPE_CHECKING
from app.schemas.execution_plan import AttackScenario, AttackScenarioStep, TargetConfig

if TYPE_CHECKING:
    from app.services.bruno.runner import BrunoRunner, ExecutionResultSummary


class WorkflowExecutor:
    """
    Stateful workflow execution engine.
    Executes ordered or altered multi-step business logic attack scenarios
    (e.g., out-of-order execution, replay, race condition simulations).
    """

    def __init__(self, runner: Optional[Any] = None):
        self._runner = runner

    def get_runner(self) -> Any:
        if self._runner is None:
            from app.services.bruno.runner import BrunoRunner
            self._runner = BrunoRunner()
        return self._runner

    async def execute_workflow(
        self,
        scenario: AttackScenario,
        target: TargetConfig
    ) -> Any:
        """
        Executes a multi-step workflow scenario, maintaining state context across steps.
        """
        runner = self.get_runner()
        return await runner.execute_scenario(scenario, target)

    def create_out_of_order_scenario(
        self,
        base_scenario: AttackScenario,
        reversed_step_indices: List[int],
        suffix: str = "OUT-OF-ORDER"
    ) -> AttackScenario:
        """
        Generates an altered workflow scenario where steps are reordered (e.g. refund before payment).
        """
        reordered_steps: List[AttackScenarioStep] = []
        for new_idx, orig_idx in enumerate(reversed_step_indices):
            if 0 <= orig_idx < len(base_scenario.steps):
                orig_step = base_scenario.steps[orig_idx]
                reordered_steps.append(
                    AttackScenarioStep(
                        step_number=new_idx + 1,
                        step_name=f"{orig_step.step_name}_altered_order",
                        method=orig_step.method,
                        path=orig_step.path,
                        headers=orig_step.headers,
                        query_params=orig_step.query_params,
                        body=orig_step.body,
                        expected_status=400,
                    )
                )

        return AttackScenario(
            scenario_id=f"{base_scenario.scenario_id}-{suffix}",
            attack_id=f"{base_scenario.attack_id}-{suffix}",
            category="Business Logic",
            endpoint=base_scenario.endpoint,
            method=base_scenario.method,
            objective=f"Test out-of-order execution against {base_scenario.endpoint}",
            preconditions=base_scenario.preconditions,
            steps=reordered_steps,
            mutations=base_scenario.mutations,
            expected_secure_behavior="Server rejects premature or out-of-order state transitions with HTTP 400/409/422.",
            expected_status=400,
            severity="high",
            priority="high",
            role_required=base_scenario.role_required,
            is_adaptive=True,
            parent_attack_id=base_scenario.attack_id,
            reason="Verify backend state-machine enforcement when steps are issued out of normal sequence.",
        )
