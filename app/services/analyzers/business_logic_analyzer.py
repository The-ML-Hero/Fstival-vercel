from typing import Any, Dict, List
from app.schemas.ai_models import AIAttackHypothesis, AIAttackMutation


class BusinessLogicAnalyzer:
    """
    Generates intelligent business logic and workflow flaw attack hypotheses.
    Identifies out-of-order execution, race conditions, state machine tampering, and replay vectors.
    """

    def generate_workflow_attack_hypotheses(
        self,
        workflows: List[Any],
        endpoints_raw: List[Dict[str, Any]],
        start_counter: int = 1
    ) -> List[AIAttackHypothesis]:
        hypotheses: List[AIAttackHypothesis] = []
        counter = start_counter

        for wf in workflows:
            wf_name = wf.workflow_name if hasattr(wf, "workflow_name") else wf.get("workflow_name", "")
            raw_steps = wf.steps if hasattr(wf, "steps") else wf.get("steps", [])

            # Normalize steps
            steps: List[Dict[str, Any]] = []
            for s in raw_steps:
                if hasattr(s, "model_dump"):
                    steps.append(s.model_dump())
                elif isinstance(s, dict):
                    steps.append(s)
                else:
                    steps.append({
                        "step_number": getattr(s, "step_number", 1),
                        "step_name": getattr(s, "step_name", "step"),
                        "endpoint": getattr(s, "endpoint", "/"),
                        "method": getattr(s, "method", "GET"),
                        "description": getattr(s, "description", None),
                    })

            step_names = [s.get("step_name", "").lower() for s in steps]

            # 1. E-Commerce Payment / Refund Ordering Flaws
            has_refund = any("refund" in name for name in step_names)

            if has_refund:
                refund_step = next(s for s in steps if "refund" in s.get("step_name", "").lower())
                ref_endpoint = refund_step.get("endpoint", "/refund")
                ref_method = refund_step.get("method", "POST")

                # Scenario A: Refund before Payment
                hypotheses.append(AIAttackHypothesis(
                    attack_id=f"ATK-{counter:03d}",
                    category="Business Logic",
                    endpoint=ref_endpoint,
                    method=ref_method,
                    objective="Determine if a refund can be executed against an un-settled, unpaid, or pending order.",
                    preconditions=[
                        "Order exists in pending/unpaid status",
                        "Attacker has access to order identifier"
                    ],
                    steps=[
                        "1. Create a new order without completing the payment step",
                        f"2. Send {ref_method} request to {ref_endpoint} referencing the unpaid order_id",
                        "3. Check if server processes credit/refund without verifying payment settlement status"
                    ],
                    expected_secure_behavior="Server rejects the request with 400 Bad Request or 422 Unprocessable Entity stating order is unpaid.",
                    reason="Incomplete state-machine validation allows premature state transitions in multi-step settlement workflows.",
                    severity="high",
                    exploitability=0.85,
                    impact=0.95,
                    confidence=0.88,
                    mutations=[
                        AIAttackMutation(
                            parameter_name="order_id",
                            parameter_location="body" if "{order" not in ref_endpoint else "path",
                            mutation_type="unpaid_order_state",
                            payload_sample="ORDER-PENDING-UNPAID-999",
                            rationale="Supply unpaid order ID directly to refund processing endpoint."
                        )
                    ]
                ))
                counter += 1

                # Scenario B: Double Refund / Replay
                hypotheses.append(AIAttackHypothesis(
                    attack_id=f"ATK-{counter:03d}",
                    category="Business Logic",
                    endpoint=ref_endpoint,
                    method=ref_method,
                    objective="Determine if multiple concurrent refund requests trigger a double-refund / race condition.",
                    preconditions=[
                        "Valid paid order exists",
                        "Refund capability is available"
                    ],
                    steps=[
                        "1. Complete a normal purchase order and payment",
                        f"2. Dispatch 10 concurrent {ref_method} requests to {ref_endpoint} with the same payment/order ID",
                        "3. Verify if ledger balance is credited multiple times"
                    ],
                    expected_secure_behavior="First request succeeds (200 OK), subsequent concurrent requests fail with 409 Conflict or 400 Bad Request.",
                    reason="Lack of distributed locks or idempotent transaction keys allows race conditions during balance crediting.",
                    severity="critical",
                    exploitability=0.75,
                    impact=0.98,
                    confidence=0.85,
                    mutations=[
                        AIAttackMutation(
                            parameter_name="idempotency_key",
                            parameter_location="header",
                            mutation_type="omitted_idempotency",
                            payload_sample="",
                            rationale="Omit or duplicate idempotency tokens during concurrent refund dispatch."
                        )
                    ]
                ))
                counter += 1

            # 2. Healthcare / Clinical Step-Skipping
            if "Patient Management Workflow" in wf_name or "appointment" in wf_name.lower():
                app_step = next((s for s in steps if "appointment" in s.get("step_name", "").lower() or "prescri" in s.get("step_name", "").lower()), None)
                if app_step:
                    app_endpoint = app_step.get("endpoint", "/appointments")
                    app_method = app_step.get("method", "POST")
                    hypotheses.append(AIAttackHypothesis(
                        attack_id=f"ATK-{counter:03d}",
                        category="Business Logic",
                        endpoint=app_endpoint,
                        method=app_method,
                        objective="Determine if clinical action can be scheduled or executed without an authorized active patient record.",
                        preconditions=[
                            "Attacker has doctor/staff session or valid API token"
                        ],
                        steps=[
                            f"1. Directly issue {app_method} to {app_endpoint} using a fabricated or deleted patient ID",
                            "2. Observe whether clinical record is created in orphaned state"
                        ],
                        expected_secure_behavior="API verifies active patient relationship and returns 404 Not Found or 403 Forbidden.",
                        reason="Workflow relies on UI navigation sequence rather than backend relational integrity checks.",
                        severity="medium",
                        exploitability=0.70,
                        impact=0.75,
                        confidence=0.82,
                        mutations=[
                            AIAttackMutation(
                                parameter_name="patient_id",
                                parameter_location="body" if "{patient" not in app_endpoint else "path",
                                mutation_type="orphaned_foreign_id",
                                payload_sample="NONEXISTENT-OR-DELETED-PATIENT-001",
                                rationale="Test orphaned record creation."
                            )
                        ]
                    ))
                    counter += 1

            # 3. State-Machine Direct Modification (PUT/PATCH on completed resource)
            if len(steps) >= 3:
                update_step = next((s for s in steps if s.get("method") in {"PUT", "PATCH"}), None)
                if update_step:
                    upd_endpoint = update_step.get("endpoint", "/update")
                    upd_method = update_step.get("method", "PUT")
                    hypotheses.append(AIAttackHypothesis(
                        attack_id=f"ATK-{counter:03d}",
                        category="Business Logic",
                        endpoint=upd_endpoint,
                        method=upd_method,
                        objective="Determine if resource attributes (such as status, role, or prices) can be modified after entity completion/closure.",
                        preconditions=[
                            "Target resource exists in finalized/closed state"
                        ],
                        steps=[
                            "1. Advance resource lifecycle to completed / archived status",
                            f"2. Issue {upd_method} request to {upd_endpoint} attempting to alter status or protected values",
                            "3. Verify if backend updates immutable records"
                        ],
                        expected_secure_behavior="Server rejects modifications to finalized resources with 403 Forbidden or 409 Conflict.",
                        reason="Missing state machine immutability guards allow retroactive tampering with finalized transactions.",
                        severity="high",
                        exploitability=0.80,
                        impact=0.85,
                        confidence=0.84,
                        mutations=[
                            AIAttackMutation(
                                parameter_name="status",
                                parameter_location="body",
                                mutation_type="state_transition_override",
                                payload_sample='{"status": "APPROVED", "is_paid": true}',
                                rationale="Attempt direct modification of restricted state lifecycle properties."
                            )
                        ]
                    ))
                    counter += 1

        return hypotheses
