from typing import Any, Dict, List, Union
from app.schemas.module2_contract import Module2AttackPlanExport
from app.schemas.module3_contract import Module3ResultExport, Module3AttackResultItem
from app.schemas.module3.observation import SecurityObservation


class Module2ResultAdapter:
    """
    Adapter that consumes Module 2's stable result contract (JSON/dict/model)
    and normalizes all raw execution outputs into typed SecurityObservation objects.
    Decoupled from Module 2 internal classes.
    """

    def normalize_results(
        self,
        raw_export: Union[Module3ResultExport, Dict[str, Any]]
    ) -> List[SecurityObservation]:
        """
        Transforms Module 2 result export into a normalized list of SecurityObservations.
        """
        if hasattr(raw_export, "model_dump"):
            data = raw_export.model_dump()
        elif isinstance(raw_export, dict):
            data = raw_export
        else:
            raise ValueError(f"Unsupported Module 2 result format: {type(raw_export)}")

        attack_results = data.get("attack_results", [])
        observations: List[SecurityObservation] = []

        for item in attack_results:
            attack_id = item.get("attack_id", "UNKNOWN-ATK")
            category = item.get("category", "General")
            endpoint = item.get("endpoint", "/")
            method = item.get("method", "GET").upper()
            status = item.get("status", "completed")  # "passed", "failed", "error"

            expected = item.get("expected", {})
            actual = item.get("actual", {})
            expected_status = expected.get("status") if isinstance(expected, dict) else None
            actual_status = actual.get("status") if isinstance(actual, dict) else None

            evidence = item.get("evidence", {})
            req_headers = evidence.get("request_headers", {})
            resp_headers = evidence.get("response_headers", {})
            resp_body = evidence.get("response_body")
            duration_ms = evidence.get("response_time_ms", 0.0)
            status_matched = evidence.get("status_code_matched", False)

            steps = item.get("steps", [])
            objective = item.get("objective")
            reason = item.get("reason")
            is_adaptive = item.get("is_adaptive", False)
            parent_attack_id = item.get("parent_attack_id")

            observation = SecurityObservation(
                attack_id=attack_id,
                category=category,
                endpoint=endpoint,
                method=method,
                status=status,
                expected_status=expected_status,
                actual_status=actual_status,
                status_code_matched=status_matched,
                duration_ms=duration_ms,
                request_headers=req_headers,
                response_headers=resp_headers,
                response_body=resp_body,
                steps=steps,
                objective=objective,
                reason=reason,
                is_adaptive=is_adaptive,
                parent_attack_id=parent_attack_id,
            )
            observations.append(observation)

        return observations
