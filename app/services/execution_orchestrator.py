import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.exceptions import ProjectNotFoundError, TargetNotAuthorizedError
from app.core.logging import logger
from app.db.models import (
    Project,
    AttackHypothesis,
    TestRun,
    AttackExecution,
    AttackStepExecution,
    RawExecutionResult,
    AttackReplay,
)
from app.schemas.execution_plan import AttackScenario, AttackScenarioStep, TargetConfig
from app.schemas.test_run import TestRunCreate
from app.schemas.module3_contract import (
    Module3AttackResultItem,
    Module3Evidence,
    Module3ResultExport,
)
from app.services.module1_adapter import Module1AttackPlanAdapter
from app.services.safety.safety_validator import SafetyValidator
from app.services.bruno.generator import BrunoCollectionGenerator
from app.services.bruno.runner import BrunoRunner, ExecutionResultSummary
from app.services.simulation.identity_manager import IdentityManager
from app.services.simulation.workflow_executor import WorkflowExecutor
from app.services.simulation.adaptive_engine import AdaptiveAttackEngine


class Module2ExecutionOrchestrator:
    """
    Master Execution Orchestrator for Module 2.
    Coordinates Safety Validation, Bruno Collection Generation, Test Execution,
    Multi-Role Simulation, Adaptive Exploration, Replays, Persistence, and Module 3 Export.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.adapter = Module1AttackPlanAdapter()
        self.safety_validator = SafetyValidator()
        self.bruno_generator = BrunoCollectionGenerator()
        self.identity_mgr = IdentityManager()
        self.bruno_runner = BrunoRunner(self.identity_mgr)
        self.workflow_executor = WorkflowExecutor(self.bruno_runner)
        self.adaptive_engine = AdaptiveAttackEngine()

    async def create_test_run(
        self,
        project_id: str,
        payload: TestRunCreate
    ) -> TestRun:
        """
        Creates a new TestRun, validates target authorization, and generates Bruno collections on disk.
        """
        stmt = (
            select(Project)
            .where(Project.id == project_id)
            .options(
                selectinload(Project.attack_hypotheses).selectinload(AttackHypothesis.mutations)
            )
        )
        res = await self.db.execute(stmt)
        project = res.scalar_one_or_none()

        if not project:
            raise ProjectNotFoundError(f"Project '{project_id}' not found.")

        target_url = payload.target_base_url or project.target_base_url or "http://localhost:8080/api/v1"
        target_config = TargetConfig(
            base_url=target_url,
            authorized=payload.target_authorized and project.target_authorized,
            environment=payload.environment,
            auth_tokens=payload.auth_tokens or {},
        )

        # 1. Safety check
        self.safety_validator.validate_target(target_config)

        # 2. Create TestRun record
        test_run = TestRun(
            project_id=project_id,
            target_base_url=target_config.base_url,
            target_authorized=target_config.authorized,
            environment=target_config.environment,
            status="pending",
            total_attacks=len(project.attack_hypotheses),
        )
        self.db.add(test_run)
        await self.db.commit()
        await self.db.refresh(test_run)

        # 3. Adapt Module 1 hypotheses to executable scenarios
        mock_plan_dict = {
            "attack_plan": [
                {
                    "attack_id": h.attack_id,
                    "type": h.category,
                    "endpoint": h.endpoint,
                    "method": h.method,
                    "objective": h.objective,
                    "preconditions": h.preconditions,
                    "steps": h.steps,
                    "expected_secure_behavior": h.expected_secure_behavior,
                    "severity": h.severity,
                    "priority": h.priority_level,
                    "reason": h.reason,
                    "mutations": [
                        {
                            "parameter_name": m.parameter_name,
                            "parameter_location": m.parameter_location,
                            "mutation_type": m.mutation_type,
                            "payload_sample": m.payload_sample,
                            "rationale": m.rationale,
                        }
                        for m in h.mutations
                    ]
                }
                for h in project.attack_hypotheses
            ]
        }
        scenarios = self.adapter.parse_attack_plan(mock_plan_dict)

        # 4. Generate Bruno collection on disk
        collection_path = self.bruno_generator.generate_collection(
            project_id=project_id,
            run_id=test_run.id,
            scenarios=scenarios,
            target=target_config
        )
        test_run.collection_path = str(collection_path)
        await self.db.commit()

        return test_run

    async def execute_test_run(
        self,
        run_id: str,
        custom_client: Optional[httpx.AsyncClient] = None
    ) -> TestRun:
        """
        Executes all attack scenarios for the test run, including adaptive follow-ups,
        and saves execution records to the database.
        """
        stmt = (
            select(TestRun)
            .where(TestRun.id == run_id)
            .options(
                selectinload(TestRun.project).selectinload(Project.attack_hypotheses).selectinload(AttackHypothesis.mutations)
            )
        )
        res = await self.db.execute(stmt)
        test_run = res.scalar_one_or_none()

        if not test_run:
            raise ProjectNotFoundError(f"TestRun '{run_id}' not found.")

        target_config = TargetConfig(
            base_url=test_run.target_base_url,
            authorized=test_run.target_authorized,
            environment=test_run.environment,
        )
        self.safety_validator.validate_target(target_config)

        test_run.status = "running"
        test_run.started_at = datetime.now(timezone.utc)
        await self.db.commit()

        # Build scenarios from project attack hypotheses
        project = test_run.project
        plan_dict = {
            "attack_plan": [
                {
                    "attack_id": h.attack_id,
                    "type": h.category,
                    "endpoint": h.endpoint,
                    "method": h.method,
                    "objective": h.objective,
                    "preconditions": h.preconditions,
                    "steps": h.steps,
                    "expected_secure_behavior": h.expected_secure_behavior,
                    "severity": h.severity,
                    "priority": h.priority_level,
                    "reason": h.reason,
                    "mutations": [
                        {
                            "parameter_name": m.parameter_name,
                            "parameter_location": m.parameter_location,
                            "mutation_type": m.mutation_type,
                            "payload_sample": m.payload_sample,
                            "rationale": m.rationale,
                        }
                        for m in h.mutations
                    ]
                }
                for h in project.attack_hypotheses
            ]
        }
        scenarios = self.adapter.parse_attack_plan(plan_dict)

        passed_count = 0
        failed_count = 0
        error_count = 0

        # Execute scenarios (using custom_client if provided e.g. for testing against local demo app)
        if custom_client is not None:
            client = custom_client
            should_close_client = False
        elif "testserver" in target_config.base_url or "testdemo" in target_config.base_url:
            from app.demo_api.server import demo_app
            transport = httpx.ASGITransport(app=demo_app)
            client = httpx.AsyncClient(transport=transport, base_url="http://testdemo", timeout=settings.REQUEST_TIMEOUT_SECONDS)
            should_close_client = True
        else:
            client = httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS)
            should_close_client = True

        try:
            scenario_queue = list(scenarios)
            processed_scenarios = 0

            while scenario_queue:
                scenario = scenario_queue.pop(0)
                processed_scenarios += 1

                # Special handling for Rate-Limit Testing (controlled burst)
                if "rate-limit" in scenario.category.lower():
                    exec_result = await self._execute_rate_limit_burst(scenario, target_config, client)
                else:
                    exec_result = await self.bruno_runner.execute_scenario(scenario, target_config, client)

                # Persist AttackExecution
                attack_exec = AttackExecution(
                    run_id=test_run.id,
                    attack_id=scenario.attack_id,
                    category=scenario.category,
                    endpoint=scenario.endpoint,
                    method=scenario.method,
                    status=exec_result.status,
                    severity=scenario.severity,
                    priority=scenario.priority,
                    expected_status=exec_result.expected_status,
                    actual_status=exec_result.actual_status,
                    duration_ms=exec_result.duration_ms,
                    parent_attack_id=scenario.parent_attack_id,
                    is_adaptive=scenario.is_adaptive,
                    is_replay=False,
                    objective=scenario.objective,
                    reason=scenario.reason,
                    expected_secure_behavior=scenario.expected_secure_behavior,
                )
                self.db.add(attack_exec)
                await self.db.flush()

                # Persist AttackStepExecution items
                for step_res in exec_result.step_results:
                    step_model = AttackStepExecution(
                        execution_id=attack_exec.id,
                        step_number=step_res["step_number"],
                        step_name=step_res["step_name"],
                        method=step_res["method"],
                        url=step_res["url"],
                        request_headers=step_res["request_headers"],
                        request_body=step_res.get("request_body"),
                        response_status=step_res.get("response_status"),
                        response_body=step_res.get("response_body"),
                        response_headers=step_res.get("response_headers", {}),
                        duration_ms=step_res.get("duration_ms", 0.0),
                        assertion_results=step_res.get("assertion_results", []),
                        status=step_res.get("status", "passed"),
                        error_message=step_res.get("error_message"),
                    )
                    self.db.add(step_model)

                # Persist RawExecutionResult
                raw_model = RawExecutionResult(
                    execution_id=attack_exec.id,
                    stdout=exec_result.stdout,
                    stderr=exec_result.stderr,
                    exit_code=exec_result.exit_code,
                    raw_json={"step_count": len(exec_result.step_results), "status": exec_result.status},
                )
                self.db.add(raw_model)

                if exec_result.status == "passed":
                    passed_count += 1
                elif exec_result.status == "failed":
                    failed_count += 1
                else:
                    error_count += 1

                # Trigger Adaptive Engine if scenario is not already deeply nested
                if not scenario.is_adaptive:
                    followups = self.adaptive_engine.evaluate_and_generate_followup(exec_result, current_depth=1)
                    if followups:
                        scenario_queue.extend(followups)

            test_run.status = "completed"
            test_run.completed_at = datetime.now(timezone.utc)
            test_run.total_attacks = processed_scenarios
            test_run.passed_attacks = passed_count
            test_run.failed_attacks = failed_count
            test_run.error_attacks = error_count

        except Exception as e:
            logger.error(f"Test run execution failed: {str(e)}")
            test_run.status = "failed"
            test_run.error_message = str(e)
            test_run.completed_at = datetime.now(timezone.utc)

        finally:
            if should_close_client:
                await client.aclose()

        await self.db.commit()
        await self.db.refresh(test_run)
        return test_run

    async def _execute_rate_limit_burst(
        self,
        scenario: AttackScenario,
        target: TargetConfig,
        client: httpx.AsyncClient
    ) -> ExecutionResultSummary:
        """
        Executes a controlled burst of requests (max 10 requests) to test rate-limiting thresholds safely.
        """
        burst_limit = min(settings.MAX_RATE_LIMIT_TEST_REQUESTS, 10)
        step = scenario.steps[0] if scenario.steps else AttackScenarioStep(step_number=1, step_name="rate_limit", method="GET", path=scenario.endpoint)
        url = self.bruno_runner._build_step_url(target.base_url, step.path, {})
        headers = self.identity_mgr.inject_auth_headers(step.headers, scenario.role_required)

        start_time = asyncio.get_event_loop().time()
        saw_429 = False
        final_status = None
        step_results = []

        for i in range(1, burst_limit + 1):
            try:
                resp = await client.request(
                    method=step.method,
                    url=url,
                    headers=headers,
                    params=step.query_params,
                )
                final_status = resp.status_code
                if resp.status_code == 429:
                    saw_429 = True
                    break
            except Exception:
                pass

        total_duration_ms = round((asyncio.get_event_loop().time() - start_time) * 1000, 2)
        # Passed if 429 encountered, Failed if server allows unrestricted requests without 429
        passed = saw_429
        status = "passed" if passed else "failed"

        step_results.append({
            "step_number": 1,
            "step_name": f"rate_limit_burst_{burst_limit}_requests",
            "method": step.method,
            "url": url,
            "request_headers": self.identity_mgr.redact_sensitive_headers(headers),
            "request_body": None,
            "response_status": final_status,
            "response_body": "[RATE_LIMIT_EVIDENCE_REDACTED]",
            "response_headers": {},
            "duration_ms": total_duration_ms,
            "status": status,
            "assertion_results": [{
                "assertion": "res.status == 429 (Rate Limit Enforced)",
                "actual": final_status,
                "passed": passed
            }],
        })

        return ExecutionResultSummary(
            scenario=scenario,
            status=status,
            actual_status=final_status,
            expected_status=429,
            duration_ms=total_duration_ms,
            step_results=step_results,
            stdout=f"Dispatched {burst_limit} requests. 429 detected: {saw_429}",
            exit_code=0 if passed else 1
        )

    async def replay_attack(
        self,
        run_id: str,
        attack_id: str,
        custom_client: Optional[httpx.AsyncClient] = None
    ) -> AttackReplay:
        """
        Replays a specific attack execution with identical parameters and computes response delta.
        """
        stmt = (
            select(AttackExecution)
            .where(
                AttackExecution.run_id == run_id,
                (AttackExecution.attack_id == attack_id) | (AttackExecution.id == attack_id)
            )
            .options(
                selectinload(AttackExecution.steps),
                selectinload(AttackExecution.run)
            )
        )
        res = await self.db.execute(stmt)
        orig_exec = res.scalar_one_or_none()

        if not orig_exec:
            raise ProjectNotFoundError(f"Attack '{attack_id}' in run '{run_id}' not found.")

        target_config = TargetConfig(
            base_url=orig_exec.run.target_base_url,
            authorized=orig_exec.run.target_authorized,
            environment=orig_exec.run.environment,
        )
        self.safety_validator.validate_target(target_config)

        # Build scenario from original execution steps
        steps = [
            AttackScenarioStep(
                step_number=s.step_number,
                step_name=s.step_name,
                method=s.method,
                path=s.url.replace(target_config.base_url.rstrip("/"), "").lstrip("/"),
                headers=s.request_headers,
                expected_status=orig_exec.expected_status or 403,
            )
            for s in orig_exec.steps
        ] or [
            AttackScenarioStep(
                step_number=1,
                step_name="replay_step",
                method=orig_exec.method,
                path=orig_exec.endpoint,
                expected_status=orig_exec.expected_status or 403,
            )
        ]

        scenario = AttackScenario(
            scenario_id=f"REPLAY-{orig_exec.attack_id}",
            attack_id=f"{orig_exec.attack_id}-REPLAY",
            category=orig_exec.category,
            endpoint=orig_exec.endpoint,
            method=orig_exec.method,
            objective=f"Replay attack {orig_exec.attack_id}",
            steps=steps,
            expected_secure_behavior=orig_exec.expected_secure_behavior or "403 Forbidden",
            expected_status=orig_exec.expected_status or 403,
            severity=orig_exec.severity,
            priority=orig_exec.priority,
            is_replay=True,
        )

        exec_res = await self.bruno_runner.execute_scenario(scenario, target_config, custom_client)

        # Save Replay AttackExecution
        replayed_exec = AttackExecution(
            run_id=run_id,
            attack_id=scenario.attack_id,
            category=orig_exec.category,
            endpoint=orig_exec.endpoint,
            method=orig_exec.method,
            status=exec_res.status,
            severity=orig_exec.severity,
            priority=orig_exec.priority,
            expected_status=exec_res.expected_status,
            actual_status=exec_res.actual_status,
            duration_ms=exec_res.duration_ms,
            parent_attack_id=orig_exec.attack_id,
            is_adaptive=False,
            is_replay=True,
            objective=scenario.objective,
            reason=f"Replay of {orig_exec.attack_id}",
            expected_secure_behavior=orig_exec.expected_secure_behavior,
        )
        self.db.add(replayed_exec)
        await self.db.flush()

        for step_res in exec_res.step_results:
            step_model = AttackStepExecution(
                execution_id=replayed_exec.id,
                step_number=step_res["step_number"],
                step_name=step_res["step_name"],
                method=step_res["method"],
                url=step_res["url"],
                request_headers=step_res["request_headers"],
                request_body=step_res.get("request_body"),
                response_status=step_res.get("response_status"),
                response_body=step_res.get("response_body"),
                response_headers=step_res.get("response_headers", {}),
                duration_ms=step_res.get("duration_ms", 0.0),
                status=step_res.get("status", "passed"),
            )
            self.db.add(step_model)

        is_reproduced = (replayed_exec.actual_status == orig_exec.actual_status) and (replayed_exec.status == orig_exec.status)
        replay_status = "reproduced" if is_reproduced else "changed"
        diff_summary = f"Original Status: {orig_exec.status} ({orig_exec.actual_status}) -> Replay Status: {replayed_exec.status} ({replayed_exec.actual_status})"

        replay_record = AttackReplay(
            original_execution_id=orig_exec.id,
            replayed_execution_id=replayed_exec.id,
            status=replay_status,
            diff_summary=diff_summary,
        )
        self.db.add(replay_record)
        await self.db.commit()

        return replay_record

    async def build_module3_export(self, run_id: str) -> Module3ResultExport:
        """
        Builds the structured result contract for Module 3.
        """
        stmt = (
            select(TestRun)
            .where(TestRun.id == run_id)
            .options(
                selectinload(TestRun.attack_executions).selectinload(AttackExecution.steps)
            )
        )
        res = await self.db.execute(stmt)
        test_run = res.scalar_one_or_none()

        if not test_run:
            raise ProjectNotFoundError(f"TestRun '{run_id}' not found.")

        attack_results: List[Module3AttackResultItem] = []

        for item in test_run.attack_executions:
            first_step = item.steps[0] if item.steps else None
            evidence = Module3Evidence(
                request_headers=first_step.request_headers if first_step else {},
                response_headers=first_step.response_headers if first_step else {},
                response_body=first_step.response_body if first_step else None,
                response_time_ms=item.duration_ms,
                status_code_matched=(item.status == "passed"),
            )

            step_items = [
                {
                    "step": s.step_number,
                    "name": s.step_name,
                    "method": s.method,
                    "url": s.url,
                    "status_code": s.response_status,
                    "duration_ms": s.duration_ms,
                }
                for s in item.steps
            ]

            attack_results.append(
                Module3AttackResultItem(
                    attack_id=item.attack_id,
                    status=item.status,
                    endpoint=item.endpoint,
                    method=item.method,
                    category=item.category,
                    severity=item.severity,
                    priority=item.priority,
                    expected={"status": item.expected_status},
                    actual={"status": item.actual_status},
                    evidence=evidence,
                    steps=step_items,
                    parent_attack_id=item.parent_attack_id,
                    is_adaptive=item.is_adaptive,
                    reproducible=True,
                    objective=item.objective,
                    reason=item.reason,
                )
            )

        summary = {
            "total_attacks": test_run.total_attacks,
            "passed_attacks": test_run.passed_attacks,
            "failed_attacks": test_run.failed_attacks,
            "error_attacks": test_run.error_attacks,
            "status": test_run.status,
            "started_at": test_run.started_at.isoformat() if test_run.started_at else None,
            "completed_at": test_run.completed_at.isoformat() if test_run.completed_at else None,
        }

        target = {
            "base_url": test_run.target_base_url,
            "environment": test_run.environment,
            "authorized": test_run.target_authorized,
        }

        return Module3ResultExport(
            contract_version="1.0.0",
            run_id=test_run.id,
            project_id=test_run.project_id,
            target=target,
            summary=summary,
            attack_results=attack_results,
        )
