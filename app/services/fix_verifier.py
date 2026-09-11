from datetime import datetime, timezone
from typing import Optional
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import ProjectNotFoundError
from app.db.models import (
    VulnerabilityFinding,
    TestRun,
    AttackExecution,
    FixVerification,
)
from app.schemas.execution_plan import AttackScenario, AttackScenarioStep, TargetConfig
from app.schemas.module3.verification import FixVerificationResponse
from app.services.bruno.runner import BrunoRunner


class FixVerifier:
    """
    Automated Fix Verification Service for Module 3.
    Re-executes original attack tests against patched target APIs and determines
    whether vulnerabilities are FIXED, NOT FIXED, or have caused REGRESSIONS.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.runner = BrunoRunner()

    async def verify_fix(
        self,
        finding_id: str,
        override_base_url: Optional[str] = None,
        custom_client: Optional[httpx.AsyncClient] = None
    ) -> FixVerificationResponse:
        """
        Re-runs the attack test corresponding to finding_id and updates verification status.
        """
        stmt = (
            select(VulnerabilityFinding)
            .where(
                (VulnerabilityFinding.id == finding_id) | (VulnerabilityFinding.finding_id == finding_id)
            )
        )
        res = await self.db.execute(stmt)
        finding = res.scalar_one_or_none()

        if not finding:
            raise ProjectNotFoundError(f"Vulnerability finding '{finding_id}' not found.")

        # Fetch original test run
        test_run = await self.db.get(TestRun, finding.run_id)
        if not test_run:
            raise ProjectNotFoundError(f"Associated test run '{finding.run_id}' not found.")

        target_base_url = override_base_url or test_run.target_base_url
        target_config = TargetConfig(
            base_url=target_base_url,
            authorized=test_run.target_authorized,
            environment=test_run.environment,
        )

        # Build scenario from finding's steps
        steps = []
        for s in finding.steps_json:
            steps.append(
                AttackScenarioStep(
                    step_number=s.get("step", 1),
                    step_name=s.get("name", "verification_step"),
                    method=s.get("method", finding.method),
                    path=s.get("url", finding.endpoint).replace(target_config.base_url.rstrip("/"), "").lstrip("/"),
                    expected_status=403 if "bola" in finding.type.lower() or "authorization" in finding.type.lower() else 401,
                )
            )
        if not steps:
            steps = [
                AttackScenarioStep(
                    step_number=1,
                    step_name="verify_fix_probe",
                    method=finding.method,
                    path=finding.endpoint,
                    expected_status=403,
                )
            ]

        scenario = AttackScenario(
            scenario_id=f"VERIFY-{finding.finding_id}",
            attack_id=f"{finding.attack_id}-VERIFY",
            category=finding.type,
            endpoint=finding.endpoint,
            method=finding.method,
            objective=f"Verify fix for {finding.finding_id}",
            steps=steps,
            expected_secure_behavior="Endpoint properly enforces security controls and rejects unauthorized access.",
            expected_status=steps[0].expected_status,
            severity=finding.severity,
            priority="high",
            role_required="user",
        )

        # Execute test
        exec_summary = await self.runner.execute_scenario(scenario, target_config, custom_client)

        previous_status = finding.status  # e.g. "confirmed"
        actual_code = exec_summary.actual_status

        # Evaluate fix result
        # If API returned 403/401/400/429 (blocked as expected) -> FIXED
        if exec_summary.status == "passed" or actual_code in {401, 403, 400, 404, 422, 429}:
            result = "fixed"
            new_status = "resolved"
            diff_summary = (
                f"FIX VERIFIED: Target API now successfully enforces access control. "
                f"Previous status allowed unauthorized HTTP 200 -> Now correctly returns HTTP {actual_code}."
            )
        elif actual_code == 500:
            result = "regression"
            new_status = "unresolved"
            diff_summary = f"REGRESSION: Target API crashed with HTTP 500 Internal Server Error during fix verification."
        else:
            result = "not_fixed"
            new_status = "confirmed"
            diff_summary = (
                f"NOT FIXED: Vulnerability is still active. Target API returned HTTP {actual_code} "
                f"instead of expected secure rejection (HTTP {scenario.expected_status})."
            )

        # Update finding status in DB
        finding.verification_status = result
        if result == "fixed":
            finding.status = "false-positive"  # No longer an active flaw in the current state

        # Create FixVerification record
        verification_record = FixVerification(
            finding_id=finding.id,
            run_id=finding.run_id,
            previous_status=previous_status,
            new_status=new_status,
            result=result,
            diff_summary=diff_summary,
            verified_at=datetime.now(timezone.utc),
        )
        self.db.add(verification_record)
        await self.db.commit()

        return FixVerificationResponse(
            finding_id=finding.finding_id,
            previous_status=previous_status,
            new_status=new_status,
            result=result,
            diff_summary=diff_summary,
            verified_at=verification_record.verified_at,
        )
