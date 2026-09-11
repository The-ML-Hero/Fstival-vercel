import os
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession
from app.demo_api.server import demo_app
from app.db.models import Project, TestRun, VulnerabilityFinding
from app.services.fix_verifier import FixVerifier


@pytest.mark.asyncio
async def test_live_fix_verification_before_and_after_patch(db_session: AsyncSession):
    # 1. Reset vulnerabilities to initial (unpatched/vulnerable) state
    from app.demo_api import server as demo_server
    demo_server.PATCH_VULNERABILITIES = False

    # 2. Setup project & test run targeting demo API using test db_session
    proj = Project(name="Live Fix Demo Project", target_authorized=True)
    db_session.add(proj)
    await db_session.commit()
    await db_session.refresh(proj)
    project_id = proj.id

    run = TestRun(
        project_id=project_id,
        target_base_url="http://testdemo",
        target_authorized=True,
        environment="local",
        status="completed",
    )
    db_session.add(run)
    await db_session.commit()
    await db_session.refresh(run)
    run_id = run.id

    # Insert a detected BOLA finding
    finding = VulnerabilityFinding(
        run_id=run_id,
        project_id=project_id,
        finding_id="VULN-BOLA-102",
        attack_id="ATK-BOLA-102",
        title="Broken Object Level Authorization on GET /patients/102",
        type="BOLA / IDOR",
        endpoint="/patients/102",
        method="GET",
        severity="critical",
        confidence=0.95,
        status="confirmed",
        verification_status="unverified",
        risk_score=95,
        data_sensitivity="high",
        blast_radius_reach="All Tenant Resources",
        blast_radius_confidence=0.85,
        remediation_json={},
        evidence_json={"actual_status": 200},
        steps_json=[{"step": 1, "url": "http://testdemo/patients/102", "method": "GET"}],
    )
    db_session.add(finding)
    await db_session.commit()
    await db_session.refresh(finding)
    finding_db_id = finding.id

    # 3. Step 1: Verify before patch (Server is still vulnerable)
    transport = ASGITransport(app=demo_app)
    async with AsyncClient(transport=transport, base_url="http://testdemo") as demo_client:
        verifier = FixVerifier(db_session)
        unfixed_res = await verifier.verify_fix(
            finding_id=finding_db_id,
            custom_client=demo_client
        )
        assert unfixed_res.result == "not_fixed"
        assert "NOT FIXED" in unfixed_res.diff_summary

        # 4. Step 2: Developer fixes the vulnerability on the target API
        demo_server.PATCH_VULNERABILITIES = True

        # 5. Step 3: Verify after patch (Target now enforces ownership check and returns 403 Forbidden)
        fixed_res = await verifier.verify_fix(
            finding_id=finding_db_id,
            custom_client=demo_client
        )
        assert fixed_res.result == "fixed"
        assert "FIX VERIFIED" in fixed_res.diff_summary
        assert "403" in fixed_res.diff_summary

    # Reset for other tests
    demo_server.PATCH_VULNERABILITIES = False
