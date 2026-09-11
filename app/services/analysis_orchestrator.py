from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import ProjectNotFoundError
from app.core.logging import logger
from app.db.models import (
    Project,
    TestRun,
    VulnerabilityFinding,
    AttackGraphModel,
    AttackChainModel,
    SecurityScanSummary,
    RegressionRecord,
)
from app.schemas.module3.finding import VulnerabilityFindingResponse, RemediationRecommendation
from app.schemas.module3.graph import AttackChainResponse
from app.schemas.module3.report import ExecutiveReportResponse
from app.schemas.module3.security_gate import SecurityGatePolicy, SecurityGateResponse
from app.schemas.module3_contract import Module3ResultExport
from app.services.module2_adapter import Module2ResultAdapter
from app.services.analyzers.evidence_verifier import EvidenceVerifier
from app.services.analyzers.vulnerability_classifier import VulnerabilityClassifier
from app.services.analyzers.risk_engine import RiskEngine
from app.services.analyzers.blast_radius_engine import BlastRadiusEngine
from app.services.analyzers.attack_graph_builder import AttackGraphBuilder
from app.services.analyzers.ai_explanation_engine import AIExplanationEngine
from app.services.analyzers.remediation_engine import RemediationEngine
from app.services.analyzers.regression_detector import RegressionDetector
from app.services.analyzers.ci_gate_engine import CIGateEngine
from app.services.execution_orchestrator import Module2ExecutionOrchestrator


class Module3AnalysisOrchestrator:
    """
    Master Analysis Orchestrator for Module 3.
    Coordinates Ingestion, Evidence Verification, Vulnerability Classification,
    Risk Scoring, Blast Radius, Attack Graphs, AI Explanations, Remediation Generation,
    Regression Tracking, Security History, CI/CD Gate, and Reporting.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.adapter = Module2ResultAdapter()
        self.evidence_verifier = EvidenceVerifier()
        self.classifier = VulnerabilityClassifier()
        self.risk_engine = RiskEngine()
        self.blast_radius_engine = BlastRadiusEngine()
        self.graph_builder = AttackGraphBuilder()
        self.ai_explainer = AIExplanationEngine()
        self.remediation_engine = RemediationEngine()
        self.regression_detector = RegressionDetector()
        self.ci_gate_engine = CIGateEngine()

    async def analyze_run(
        self,
        run_id: str,
        export_contract: Optional[Module3ResultExport] = None
    ) -> List[VulnerabilityFinding]:
        """
        Executes end-to-end Module 3 analysis pipeline for a test run.
        """
        stmt = select(TestRun).where(TestRun.id == run_id)
        res = await self.db.execute(stmt)
        test_run = res.scalar_one_or_none()

        if not test_run:
            raise ProjectNotFoundError(f"TestRun '{run_id}' not found.")

        # 1. Obtain Module 2 export contract if not passed directly
        if not export_contract:
            exec_orch = Module2ExecutionOrchestrator(self.db)
            export_contract = await exec_orch.build_module3_export(run_id)

        # 2. Normalize results into SecurityObservation objects
        observations = self.adapter.normalize_results(export_contract)

        # Clear any prior findings for this run to avoid duplicates on re-analysis
        del_stmt = select(VulnerabilityFinding).where(VulnerabilityFinding.run_id == run_id)
        del_res = await self.db.execute(del_stmt)
        for old_f in del_res.scalars().all():
            await self.db.delete(old_f)

        findings: List[VulnerabilityFinding] = []
        finding_counter = 1

        for obs in observations:
            # 3. Evidence Verification
            ver_res = self.evidence_verifier.verify(obs)

            # If evidence verifies that this is NOT vulnerable (e.g. false-positive or passed), skip or flag
            if not ver_res.is_vulnerable:
                continue

            # 4. Vulnerability Classification
            std_type, title, base_sev = self.classifier.classify(obs)

            # 5. Blast Radius & Business Impact
            blast_res = self.blast_radius_engine.analyze_blast_radius(obs, std_type, ver_res.data_sensitivity)
            impact_res = self.blast_radius_engine.analyze_business_impact(obs, std_type, ver_res.data_sensitivity)

            # 6. Risk Engine Calculation
            risk_res = self.risk_engine.calculate_finding_risk(
                severity=base_sev,
                confidence_status=ver_res.status,
                data_sensitivity=ver_res.data_sensitivity,
                exploitability=0.9 if obs.actual_status == 200 else 0.6,
                reach_level=blast_res.estimated_reach,
            )

            # 7. AI Explanations
            ai_exp = self.ai_explainer.generate_explanations(obs, std_type, base_sev)

            # 8. Remediation Generation
            remediation = self.remediation_engine.generate_remediation(obs, std_type)

            finding = VulnerabilityFinding(
                run_id=run_id,
                project_id=test_run.project_id,
                finding_id=f"VULN-{finding_counter:03d}",
                attack_id=obs.attack_id,
                title=title,
                type=std_type,
                endpoint=obs.endpoint,
                method=obs.method,
                severity=base_sev,
                confidence=ver_res.confidence,
                status=ver_res.status,
                verification_status="unverified",
                risk_score=risk_res.risk_score,
                data_sensitivity=ver_res.data_sensitivity,
                risk_breakdown=risk_res.breakdown.model_dump(),
                confirmed_impact=impact_res.confirmed_impact,
                potential_impact=impact_res.potential_impact,
                blast_radius_reach=blast_res.estimated_reach,
                blast_radius_confidence=blast_res.confidence,
                blast_radius_reasoning=blast_res.reasoning,
                technical_explanation=ai_exp.technical_explanation,
                simple_explanation=ai_exp.simple_explanation,
                evidence_explanation=ai_exp.evidence_explanation,
                why_it_matters=ai_exp.why_it_matters,
                remediation_json=remediation.model_dump(),
                evidence_json={
                    "request_headers": obs.request_headers,
                    "response_headers": obs.response_headers,
                    "response_body": obs.response_body,
                    "duration_ms": obs.duration_ms,
                    "actual_status": obs.actual_status,
                    "expected_status": obs.expected_status,
                },
                steps_json=obs.steps,
            )
            self.db.add(finding)
            findings.append(finding)
            finding_counter += 1

        await self.db.flush()

        # 9. Build Attack Graph and Detect Chains
        graph_resp, chains = self.graph_builder.build_graph(run_id, findings)

        # Persist Attack Graph
        graph_stmt = select(AttackGraphModel).where(AttackGraphModel.run_id == run_id)
        existing_g = (await self.db.execute(graph_stmt)).scalar_one_or_none()
        if existing_g:
            existing_g.nodes_json = [n.model_dump() for n in graph_resp.nodes]
            existing_g.edges_json = [e.model_dump() for e in graph_resp.edges]
        else:
            graph_model = AttackGraphModel(
                run_id=run_id,
                project_id=test_run.project_id,
                nodes_json=[n.model_dump() for n in graph_resp.nodes],
                edges_json=[e.model_dump() for e in graph_resp.edges],
            )
            self.db.add(graph_model)

        # Persist Attack Chains
        del_chain_stmt = select(AttackChainModel).where(AttackChainModel.run_id == run_id)
        del_chains = (await self.db.execute(del_chain_stmt)).scalars().all()
        for dc in del_chains:
            await self.db.delete(dc)

        for ch in chains:
            chain_model = AttackChainModel(
                run_id=run_id,
                chain_id=ch.chain_id,
                title=ch.title,
                overall_risk=ch.overall_risk,
                explanation=ch.explanation,
                nodes_json=[n.model_dump() for n in ch.nodes],
                edges_json=[e.model_dump() for e in ch.edges],
            )
            self.db.add(chain_model)

        # 10. Security Score & CI Gate
        score_resp = self.risk_engine.calculate_project_security_score(
            run_id=run_id,
            findings_severities=[f.severity for f in findings]
        )
        gate_resp = self.ci_gate_engine.evaluate(findings, score_resp.security_score)

        # 11. Regression Detection against prior scan of this project
        prior_scan_stmt = (
            select(SecurityScanSummary)
            .where(SecurityScanSummary.project_id == test_run.project_id, SecurityScanSummary.run_id != run_id)
            .order_by(desc(SecurityScanSummary.scanned_at))
        )
        prior_scan = (await self.db.execute(prior_scan_stmt)).scalars().first()

        prior_findings: List[VulnerabilityFinding] = []
        prior_score = None
        if prior_scan:
            prior_findings_stmt = select(VulnerabilityFinding).where(VulnerabilityFinding.run_id == prior_scan.run_id)
            prior_findings = (await self.db.execute(prior_findings_stmt)).scalars().all()
            prior_score = prior_scan.security_score

        reg_resp = self.regression_detector.compare_runs(
            project_id=test_run.project_id,
            current_run_id=run_id,
            current_findings=findings,
            current_score=score_resp.security_score,
            previous_run_id=prior_scan.run_id if prior_scan else None,
            previous_findings=prior_findings,
            previous_score=prior_score,
        )

        # Record regressions in DB
        for reg_item in reg_resp.regressions:
            reg_record = RegressionRecord(
                project_id=test_run.project_id,
                current_run_id=run_id,
                previous_run_id=prior_scan.run_id if prior_scan else None,
                finding_id=reg_item.get("finding_id"),
                regression_type="reopened_vulnerability",
                details_json=reg_item,
            )
            self.db.add(reg_record)

        # 12. Persist Security Scan Summary
        scan_summary_stmt = select(SecurityScanSummary).where(SecurityScanSummary.run_id == run_id)
        scan_summary = (await self.db.execute(scan_summary_stmt)).scalar_one_or_none()
        if not scan_summary:
            scan_summary = SecurityScanSummary(
                project_id=test_run.project_id,
                run_id=run_id,
                security_score=score_resp.security_score,
                total_findings=len(findings),
                critical_count=score_resp.critical_count,
                high_count=score_resp.high_count,
                medium_count=score_resp.medium_count,
                low_count=score_resp.low_count,
                fixed_count=0,
                regression_count=len(reg_resp.regressions),
                ci_gate_status=gate_resp.status,
            )
            self.db.add(scan_summary)
        else:
            scan_summary.security_score = score_resp.security_score
            scan_summary.total_findings = len(findings)
            scan_summary.critical_count = score_resp.critical_count
            scan_summary.high_count = score_resp.high_count
            scan_summary.medium_count = score_resp.medium_count
            scan_summary.low_count = score_resp.low_count
            scan_summary.regression_count = len(reg_resp.regressions)
            scan_summary.ci_gate_status = gate_resp.status

        await self.db.commit()
        return findings

    async def get_executive_report(self, run_id: str) -> ExecutiveReportResponse:
        """
        Compiles the comprehensive executive security report for a run.
        """
        # Ensure run has been analyzed
        findings_stmt = select(VulnerabilityFinding).where(VulnerabilityFinding.run_id == run_id)
        findings = (await self.db.execute(findings_stmt)).scalars().all()

        if not findings:
            findings = await self.analyze_run(run_id)

        test_run = await self.db.get(TestRun, run_id)
        if not test_run:
            raise ProjectNotFoundError(f"TestRun '{run_id}' not found.")

        score_resp = self.risk_engine.calculate_project_security_score(
            run_id=run_id,
            findings_severities=[f.severity for f in findings]
        )
        gate_resp = self.ci_gate_engine.evaluate(findings, score_resp.security_score)

        # Chains
        chains_stmt = select(AttackChainModel).where(AttackChainModel.run_id == run_id)
        chain_models = (await self.db.execute(chains_stmt)).scalars().all()
        chains_resp = [
            AttackChainResponse(
                chain_id=cm.chain_id,
                title=cm.title,
                overall_risk=cm.overall_risk,
                explanation=cm.explanation,
                nodes=cm.nodes_json,
                edges=cm.edges_json,
            )
            for cm in chain_models
        ]

        criticals = [self._format_finding_resp(f) for f in findings if f.severity.lower() == "critical"]
        highs = [self._format_finding_resp(f) for f in findings if f.severity.lower() == "high"]
        mediums = [self._format_finding_resp(f) for f in findings if f.severity.lower() == "medium"]
        lows = [self._format_finding_resp(f) for f in findings if f.severity.lower() == "low"]

        # Remediation roadmap
        roadmap = []
        for idx, f in enumerate(findings):
            roadmap.append({
                "step": idx + 1,
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "recommended_action": f.remediation_json.get("what_to_change", "Audit access controls"),
                "principle": f.remediation_json.get("secure_design_principle", "Defense in Depth"),
            })

        summary_text = (
            f"API Guardian Security Assessment Report for Test Run {run_id}. "
            f"Overall Security Health Score is {score_resp.security_score}/100 ({score_resp.risk_level.upper()} RISK). "
            f"Detected {len(findings)} total active findings ({len(criticals)} Critical, {len(highs)} High, {len(mediums)} Medium). "
            f"CI/CD Security Gate: {gate_resp.status.upper()}."
        )

        test_stats = {
            "total_attacks_executed": test_run.total_attacks,
            "passed_attacks": test_run.passed_attacks,
            "failed_attacks": test_run.failed_attacks,
            "target_base_url": test_run.target_base_url,
            "environment": test_run.environment,
        }

        return ExecutiveReportResponse(
            project_id=test_run.project_id,
            run_id=run_id,
            generated_at=datetime.now(timezone.utc),
            executive_summary=summary_text,
            security_score=score_resp,
            ci_gate=gate_resp,
            critical_findings=criticals,
            high_findings=highs,
            medium_findings=mediums,
            low_findings=lows,
            attack_chains=chains_resp,
            remediation_roadmap=roadmap,
            test_statistics=test_stats,
        )

    def _format_finding_resp(self, f: VulnerabilityFinding) -> VulnerabilityFindingResponse:
        """Converts ORM finding model to Pydantic finding response."""
        remediation_obj = None
        if f.remediation_json:
            remediation_obj = RemediationRecommendation(
                what_to_change=f.remediation_json.get("what_to_change", ""),
                why=f.remediation_json.get("why", ""),
                secure_design_principle=f.remediation_json.get("secure_design_principle", ""),
                example_pseudocode=f.remediation_json.get("example_pseudocode", ""),
                target_framework=f.remediation_json.get("target_framework", "FastAPI / Python"),
            )

        return VulnerabilityFindingResponse(
            id=f.id,
            finding_id=f.finding_id,
            attack_id=f.attack_id,
            title=f.title,
            type=f.type,
            endpoint=f.endpoint,
            method=f.method,
            severity=f.severity,
            confidence=f.confidence,
            status=f.status,
            verification_status=f.verification_status,
            risk_score=f.risk_score,
            data_sensitivity=f.data_sensitivity,
            confirmed_impact=f.confirmed_impact,
            potential_impact=f.potential_impact,
            blast_radius_reach=f.blast_radius_reach,
            blast_radius_confidence=f.blast_radius_confidence,
            blast_radius_reasoning=f.blast_radius_reasoning,
            technical_explanation=f.technical_explanation,
            simple_explanation=f.simple_explanation,
            evidence_explanation=f.evidence_explanation,
            why_it_matters=f.why_it_matters,
            remediation=remediation_obj,
            evidence=f.evidence_json or {},
            steps=f.steps_json or [],
            created_at=f.created_at,
        )
