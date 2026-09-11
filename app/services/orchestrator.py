from typing import Any, Dict, List, Optional
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import AnalysisError, ProjectNotFoundError
from app.core.logging import logger
from app.core.security import check_target_authorization
from app.db.models import (
    Project,
    ApiSpec,
    Endpoint,
    Parameter,
    SchemaModel,
    AuthScheme,
    InferredRole,
    ResourceEntity,
    Workflow,
    AttackHypothesis,
    AttackMutation,
)
from app.schemas.module2_contract import (
    Module2ApiSummary,
    Module2AttackItem,
    Module2AttackPlanExport,
    Module2Endpoint,
    Module2Mutation,
    Module2Parameter,
    Module2Resource,
    Module2ResourceRelationship,
    Module2Role,
    Module2Workflow,
    Module2WorkflowStep,
)
from app.services.analyzers.auth_analyzer import AuthAnalyzer
from app.services.analyzers.role_analyzer import RoleAnalyzer
from app.services.analyzers.resource_analyzer import ResourceAnalyzer
from app.services.analyzers.workflow_analyzer import WorkflowAnalyzer
from app.services.analyzers.attack_prioritizer import AttackPrioritizer
from app.services.ai.factory import get_ai_provider
from app.services.openapi_parser.parser import OpenAPIParser


class AnalysisPipelineOrchestrator:
    """
    Coordinates the full end-to-end analysis pipeline:
    OpenAPI Ingestion -> Parsing -> Discovery -> Auth/Role/Resource/Workflow Analyzers
    -> AI Understanding -> Attack Hypothesis & Mutation Generation -> Prioritization -> Persistence.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.auth_analyzer = AuthAnalyzer()
        self.role_analyzer = RoleAnalyzer()
        self.resource_analyzer = ResourceAnalyzer()
        self.workflow_analyzer = WorkflowAnalyzer()
        self.attack_prioritizer = AttackPrioritizer()

    async def ingest_openapi(
        self,
        project_id: str,
        spec_content: str | Dict[str, Any]
    ) -> ApiSpec:
        """
        Parses specification, stores raw ApiSpec, normalized Endpoints, Parameters, Schemas, and AuthSchemes.
        """
        # Verify project exists
        project = await self.db.get(Project, project_id)
        if not project:
            raise ProjectNotFoundError(f"Project '{project_id}' not found.")

        # Parse spec
        parser = OpenAPIParser(spec_content)
        meta = parser.get_metadata()
        security_schemes_raw = parser.get_security_schemes()
        endpoints_raw = parser.get_endpoints()

        # Update project target_base_url if found
        if meta.get("target_base_url") and not project.target_base_url:
            project.target_base_url = meta["target_base_url"]

        # Clear existing spec & endpoints if re-importing
        existing_spec = await self.db.execute(select(ApiSpec).where(ApiSpec.project_id == project_id))
        spec_obj = existing_spec.scalar_one_or_none()

        if spec_obj:
            spec_obj.title = meta["title"]
            spec_obj.version = meta["version"]
            spec_obj.openapi_version = meta["openapi_version"]
            spec_obj.description = meta["description"]
            spec_obj.raw_content = meta["raw_content"]
            spec_obj.spec_format = meta["spec_format"]
        else:
            spec_obj = ApiSpec(
                project_id=project_id,
                title=meta["title"],
                version=meta["version"],
                openapi_version=meta["openapi_version"],
                description=meta["description"],
                raw_content=meta["raw_content"],
                spec_format=meta["spec_format"],
            )
            self.db.add(spec_obj)

        # Clear existing child items to refresh
        await self.db.execute(delete(Endpoint).where(Endpoint.project_id == project_id))
        await self.db.execute(delete(AuthScheme).where(AuthScheme.project_id == project_id))

        # Store auth schemes
        for s in security_schemes_raw:
            auth_scheme = AuthScheme(
                project_id=project_id,
                scheme_name=s["scheme_name"],
                scheme_type=s["scheme_type"],
                security_required=s["security_required"],
                token_location=s["token_location"],
                header_name=s["header_name"],
                bearer_format=s["bearer_format"],
                scopes=s["scopes"],
                description=s["description"],
            )
            self.db.add(auth_scheme)

        # Store endpoints, parameters, and schemas
        for ep in endpoints_raw:
            endpoint_model = Endpoint(
                project_id=project_id,
                method=ep["method"],
                path=ep["path"],
                operation_id=ep["operation_id"],
                summary=ep["summary"],
                description=ep["description"],
                security_required=ep["security_required"],
                tags=ep["tags"],
                security_schemes=ep["security_schemes"],
                responses_summary=ep["responses_summary"],
            )
            self.db.add(endpoint_model)
            await self.db.flush()

            # Add parameters
            for p in ep["parameters"]:
                param_model = Parameter(
                    endpoint_id=endpoint_model.id,
                    name=p["name"],
                    location=p["location"],
                    param_type=p["param_type"],
                    required=p["required"],
                    default_value=p["default_value"],
                    enum_values=p["enum_values"],
                    schema_def=p["schema_def"],
                    description=p["description"],
                )
                self.db.add(param_model)

            # Add schemas
            for s in ep["schemas"]:
                schema_model = SchemaModel(
                    endpoint_id=endpoint_model.id,
                    schema_type=s["schema_type"],
                    status_code=s["status_code"],
                    content_type=s["content_type"],
                    schema_json=s["schema_json"],
                    description=s["description"],
                )
                self.db.add(schema_model)

        await self.db.commit()
        return spec_obj

    async def run_analysis(
        self,
        project_id: str,
        ai_provider_override: Optional[str] = None
    ) -> Module2AttackPlanExport:
        """
        Executes the complete discovery and attack planning pipeline on a project.
        """
        # 1. Fetch Project and verify target authorization
        stmt = (
            select(Project)
            .where(Project.id == project_id)
            .options(
                selectinload(Project.api_spec),
                selectinload(Project.auth_schemes),
                selectinload(Project.endpoints).selectinload(Endpoint.parameters),
                selectinload(Project.endpoints).selectinload(Endpoint.schemas),
            )
        )
        res = await self.db.execute(stmt)
        project = res.scalar_one_or_none()

        if not project:
            raise ProjectNotFoundError(f"Project '{project_id}' not found.")
        if not project.api_spec:
            raise AnalysisError(f"Project '{project_id}' has no imported OpenAPI specification.")

        check_target_authorization(project.target_authorized, project.target_base_url)

        # 2. Extract Raw Endpoints & Auth Schemes for Analyzers
        endpoints_raw: List[Dict[str, Any]] = []
        for ep in project.endpoints:
            params = [
                {
                    "name": p.name,
                    "location": p.location,
                    "param_type": p.param_type,
                    "required": p.required,
                    "default_value": p.default_value,
                    "enum_values": p.enum_values,
                    "schema_def": p.schema_def,
                    "description": p.description,
                }
                for p in ep.parameters
            ]
            schemas = [
                {
                    "schema_type": s.schema_type,
                    "status_code": s.status_code,
                    "content_type": s.content_type,
                    "schema_json": s.schema_json,
                    "description": s.description,
                }
                for s in ep.schemas
            ]
            endpoints_raw.append({
                "id": ep.id,
                "method": ep.method,
                "path": ep.path,
                "operation_id": ep.operation_id,
                "summary": ep.summary,
                "description": ep.description,
                "security_required": ep.security_required,
                "tags": ep.tags,
                "security_schemes": ep.security_schemes,
                "parameters": params,
                "schemas": schemas,
            })

        auth_schemes_raw: List[Dict[str, Any]] = [
            {
                "scheme_name": a.scheme_name,
                "scheme_type": a.scheme_type,
                "security_required": a.security_required,
                "token_location": a.token_location,
                "header_name": a.header_name,
                "bearer_format": a.bearer_format,
                "scopes": a.scopes,
                "description": a.description,
            }
            for a in project.auth_schemes
        ]

        # 3. Execute Analyzers
        auth_analysis = self.auth_analyzer.analyze(auth_schemes_raw, endpoints_raw)
        role_analysis = self.role_analyzer.analyze(endpoints_raw, auth_schemes_raw)
        resource_analysis = self.resource_analyzer.analyze(endpoints_raw)
        workflow_analysis = self.workflow_analyzer.analyze(endpoints_raw, resource_analysis.resources)

        # 4. Prepare Context for AI Engine
        ai_context = {
            "api_title": project.api_spec.title,
            "api_version": project.api_spec.version,
            "endpoints": endpoints_raw,
            "auth_schemes": auth_schemes_raw,
            "roles": [r.model_dump() for r in role_analysis.detected_roles],
            "resources": [r.model_dump() for r in resource_analysis.resources],
            "workflows": [w.model_dump() for w in workflow_analysis.workflows],
        }

        # 5. Invoke AI Provider
        ai_provider = get_ai_provider(ai_provider_override)
        ai_result = await ai_provider.analyze_api(ai_context)

        # 6. Prioritize Attack Hypotheses
        prioritized_attacks = self.attack_prioritizer.prioritize_hypotheses(ai_result.attack_hypotheses)

        # 7. Persist Roles, Resources, Workflows, and Attack Hypotheses to DB
        await self.db.execute(delete(InferredRole).where(InferredRole.project_id == project_id))
        await self.db.execute(delete(ResourceEntity).where(ResourceEntity.project_id == project_id))
        await self.db.execute(delete(Workflow).where(Workflow.project_id == project_id))
        await self.db.execute(delete(AttackHypothesis).where(AttackHypothesis.project_id == project_id))

        # Save Inferred Roles
        for r in role_analysis.detected_roles:
            role_model = InferredRole(
                project_id=project_id,
                role_name=r.role_name,
                confidence=r.confidence,
                reasoning=r.reasoning,
                evidence=r.evidence,
                associated_endpoints=r.associated_endpoints,
            )
            self.db.add(role_model)

        # Save Resources
        for res_item in resource_analysis.resources:
            res_model = ResourceEntity(
                project_id=project_id,
                name=res_item.name,
                description=res_item.description,
                endpoints=res_item.endpoints,
                crud_operations=res_item.crud_operations,
                relationships=[rel.model_dump() for rel in res_item.relationships],
            )
            self.db.add(res_model)

        # Save Workflows
        for wf in workflow_analysis.workflows:
            wf_model = Workflow(
                project_id=project_id,
                workflow_name=wf.workflow_name,
                description=wf.description,
                confidence=wf.confidence,
                steps=[s.model_dump() for s in wf.steps],
                parameter_mappings=[m.model_dump() for m in wf.parameter_mappings],
            )
            self.db.add(wf_model)

        # Save Hypotheses & Mutations
        saved_attack_items: List[Module2AttackItem] = []
        for hyp, score, level in prioritized_attacks:
            hyp_model = AttackHypothesis(
                project_id=project_id,
                attack_id=hyp.attack_id,
                category=hyp.category,
                endpoint=hyp.endpoint,
                method=hyp.method,
                objective=hyp.objective,
                preconditions=hyp.preconditions,
                steps=hyp.steps,
                expected_secure_behavior=hyp.expected_secure_behavior,
                reason=hyp.reason,
                severity=hyp.severity,
                exploitability=hyp.exploitability,
                impact=hyp.impact,
                confidence=hyp.confidence,
                priority_score=score,
                priority_level=level,
            )
            self.db.add(hyp_model)
            await self.db.flush()

            mutation_items: List[Module2Mutation] = []
            for mut in hyp.mutations:
                mut_model = AttackMutation(
                    hypothesis_id=hyp_model.id,
                    parameter_name=mut.parameter_name,
                    parameter_location=mut.parameter_location,
                    mutation_type=mut.mutation_type,
                    payload_sample=mut.payload_sample,
                    rationale=mut.rationale,
                )
                self.db.add(mut_model)
                mutation_items.append(Module2Mutation(
                    parameter_name=mut.parameter_name,
                    parameter_location=mut.parameter_location,
                    mutation_type=mut.mutation_type,
                    payload_sample=mut.payload_sample,
                    rationale=mut.rationale,
                ))

            saved_attack_items.append(Module2AttackItem(
                attack_id=hyp.attack_id,
                type=hyp.category,
                endpoint=hyp.endpoint,
                method=hyp.method,
                objective=hyp.objective,
                preconditions=hyp.preconditions,
                steps=hyp.steps,
                mutations=mutation_items,
                expected_secure_behavior=hyp.expected_secure_behavior,
                reason=hyp.reason,
                severity=hyp.severity,
                exploitability=hyp.exploitability,
                impact=hyp.impact,
                confidence=hyp.confidence,
                priority_score=score,
                priority=level,
            ))

        await self.db.commit()

        # 8. Build and return the Module 2 Contract Export
        return await self.build_module2_export(project_id)

    async def build_module2_export(self, project_id: str) -> Module2AttackPlanExport:
        """
        Builds the strict JSON payload conforming to the Module 2 consumption contract.
        """
        stmt = (
            select(Project)
            .where(Project.id == project_id)
            .options(
                selectinload(Project.api_spec),
                selectinload(Project.inferred_roles),
                selectinload(Project.resources),
                selectinload(Project.workflows),
                selectinload(Project.attack_hypotheses).selectinload(AttackHypothesis.mutations),
                selectinload(Project.endpoints).selectinload(Endpoint.parameters),
                selectinload(Project.endpoints).selectinload(Endpoint.schemas),
            )
        )
        res = await self.db.execute(stmt)
        project = res.scalar_one_or_none()

        if not project or not project.api_spec:
            raise ProjectNotFoundError(f"Project '{project_id}' not found or spec not imported.")

        # Endpoints
        module2_endpoints: List[Module2Endpoint] = []
        for ep in project.endpoints:
            req_schemas = [s.schema_json for s in ep.schemas if s.schema_type == "request_body"]
            resp_schemas = [s.schema_json for s in ep.schemas if s.schema_type == "response_body"]
            params = [
                Module2Parameter(
                    name=p.name,
                    location=p.location,
                    type=p.param_type,
                    required=p.required,
                    default_value=p.default_value,
                    enum_values=p.enum_values,
                    schema_def=p.schema_def,
                )
                for p in ep.parameters
            ]
            module2_endpoints.append(Module2Endpoint(
                id=ep.id,
                method=ep.method,
                path=ep.path,
                operation_id=ep.operation_id,
                summary=ep.summary,
                security_required=ep.security_required,
                tags=ep.tags,
                security_schemes=ep.security_schemes,
                parameters=params,
                request_schemas=req_schemas,
                response_schemas=resp_schemas,
            ))

        # Roles
        module2_roles = [
            Module2Role(
                role_name=r.role_name,
                confidence=r.confidence,
                reasoning=r.reasoning,
                evidence=r.evidence,
                associated_endpoints=r.associated_endpoints,
            )
            for r in project.inferred_roles
        ]

        # Resources
        module2_resources = [
            Module2Resource(
                name=res_item.name,
                description=res_item.description,
                endpoints=res_item.endpoints,
                crud_operations=res_item.crud_operations,
                relationships=[
                    Module2ResourceRelationship(
                        target_resource=rel.get("target_resource", rel.get("target", "")),
                        relationship_type=rel.get("relationship_type", rel.get("type", "")),
                        evidence_endpoint=rel.get("evidence_endpoint"),
                    )
                    for rel in res_item.relationships
                ]
            )
            for res_item in project.resources
        ]

        # Workflows
        module2_workflows = [
            Module2Workflow(
                workflow_name=wf.workflow_name,
                description=wf.description,
                confidence=wf.confidence,
                steps=[
                    Module2WorkflowStep(
                        step_number=s.get("step_number", 1),
                        step_name=s.get("step_name", "step"),
                        endpoint=s.get("endpoint", "/"),
                        method=s.get("method", "GET"),
                        description=s.get("description"),
                        produces_parameters=s.get("produces_parameters", []),
                        consumes_parameters=s.get("consumes_parameters", []),
                    )
                    for s in wf.steps
                ],
                parameter_mappings=wf.parameter_mappings,
            )
            for wf in project.workflows
        ]

        # Attack Plan
        module2_attacks = [
            Module2AttackItem(
                attack_id=hyp.attack_id,
                type=hyp.category,
                endpoint=hyp.endpoint,
                method=hyp.method,
                objective=hyp.objective,
                preconditions=hyp.preconditions,
                steps=hyp.steps,
                mutations=[
                    Module2Mutation(
                        parameter_name=m.parameter_name,
                        parameter_location=m.parameter_location,
                        mutation_type=m.mutation_type,
                        payload_sample=m.payload_sample,
                        rationale=m.rationale,
                    )
                    for m in hyp.mutations
                ],
                expected_secure_behavior=hyp.expected_secure_behavior,
                reason=hyp.reason,
                severity=hyp.severity,
                exploitability=hyp.exploitability,
                impact=hyp.impact,
                confidence=hyp.confidence,
                priority_score=hyp.priority_score,
                priority=hyp.priority_level,
            )
            for hyp in sorted(project.attack_hypotheses, key=lambda x: x.priority_score, reverse=True)
        ]

        api_summary = Module2ApiSummary(
            title=project.api_spec.title,
            version=project.api_spec.version,
            openapi_version=project.api_spec.openapi_version,
            description=project.api_spec.description,
            target_base_url=project.target_base_url,
            total_endpoints=len(module2_endpoints),
            total_resources=len(module2_resources),
            total_workflows=len(module2_workflows),
            total_attacks_planned=len(module2_attacks),
        )

        return Module2AttackPlanExport(
            contract_version="1.0.0",
            project_id=project.id,
            target_authorized=project.target_authorized,
            api_summary=api_summary,
            endpoints=module2_endpoints,
            roles=module2_roles,
            resources=module2_resources,
            workflows=module2_workflows,
            attack_plan=module2_attacks,
        )
