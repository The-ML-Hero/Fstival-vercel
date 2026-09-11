from typing import Any, Dict, List, Optional
from app.schemas.resource import ResourceEntityResponse
from app.schemas.workflow import ParameterMapping, WorkflowAnalysisResult, WorkflowResponse, WorkflowStep


class WorkflowAnalyzer:
    """
    Discovers multi-step API workflows by chaining stateful CRUD lifecycles,
    authentication flows, and resource interactions with parameter dependencies.
    """

    def analyze(
        self,
        endpoints_raw: List[Dict[str, Any]],
        resources: List[ResourceEntityResponse]
    ) -> WorkflowAnalysisResult:
        workflows: List[WorkflowResponse] = []

        ep_by_method_path: Dict[str, Dict[str, Any]] = {}
        for ep in endpoints_raw:
            ep_by_method_path[f"{ep['method']} {ep['path']}"] = ep

        # 1. Identify Authentication & Session Workflow
        login_ep = None
        user_info_ep = None
        for key, ep in ep_by_method_path.items():
            path_lower = ep["path"].lower()
            if ep["method"] == "POST" and any(k in path_lower for k in ["login", "authenticate", "token", "signin"]):
                login_ep = ep
            elif ep["method"] == "GET" and any(k in path_lower for k in ["me", "profile", "userinfo", "whoami"]):
                user_info_ep = ep

        auth_step = None
        if login_ep:
            auth_step = WorkflowStep(
                step_number=1,
                step_name="authenticate_user",
                endpoint=login_ep["path"],
                method=login_ep["method"],
                description="Obtain authentication token/session",
                produces_parameters=["token", "access_token"],
                consumes_parameters=[],
            )
            auth_workflow_steps = [auth_step]
            param_mappings = []
            if user_info_ep:
                auth_workflow_steps.append(WorkflowStep(
                    step_number=2,
                    step_name="get_current_user_profile",
                    endpoint=user_info_ep["path"],
                    method=user_info_ep["method"],
                    description="Verify authenticated session profile",
                    produces_parameters=["user_id"],
                    consumes_parameters=["token"],
                ))
                param_mappings.append(ParameterMapping(
                    source_step="authenticate_user",
                    source_field="token",
                    target_step="get_current_user_profile",
                    target_parameter="Authorization",
                    location="header",
                ))

            workflows.append(WorkflowResponse(
                workflow_name="Authentication & Identity Lifecycle",
                description="Standard user authentication flow from credential exchange to identity verification.",
                confidence=0.92,
                steps=auth_workflow_steps,
                parameter_mappings=param_mappings,
            ))

        # 2. Build Lifecycle Workflows for each Primary Resource
        for res in resources:
            crud = res.crud_operations
            steps: List[WorkflowStep] = []
            param_mappings: List[ParameterMapping] = []
            step_counter = 1

            if auth_step:
                steps.append(WorkflowStep(
                    step_number=step_counter,
                    step_name="authenticate_session",
                    endpoint=auth_step.endpoint,
                    method=auth_step.method,
                    description=auth_step.description,
                    produces_parameters=["token"],
                    consumes_parameters=[],
                ))
                step_counter += 1

            create_ep_key = crud.get("create")
            list_ep_key = crud.get("list")
            read_ep_key = crud.get("read")
            update_ep_key = crud.get("update")
            delete_ep_key = crud.get("delete")

            create_step_name = None
            if create_ep_key and create_ep_key in ep_by_method_path:
                ep = ep_by_method_path[create_ep_key]
                create_step_name = f"create_{res.name.lower()}"
                steps.append(WorkflowStep(
                    step_number=step_counter,
                    step_name=create_step_name,
                    endpoint=ep["path"],
                    method=ep["method"],
                    description=f"Create new {res.name} entity",
                    produces_parameters=["id", f"{res.name.lower()}_id"],
                    consumes_parameters=["token"] if auth_step else [],
                ))
                step_counter += 1

            if read_ep_key and read_ep_key in ep_by_method_path:
                ep = ep_by_method_path[read_ep_key]
                read_step_name = f"get_{res.name.lower()}"
                steps.append(WorkflowStep(
                    step_number=step_counter,
                    step_name=read_step_name,
                    endpoint=ep["path"],
                    method=ep["method"],
                    description=f"Fetch {res.name} details by ID",
                    produces_parameters=[],
                    consumes_parameters=["id"],
                ))
                if create_step_name:
                    param_mappings.append(ParameterMapping(
                        source_step=create_step_name,
                        source_field="id",
                        target_step=read_step_name,
                        target_parameter="id",
                        location="path",
                    ))
                step_counter += 1

            if update_ep_key and update_ep_key in ep_by_method_path:
                ep = ep_by_method_path[update_ep_key]
                update_step_name = f"update_{res.name.lower()}"
                steps.append(WorkflowStep(
                    step_number=step_counter,
                    step_name=update_step_name,
                    endpoint=ep["path"],
                    method=ep["method"],
                    description=f"Update {res.name} attributes",
                    produces_parameters=[],
                    consumes_parameters=["id"],
                ))
                if create_step_name:
                    param_mappings.append(ParameterMapping(
                        source_step=create_step_name,
                        source_field="id",
                        target_step=update_step_name,
                        target_parameter="id",
                        location="path",
                    ))
                step_counter += 1

            if delete_ep_key and delete_ep_key in ep_by_method_path:
                ep = ep_by_method_path[delete_ep_key]
                delete_step_name = f"delete_{res.name.lower()}"
                steps.append(WorkflowStep(
                    step_number=step_counter,
                    step_name=delete_step_name,
                    endpoint=ep["path"],
                    method=ep["method"],
                    description=f"Delete {res.name} entity",
                    produces_parameters=[],
                    consumes_parameters=["id"],
                ))
                if create_step_name:
                    param_mappings.append(ParameterMapping(
                        source_step=create_step_name,
                        source_field="id",
                        target_step=delete_step_name,
                        target_parameter="id",
                        location="path",
                    ))
                step_counter += 1

            # Only add lifecycle workflow if it contains 2+ meaningful steps
            if len(steps) >= (2 if not auth_step else 3):
                workflows.append(WorkflowResponse(
                    workflow_name=f"{res.name} Management Workflow",
                    description=f"Full lifecycle management and state transitions for {res.name} resource.",
                    confidence=0.88,
                    steps=steps,
                    parameter_mappings=param_mappings,
                ))

        # 3. Cross-Resource Composite Workflows (e.g., E-Commerce Order -> Payment -> Refund or Patient -> Appointment)
        composite_steps: List[WorkflowStep] = []
        composite_mappings: List[ParameterMapping] = []
        c_step = 1

        # Check for order -> checkout/payment flow
        order_eps = [ep for ep in ep_by_method_path.values() if "order" in ep["path"].lower() and ep["method"] == "POST"]
        payment_eps = [ep for ep in ep_by_method_path.values() if any(k in ep["path"].lower() for k in ["pay", "checkout", "billing"]) and ep["method"] == "POST"]
        refund_eps = [ep for ep in ep_by_method_path.values() if "refund" in ep["path"].lower() and ep["method"] == "POST"]

        if order_eps and payment_eps:
            o_ep = order_eps[0]
            p_ep = payment_eps[0]
            composite_steps.append(WorkflowStep(
                step_number=c_step,
                step_name="create_order",
                endpoint=o_ep["path"],
                method=o_ep["method"],
                description="Initiate checkout and create pending order",
                produces_parameters=["order_id", "id"],
                consumes_parameters=[],
            ))
            c_step += 1
            composite_steps.append(WorkflowStep(
                step_number=c_step,
                step_name="process_payment",
                endpoint=p_ep["path"],
                method=p_ep["method"],
                description="Process payment transaction for the created order",
                produces_parameters=["payment_id", "transaction_id"],
                consumes_parameters=["order_id"],
            ))
            composite_mappings.append(ParameterMapping(
                source_step="create_order",
                source_field="id",
                target_step="process_payment",
                target_parameter="order_id",
                location="body" if "{order" not in p_ep["path"] else "path",
            ))
            c_step += 1

            if refund_eps:
                r_ep = refund_eps[0]
                composite_steps.append(WorkflowStep(
                    step_number=c_step,
                    step_name="request_refund",
                    endpoint=r_ep["path"],
                    method=r_ep["method"],
                    description="Request refund for settled transaction",
                    produces_parameters=["refund_id"],
                    consumes_parameters=["payment_id", "order_id"],
                ))
                composite_mappings.append(ParameterMapping(
                    source_step="process_payment",
                    source_field="payment_id",
                    target_step="request_refund",
                    target_parameter="payment_id",
                    location="body",
                ))

            workflows.append(WorkflowResponse(
                workflow_name="Order Settlement & Refund Pipeline",
                description="End-to-end commerce workflow from cart ordering to payment processing and refund execution.",
                confidence=0.89,
                steps=composite_steps,
                parameter_mappings=composite_mappings,
            ))

        return WorkflowAnalysisResult(
            workflows=workflows,
            total_workflows=len(workflows),
        )
