from typing import Any, Dict, List
from app.schemas.ai_models import AIAttackMutation


class MutationGenerator:
    """
    Generates intelligent, context-aware parameter mutation plans based on
    parameter names, data types, locations, and semantic business domain meaning.
    """

    def generate_mutations_for_parameter(
        self,
        param_name: str,
        param_type: str,
        location: str,
        category: str = "Input Validation"
    ) -> List[AIAttackMutation]:
        mutations: List[AIAttackMutation] = []
        name_lower = param_name.lower().replace("-", "_")

        # 1. Resource Identifier Mutations (BOLA / IDOR / Boundary testing)
        if (
            name_lower.endswith("_id")
            or name_lower == "id"
            or name_lower.endswith("id")
            or location == "path"
        ):
            mutations.extend([
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="cross_tenant_id",
                    payload_sample="00000000-0000-0000-0000-000000000002",
                    rationale="Test if accessing another tenant's resource ID bypasses object-level authorization (BOLA)."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="boundary_low_id",
                    payload_sample="0",
                    rationale="Test lowest non-negative boundary value handling."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="negative_id",
                    payload_sample="-1",
                    rationale="Test backend input validation and integer underflow handling on ID parameter."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="nonexistent_id",
                    payload_sample="999999999",
                    rationale="Test if nonexistent ID returns safe 404 without leaking stack traces or internal errors."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="path_traversal_marker",
                    payload_sample="../admin/profile",
                    rationale="Test if path variable allows directory traversal or route manipulation."
                ),
            ])
            return mutations

        # 2. Financial / Quantity / Pricing Mutations (Business Logic / Parameter Tampering)
        if any(kw in name_lower for kw in ["amount", "price", "total", "cost", "balance", "fee", "quantity", "discount"]):
            mutations.extend([
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="negative_amount",
                    payload_sample="-50.00",
                    rationale="Test whether negative values result in credit addition or inverted transaction calculation."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="zero_amount",
                    payload_sample="0.00",
                    rationale="Test if zero price/cost allows acquiring goods or services for free."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="fractional_precision_overflow",
                    payload_sample="0.000000001",
                    rationale="Test decimal rounding truncation vulnerabilities in financial logic."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="extreme_overflow_amount",
                    payload_sample="999999999999999999",
                    rationale="Test integer/float overflow behavior during balance arithmetic."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="type_juggling_string",
                    payload_sample="FREE",
                    rationale="Test weak typing checks in downstream microservices."
                ),
            ])
            return mutations

        # 3. Role / Privileges / Permissions Mutations (Role Escalation / Mass Assignment)
        if any(kw in name_lower for kw in ["role", "roles", "is_admin", "admin", "privilege", "permission", "user_type", "tier"]):
            mutations.extend([
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="admin_role_escalation",
                    payload_sample="admin",
                    rationale="Test if client-supplied payload can self-assign elevated administrative privileges."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="superuser_escalation",
                    payload_sample="superuser",
                    rationale="Test alternative high-privilege system role names."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="null_role_injection",
                    payload_sample="null",
                    rationale="Test if nullifying role field causes fallback to default superuser or unconstrained access."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="unknown_role",
                    payload_sample="undefined_custom_role_xyz",
                    rationale="Test error handling when role doesn't match enum specification."
                ),
            ])
            return mutations

        # 4. Age / Count / Numeric Field Mutations
        if any(kw in name_lower for kw in ["age", "count", "limit", "offset", "page", "size"]):
            mutations.extend([
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="negative_numeric",
                    payload_sample="-1",
                    rationale="Test negative numeric values on positive domain parameters."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="zero_value",
                    payload_sample="0",
                    rationale="Test boundary zero handling for paging or business logic constraints."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="large_value_dos",
                    payload_sample="100000000",
                    rationale="Test massive limit/offset request for resource exhaustion / DoS."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="type_juggling_string",
                    payload_sample="NaN",
                    rationale="Test non-numeric string injection into numeric parameter."
                ),
            ])
            return mutations

        # 5. Generic Type Fallback Mutations
        if param_type in {"integer", "number"}:
            mutations.extend([
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="negative_value",
                    payload_sample="-1",
                    rationale=f"Test negative value constraint enforcement on {param_name}."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="integer_overflow",
                    payload_sample="2147483648",
                    rationale=f"Test 32-bit signed integer boundary overflow on {param_name}."
                ),
            ])
        elif param_type == "boolean":
            mutations.extend([
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="truthy_string",
                    payload_sample="true",
                    rationale=f"Test string vs boolean type handling on {param_name}."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="numeric_boolean",
                    payload_sample="1",
                    rationale=f"Test integer type coercion on boolean field {param_name}."
                ),
            ])
        else:  # String / Object / Default
            mutations.extend([
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="empty_string",
                    payload_sample="",
                    rationale=f"Test empty string validation on {param_name}."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="special_characters",
                    payload_sample="<script>alert(1)</script>' OR 1=1--",
                    rationale=f"Test injection payload sanitization on {param_name}."
                ),
                AIAttackMutation(
                    parameter_name=param_name,
                    parameter_location=location,
                    mutation_type="long_buffer_string",
                    payload_sample="A" * 1024,
                    rationale=f"Test buffer length limits and memory allocation on {param_name}."
                ),
            ])

        return mutations
