from typing import Any, Dict
from app.schemas.module3.finding import RemediationRecommendation
from app.schemas.module3.observation import SecurityObservation


class RemediationEngine:
    """
    Generates actionable, framework-specific remediation recommendations,
    secure design principles, and concrete pseudocode patches.
    """

    def generate_remediation(
        self,
        observation: SecurityObservation,
        vulnerability_type: str
    ) -> RemediationRecommendation:
        """
        Produces prescriptive fix guidance for developers.
        """
        vtype = vulnerability_type.lower()
        endpoint = observation.endpoint
        method = observation.method

        if "bola" in vtype or "idor" in vtype:
            what = "Implement object-level ownership checks before executing database queries or returning entity objects."
            why = "Prevents authenticated attackers from reading or modifying records belonging to other tenants/users."
            principle = "Complete Mediation & Principle of Least Privilege"
            pseudocode = """# Secure FastAPI / SQLAlchemy Implementation
@router.get("/patients/{patient_id}")
async def get_patient(
    patient_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    patient = await db.get(Patient, patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
        
    # Crucial Ownership Check:
    if patient.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: You do not own this record")
        
    return patient"""

        elif "role escalation" in vtype or "mass assignment" in vtype:
            what = "Use strict Pydantic/DTO input schemas that exclude internal privilege fields (e.g. role, is_admin, balance)."
            why = "Blocks clients from directly overriding sensitive database columns through unconstrained mass assignment."
            principle = "Positive Security Model (Allowlists over Denylists)"
            pseudocode = """# Define explicit public update schema without 'role'
class UserProfileUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    # Do NOT include 'role' or 'is_admin' here!

@router.put("/users/{user_id}")
async def update_profile(
    user_id: str,
    payload: UserProfileUpdate,
    current_user: User = Depends(get_current_user)
):
    # Only allow updating own profile with safe fields
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    # Apply safe fields only
    user_data = payload.model_dump(exclude_unset=True)
    await db_update_user(user_id, user_data)"""

        elif "authentication" in vtype:
            what = "Attach authentication dependency/middleware to verify cryptographic JWT or API key signature on every request."
            why = "Guarantees that unauthenticated anonymous clients cannot access private API resources."
            principle = "Secure by Default & Explicit Authorization"
            pseudocode = """# Require authentication dependency
@router.get("/admin/users", dependencies=[Depends(require_admin_auth)])
async def list_admin_users():
    return await fetch_all_users()"""

        elif "input validation" in vtype or "tampering" in vtype:
            what = "Enforce strict boundary validation rules (e.g. amount > 0, regex constraints, length limits) in request schemas."
            why = "Rejects negative prices, boundary overflows, and malformed strings before backend business logic runs."
            principle = "Fail-Safe Defaults & Input Sanitization"
            pseudocode = """from pydantic import BaseModel, Field

class PaymentRequest(BaseModel):
    amount: float = Field(..., gt=0.0, description="Amount charged must be strictly positive")

@router.post("/orders/{order_id}/pay")
async def pay_order(order_id: str, payload: PaymentRequest):
    # Pydantic automatically rejects negative numbers with HTTP 422 Unprocessable Entity
    return await process_payment(order_id, payload.amount)"""

        elif "rate-limit" in vtype:
            what = "Implement IP-based and user-token-based rate limiting (e.g., slowapi, Redis token bucket)."
            why = "Throttles abusive spikes, mitigates brute-force attacks, and prevents Denial of Service."
            principle = "Defense in Depth & Rate Limiting"
            pseudocode = """from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@router.get("/rate-limit-test")
@limiter.limit("5/minute")
async def sensitive_action(request: Request):
    return {"status": "ok"}"""

        else:
            what = f"Audit and enforce standard validation and authorization policies on {method} {endpoint}."
            why = "Ensures predictable, hardened API execution adhering to secure coding guidelines."
            principle = "Defense in Depth"
            pseudocode = """# Ensure input validation and role authorization
@router.api_route("/{path:path}", dependencies=[Depends(verify_access_control)])
async def secure_handler():
    pass"""

        return RemediationRecommendation(
            what_to_change=what,
            why=why,
            secure_design_principle=principle,
            example_pseudocode=pseudocode.strip(),
            target_framework="FastAPI / Python",
        )
