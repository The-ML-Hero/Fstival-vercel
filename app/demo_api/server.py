from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from pydantic import BaseModel

demo_app = FastAPI(
    title="API Guardian Local Vulnerable Mock Target API",
    description="Local mock API with intentional synthetic vulnerabilities and live patching toggle for fix verification.",
    version="1.0.0"
)

# Global patch toggle for fix verification demonstration
PATCH_VULNERABILITIES: bool = False

# In-memory test state
USERS_DB: Dict[str, Dict[str, Any]] = {
    "1": {"id": "1", "name": "Alice User", "role": "user", "email": "alice@local.test"},
    "2": {"id": "2", "name": "Bob User", "role": "user", "email": "bob@local.test"},
    "99": {"id": "99", "name": "Admin Super", "role": "admin", "email": "admin@local.test"},
}

ORDERS_DB: Dict[str, Dict[str, Any]] = {
    "101": {"id": "101", "user_id": "1", "items": ["Item A"], "total": 99.00, "status": "PENDING"},
    "102": {"id": "102", "user_id": "2", "items": ["Item B"], "total": 149.00, "status": "PAID"},
    "103": {"id": "103", "user_id": "1", "items": ["Item C"], "total": 29.00, "status": "SHIPPED"},
}

PATIENTS_DB: Dict[str, Dict[str, Any]] = {
    "101": {"id": "101", "user_id": "1", "name": "Patient One", "diagnosis": "Confidential Record A"},
    "102": {"id": "102", "user_id": "2", "name": "Patient Two", "diagnosis": "Confidential Record B"},
    "103": {"id": "103", "user_id": "99", "name": "Patient Three", "diagnosis": "Confidential Record C"},
}

RATE_LIMIT_COUNTER: Dict[str, int] = {}


# Admin Controls for Fix Demonstration
@demo_app.post("/admin/apply-fixes", tags=["Fix Demo"])
async def apply_fixes():
    global PATCH_VULNERABILITIES
    PATCH_VULNERABILITIES = True
    return {"status": "success", "message": "Security patches applied. Access controls now enforced."}


@demo_app.post("/admin/reset-vulnerabilities", tags=["Fix Demo"])
async def reset_vulnerabilities():
    global PATCH_VULNERABILITIES
    PATCH_VULNERABILITIES = False
    return {"status": "success", "message": "Vulnerabilities restored to initial state."}


# 1. Authentication
@demo_app.post("/auth/token", tags=["Auth"])
async def login(payload: Dict[str, Any]):
    return {"access_token": "mock-user-jwt-token-alpha", "token_type": "Bearer"}


# 2. BOLA & Mass Assignment on User Profile
@demo_app.get("/users/{user_id}", tags=["Users"])
async def get_user_profile(user_id: str, authorization: Optional[str] = Header(None)):
    if PATCH_VULNERABILITIES:
        if not authorization or "mock-user" not in authorization:
            raise HTTPException(status_code=401, detail="Unauthorized")
        # Enforce user 1 can only read own profile
        if user_id != "1" and "mock-admin" not in authorization:
            raise HTTPException(status_code=403, detail="Forbidden: You do not own this profile")

    if user_id in USERS_DB:
        return USERS_DB[user_id]
    raise HTTPException(status_code=404, detail="User not found")


@demo_app.put("/users/{user_id}", tags=["Users"])
async def update_user_profile(user_id: str, payload: Dict[str, Any], authorization: Optional[str] = Header(None)):
    if PATCH_VULNERABILITIES:
        if "role" in payload:
            raise HTTPException(status_code=403, detail="Forbidden: Cannot self-assign role")

    if user_id not in USERS_DB:
        USERS_DB[user_id] = {"id": user_id, "name": "New User", "role": "user"}
    USERS_DB[user_id].update(payload)
    return USERS_DB[user_id]


# 3. Broken Authentication on Admin
@demo_app.get("/admin/users", tags=["Admin"])
async def list_all_users_admin(authorization: Optional[str] = Header(None)):
    if PATCH_VULNERABILITIES:
        if not authorization or "mock-admin" not in authorization:
            raise HTTPException(status_code=401, detail="Unauthorized: Admin token required")
    return list(USERS_DB.values())


# 4. Orders CRUD & BOLA
@demo_app.post("/orders", tags=["Orders"])
async def create_order(payload: Dict[str, Any]):
    order_id = str(len(ORDERS_DB) + 101)
    ORDERS_DB[order_id] = {
        "id": order_id,
        "user_id": payload.get("user_id", "1"),
        "items": payload.get("items", []),
        "total": payload.get("total", payload.get("price", 50.0)),
        "status": "PENDING",
    }
    return ORDERS_DB[order_id]


@demo_app.get("/orders/{order_id}", tags=["Orders"])
async def get_order(order_id: str, authorization: Optional[str] = Header(None)):
    if PATCH_VULNERABILITIES:
        if not authorization:
            raise HTTPException(status_code=401, detail="Unauthorized")
        if order_id in ORDERS_DB and ORDERS_DB[order_id]["user_id"] != "1" and "mock-admin" not in authorization:
            raise HTTPException(status_code=403, detail="Forbidden: You do not own this order")

    if order_id in ORDERS_DB:
        return ORDERS_DB[order_id]
    raise HTTPException(status_code=404, detail="Order not found")


@demo_app.post("/orders/{order_id}/pay", tags=["Payments"])
async def pay_order(order_id: str, payload: Dict[str, Any]):
    if order_id not in ORDERS_DB:
        raise HTTPException(status_code=404, detail="Order not found")
    amount = float(payload.get("amount", ORDERS_DB[order_id]["total"]))

    if PATCH_VULNERABILITIES:
        if amount <= 0:
            raise HTTPException(status_code=400, detail="Invalid payment amount: must be positive")

    ORDERS_DB[order_id]["total"] = amount
    ORDERS_DB[order_id]["status"] = "PAID"
    return {"status": "PAID", "order_id": order_id, "amount_charged": amount}


@demo_app.post("/orders/{order_id}/refund", tags=["Payments"])
async def refund_order(order_id: str):
    if order_id not in ORDERS_DB:
        raise HTTPException(status_code=404, detail="Order not found")

    if PATCH_VULNERABILITIES:
        if ORDERS_DB[order_id]["status"] != "PAID":
            raise HTTPException(status_code=400, detail="Cannot refund order that is not in PAID status")

    ORDERS_DB[order_id]["status"] = "REFUNDED"
    return {"status": "REFUNDED", "order_id": order_id, "refund_amount": ORDERS_DB[order_id]["total"]}


# 5. Healthcare BOLA
@demo_app.get("/patients/{patient_id}", tags=["Patients"])
async def get_patient(patient_id: str, authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization token")

    if PATCH_VULNERABILITIES:
        # User 1 is requesting, patient 102 belongs to user 2
        if patient_id in PATIENTS_DB and PATIENTS_DB[patient_id].get("user_id") != "1" and "mock-admin" not in authorization:
            raise HTTPException(status_code=403, detail="Forbidden: You do not own this patient file")

    if patient_id in PATIENTS_DB:
        return PATIENTS_DB[patient_id]
    raise HTTPException(status_code=404, detail="Patient not found")


# 6. Rate Limit Testing Endpoint
@demo_app.get("/rate-limit-test", tags=["RateLimit"])
async def test_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    count = RATE_LIMIT_COUNTER.get(client_ip, 0) + 1
    RATE_LIMIT_COUNTER[client_ip] = count
    if count > 5:
        raise HTTPException(status_code=429, detail="Too Many Requests - Rate limit exceeded")
    return {"status": "OK", "request_number": count}
