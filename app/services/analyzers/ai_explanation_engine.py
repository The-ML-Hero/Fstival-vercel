from typing import Any, Dict
from app.schemas.module3.observation import SecurityObservation


class AIExplanationResult:
    def __init__(
        self,
        technical_explanation: str,
        simple_explanation: str,
        evidence_explanation: str,
        why_it_matters: str
    ):
        self.technical_explanation = technical_explanation
        self.simple_explanation = simple_explanation
        self.evidence_explanation = evidence_explanation
        self.why_it_matters = why_it_matters


class AIExplanationEngine:
    """
    AI-powered Explanation Engine for Module 3.
    Produces developer-friendly dual explanations (Technical and Plain English)
    grounded strictly in observed execution evidence without hallucination.
    """

    def generate_explanations(
        self,
        observation: SecurityObservation,
        vulnerability_type: str,
        severity: str
    ) -> AIExplanationResult:
        """
        Generates structured, developer-actionable explanations across 4 dimensions.
        """
        endpoint = observation.endpoint
        method = observation.method
        actual = observation.actual_status
        expected = observation.expected_status
        vtype = vulnerability_type.lower()

        if "bola" in vtype or "idor" in vtype:
            technical = (
                f"Broken Object Level Authorization (OWASP API1:2023). Endpoint {method} {endpoint} "
                f"accepts client-provided resource identifiers without verifying that the requesting identity "
                f"owns or has explicit permissions to access the referenced object."
            )
            simple = (
                f"A logged-in user can view or modify records belonging to other users simply by changing the ID in the URL. "
                f"The server fails to check if the data actually belongs to the user making the request."
            )
            evidence = (
                f"When executing {method} {endpoint}, the security probe submitted a foreign resource ID expecting "
                f"an authorization rejection (HTTP {expected}), but the API returned HTTP {actual} with valid object payload."
            )
            why = (
                "BOLA is the #1 critical risk in modern APIs. It leads directly to mass customer data leaks, "
                "regulatory fines (GDPR/HIPAA), and severe brand damage."
            )

        elif "role escalation" in vtype or "mass assignment" in vtype:
            technical = (
                f"Broken Object Property Level Authorization / Mass Assignment (OWASP API3 / API5:2023). "
                f"Endpoint {method} {endpoint} blindly binds request payload properties (e.g. 'role': 'admin') "
                f"to the internal domain model without field-level authorization allowlists."
            )
            simple = (
                "A regular user can grant themselves administrative privileges by adding an extra field "
                "(like role: 'admin') to their update request."
            )
            evidence = (
                f"Sent a payload with elevated role parameters to {method} {endpoint}. The server returned "
                f"HTTP {actual} instead of rejecting the unauthorized field modification (HTTP {expected})."
            )
            why = (
                "Privilege escalation allows unauthorized actors to seize full administrative control over "
                "the entire application, accessing all tenant databases and administrative functions."
            )

        elif "authentication" in vtype:
            technical = (
                f"Broken Authentication (OWASP API2:2023). Endpoint {method} {endpoint} "
                f"does not enforce authentication middleware or valid Bearer/API token verification."
            )
            simple = (
                "Anyone on the internet can access this endpoint without logging in or providing an API key."
            )
            evidence = (
                f"Dispatched an unauthenticated request without Authorization headers to {method} {endpoint}. "
                f"The endpoint returned HTTP {actual} instead of HTTP 401 Unauthorized."
            )
            why = (
                "Exposed unauthenticated endpoints allow automated scrapers and malicious actors to harvest "
                "internal resources with zero accountability."
            )

        elif "input validation" in vtype or "tampering" in vtype:
            technical = (
                f"Lack of Input Validation & Parameter Tampering (OWASP API8:2023). "
                f"Endpoint {method} {endpoint} processes client-supplied values without boundary, type, or range validation."
            )
            simple = (
                "The server accepts invalid or negative values (such as negative prices or malformed strings) "
                "without validating them."
            )
            evidence = (
                f"Submitted mutated parameters to {method} {endpoint}. The API accepted the malicious input "
                f"with HTTP {actual} instead of rejecting it with HTTP 400/422."
            )
            why = (
                "Unvalidated inputs cause financial imbalance, corrupt database state, or trigger downstream logic failures."
            )

        elif "rate-limit" in vtype:
            technical = (
                f"Unrestricted Resource Consumption (OWASP API4:2023). Endpoint {method} {endpoint} "
                f"lacks rate-limiting throttling or token-bucket controls."
            )
            simple = (
                "The server allows unlimited rapid-fire requests without slowing down or blocking the client."
            )
            evidence = (
                f"Dispatched consecutive rapid burst requests to {method} {endpoint}. The server never returned "
                f"HTTP 429 Too Many Requests."
            )
            why = (
                "Missing rate limits invite denial of service (DoS), brute-force password guessing, and massive infrastructure costs."
            )

        else:
            technical = (
                f"Security flaw detected on {method} {endpoint}. The server behaved inconsistently with secure API standards "
                f"(expected HTTP {expected}, actual HTTP {actual})."
            )
            simple = "The endpoint allows unintended interactions that violate expected security boundaries."
            evidence = f"Executed attack test on {method} {endpoint} yielding status HTTP {actual}."
            why = "Insecure API endpoints create attack vectors that degrade overall system integrity."

        return AIExplanationResult(
            technical_explanation=technical,
            simple_explanation=simple,
            evidence_explanation=evidence,
            why_it_matters=why,
        )
