import re
from typing import List, Tuple
from app.schemas.module3.observation import SecurityObservation
from app.schemas.module3.impact import BlastRadiusResponse, BusinessImpactResponse


class BlastRadiusEngine:
    """
    Analyzes blast radius reach, resource exposure bounds, and confirmed vs potential business consequences.
    """

    def analyze_blast_radius(
        self,
        observation: SecurityObservation,
        vulnerability_type: str,
        data_sensitivity: str
    ) -> BlastRadiusResponse:
        """
        Estimates the potential blast radius reach of the vulnerability based on API mechanics.
        """
        endpoint = observation.endpoint
        vtype = vulnerability_type.lower()

        # Check for sequential integer ID in path (e.g. /patients/101, /orders/102)
        has_numeric_id = bool(re.search(r"/\d+", observation.steps[0].get("url", "") if observation.steps else endpoint) or re.search(r"\{[a-zA-Z0-9_]*id\}", endpoint.lower()))

        if "role escalation" in vtype or "admin" in endpoint.lower():
            reach = "Full System / Multi-Tenant Admin Control"
            confidence = 0.90
            reasoning = (
                "Privilege escalation allows unauthorized users to acquire administrative capabilities, "
                "granting access across all tenant boundaries and tenant data."
            )
        elif "bola" in vtype or "idor" in vtype:
            if has_numeric_id:
                reach = "All Tenant Resources (~10,000+ Objects via ID Enumeration)"
                confidence = 0.85
                reasoning = (
                    "Endpoint uses predictable, enumerable sequential identifiers. An attacker can iterate through "
                    "all valid integer IDs across the entire database without ownership checks."
                )
            else:
                reach = "Specific Resource Group (Cross-User Scope)"
                confidence = 0.75
                reasoning = "Object-level authorization is missing for this entity collection, permitting unauthorized cross-user reads/writes."
        elif "authentication" in vtype:
            reach = "Global Unauthenticated Internet"
            confidence = 0.95
            reasoning = "Endpoint does not enforce authentication tokens, exposing endpoints directly to unauthenticated external traffic."
        elif "rate-limit" in vtype:
            reach = "API Service Capacity & Availability"
            confidence = 0.80
            reasoning = "Unrestricted request bursts allow high-volume automated scraping, credential stuffing, or resource exhaustion."
        elif "business logic" in vtype or "workflow" in vtype:
            reach = "Financial & Order State Machine Lifecycle"
            confidence = 0.85
            reasoning = "Premature or altered workflow execution permits unauthorized transactions, state fraud, or financial tampering."
        else:
            reach = "Single Resource Scope"
            confidence = 0.70
            reasoning = f"Vulnerability affects input processing on {endpoint}."

        return BlastRadiusResponse(
            estimated_reach=reach,
            confidence=confidence,
            reasoning=reasoning,
            is_estimate=True,
        )

    def analyze_business_impact(
        self,
        observation: SecurityObservation,
        vulnerability_type: str,
        data_sensitivity: str
    ) -> BusinessImpactResponse:
        """
        Determines confirmed and potential business consequences.
        """
        vtype = vulnerability_type.lower()
        actual_code = observation.actual_status
        categories: List[str] = []

        confirmed = None
        potential = None

        if "bola" in vtype or "idor" in vtype:
            categories.extend(["Data Exposure", "Unauthorized Access", "Privacy Violation"])
            confirmed = f"Unauthenticated/unauthorized requester successfully read confidential object data (HTTP {actual_code})."
            potential = "Mass exfiltration of all customer records, regulatory GDPR/HIPAA compliance fines, and loss of customer trust."
        elif "role escalation" in vtype:
            categories.extend(["Account Takeover", "Privilege Escalation", "System Compromise"])
            confirmed = f"User profile accepted elevated role modifications (HTTP {actual_code})."
            potential = "Total administrative account takeover, unauthorized data deletion, and system-wide tampering."
        elif "authentication" in vtype:
            categories.extend(["Data Exposure", "Unauthenticated Access"])
            confirmed = f"Endpoint responded to unauthenticated request with valid data payload (HTTP {actual_code})."
            potential = "Public scraping of internal resources and automated attack automation."
        elif "input validation" in vtype or "parameter tampering" in vtype:
            categories.extend(["Financial Loss", "Unauthorized Modification", "Data Corruption"])
            confirmed = f"Endpoint accepted mutated payload (e.g. negative amount or boundary value) without rejection (HTTP {actual_code})."
            potential = "Financial ledger distortion, account balance manipulation, or silent data corruption."
        elif "business logic" in vtype or "workflow" in vtype:
            categories.extend(["Financial Loss", "Workflow Violation", "Operational Disruption"])
            confirmed = f"Backend accepted out-of-order state transition (HTTP {actual_code})."
            potential = "Double-spending, fraudulent refund generation, or skipped payment workflows."
        elif "rate-limit" in vtype:
            categories.extend(["Operational Disruption", "Denial of Service"])
            confirmed = f"Server processed consecutive burst requests without throttling (HTTP {actual_code})."
            potential = "Backend service degradation, excessive cloud computing bills, and credential brute-forcing."
        else:
            categories.append("Operational Security")
            confirmed = f"Observed unexpected response behavior on {observation.endpoint}."
            potential = "Potential unexpected backend state modification or information leakage."

        return BusinessImpactResponse(
            confirmed_impact=confirmed,
            potential_impact=potential,
            impact_categories=categories,
        )
