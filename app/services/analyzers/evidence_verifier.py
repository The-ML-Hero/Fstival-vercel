import json
import re
from typing import Any, Dict, Tuple
from app.schemas.module3.observation import SecurityObservation


class EvidenceVerificationResult:
    def __init__(
        self,
        status: str,  # "confirmed", "likely", "inconclusive", "false-positive"
        confidence: float,  # 0.0 to 1.0
        evidence_summary: str,
        data_sensitivity: str,  # "high", "medium", "low"
        is_vulnerable: bool
    ):
        self.status = status
        self.confidence = confidence
        self.evidence_summary = evidence_summary
        self.data_sensitivity = data_sensitivity
        self.is_vulnerable = is_vulnerable


class EvidenceVerifier:
    """
    Evaluates HTTP status codes, headers, and response bodies to distinguish
    true confirmed security vulnerabilities from false positives and inconclusive errors.
    """

    SENSITIVE_FIELD_PATTERNS = [
        re.compile(r'(?i)\b(?:password|token|secret|api_key|auth|ssn|credit_card|diagnosis|medical_record|balance|total|user_id|patient_id)\b'),
        re.compile(r'(?i)\b(?:email|phone|address|birth_date|role|admin|credentials)\b'),
    ]

    ERROR_PAGE_PATTERNS = [
        re.compile(r'(?i)(?:<!doctype html|<html|<head|<title>404|not found|page does not exist)'),
        re.compile(r'(?i)(?:{"(?:error|message|detail)":\s*"(?:not found|unauthorized|forbidden)")'),
    ]

    def verify(self, observation: SecurityObservation) -> EvidenceVerificationResult:
        """
        Performs deep evidence analysis on a security observation.
        """
        expected = observation.expected_status
        actual = observation.actual_status
        body = observation.response_body or ""
        category = observation.category.lower()

        # If assertion passed (API blocked attack as expected), it is NOT vulnerable
        if observation.status == "passed" or (expected and actual == expected):
            return EvidenceVerificationResult(
                status="false-positive",
                confidence=0.95,
                evidence_summary=f"API correctly returned HTTP {actual} matching expected secure response ({expected}). Security control is properly active.",
                data_sensitivity="low",
                is_vulnerable=False
            )

        # If HTTP 500 was returned on attack payload
        if actual == 500:
            return EvidenceVerificationResult(
                status="inconclusive",
                confidence=0.60,
                evidence_summary="Target API returned HTTP 500 Internal Server Error. Suggests unhandled exception or potential crash.",
                data_sensitivity="medium",
                is_vulnerable=True
            )

        # If API returned 200/201 when 401/403/400/429 was expected
        if actual in {200, 201, 204}:
            # Check if 200 is actually an error/404 page disguised as 200
            for err_pat in self.ERROR_PAGE_PATTERNS:
                if err_pat.search(body):
                    return EvidenceVerificationResult(
                        status="false-positive",
                        confidence=0.85,
                        evidence_summary=f"HTTP 200 was returned, but response content contains error/not-found indicators. Flagged as false-positive.",
                        data_sensitivity="low",
                        is_vulnerable=False
                    )

            # Check for sensitive domain data in response body
            sensitivity = "medium"
            has_sensitive_data = False
            for sens_pat in self.SENSITIVE_FIELD_PATTERNS:
                if sens_pat.search(body):
                    has_sensitive_data = True
                    sensitivity = "high"
                    break

            # Parse JSON body to confirm valid object structure
            is_valid_json = False
            try:
                parsed_json = json.loads(body)
                if isinstance(parsed_json, (dict, list)) and len(parsed_json) > 0:
                    is_valid_json = True
            except Exception:
                pass

            if is_valid_json and has_sensitive_data:
                return EvidenceVerificationResult(
                    status="confirmed",
                    confidence=0.95,
                    evidence_summary=f"Confirmed vulnerability: Target API returned HTTP {actual} containing structured entity data with sensitive fields ({sensitivity} sensitivity).",
                    data_sensitivity=sensitivity,
                    is_vulnerable=True
                )
            elif is_valid_json or len(body.strip()) > 10:
                return EvidenceVerificationResult(
                    status="likely",
                    confidence=0.80,
                    evidence_summary=f"Likely vulnerability: Target returned HTTP {actual} with valid response payload instead of expected HTTP {expected}.",
                    data_sensitivity=sensitivity,
                    is_vulnerable=True
                )
            else:
                return EvidenceVerificationResult(
                    status="likely",
                    confidence=0.70,
                    evidence_summary=f"Status code mismatch: Returned HTTP {actual} when HTTP {expected} was expected.",
                    data_sensitivity="low",
                    is_vulnerable=True
                )

        # Default fallback
        return EvidenceVerificationResult(
            status="inconclusive",
            confidence=0.50,
            evidence_summary=f"Unexpected status HTTP {actual} (expected {expected}). Evidence inconclusive.",
            data_sensitivity="low",
            is_vulnerable=True
        )
