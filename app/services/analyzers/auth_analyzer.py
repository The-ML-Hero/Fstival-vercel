from typing import Any, Dict, List, Set
from app.schemas.auth import AuthAnalysisResult, AuthSchemeResponse


class AuthAnalyzer:
    """
    Analyzes authentication schemes and audits endpoint security posture.
    Recognizes Bearer/JWT, API Key, Basic Auth, OAuth2, and unauthenticated routes.
    """

    def analyze(
        self,
        security_schemes_raw: List[Dict[str, Any]],
        endpoints_raw: List[Dict[str, Any]]
    ) -> AuthAnalysisResult:
        schemes: List[AuthSchemeResponse] = []
        for s in security_schemes_raw:
            schemes.append(AuthSchemeResponse(
                scheme_name=s.get("scheme_name", "default"),
                scheme_type=s.get("scheme_type", "bearer"),
                security_required=s.get("security_required", True),
                token_location=s.get("token_location"),
                header_name=s.get("header_name"),
                bearer_format=s.get("bearer_format"),
                scopes=s.get("scopes"),
                description=s.get("description"),
            ))

        unauthenticated_endpoints: List[str] = []
        authenticated_endpoints: List[str] = []

        global_security_required = len(schemes) > 0

        for ep in endpoints_raw:
            method_path = f"{ep.get('method', 'GET')} {ep.get('path', '')}"
            if ep.get("security_required", False):
                authenticated_endpoints.append(method_path)
            else:
                unauthenticated_endpoints.append(method_path)

        return AuthAnalysisResult(
            schemes=schemes,
            global_security_required=global_security_required,
            unauthenticated_endpoints=unauthenticated_endpoints,
            authenticated_endpoints=authenticated_endpoints,
        )
