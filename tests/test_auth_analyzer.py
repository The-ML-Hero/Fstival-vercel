from app.services.analyzers.auth_analyzer import AuthAnalyzer


def test_auth_detection_and_unauthenticated_audit():
    schemes_raw = [
        {
            "scheme_name": "BearerJWT",
            "scheme_type": "bearer",
            "security_required": True,
            "token_location": "header",
            "header_name": "Authorization",
            "bearer_format": "JWT",
            "scopes": None,
        }
    ]

    endpoints_raw = [
        {
            "method": "POST",
            "path": "/auth/login",
            "security_required": False,
        },
        {
            "method": "GET",
            "path": "/users/me",
            "security_required": True,
        },
        {
            "method": "GET",
            "path": "/admin/unprotected",
            "security_required": False,
        }
    ]

    analyzer = AuthAnalyzer()
    res = analyzer.analyze(schemes_raw, endpoints_raw)

    assert len(res.schemes) == 1
    assert res.schemes[0].scheme_type == "bearer"
    assert res.global_security_required is True
    assert "POST /auth/login" in res.unauthenticated_endpoints
    assert "GET /admin/unprotected" in res.unauthenticated_endpoints
    assert "GET /users/me" in res.authenticated_endpoints
