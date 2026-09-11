from app.services.analyzers.role_analyzer import RoleAnalyzer


def test_role_inference_from_paths_tags_and_scopes():
    security_schemes = [
        {
            "scheme_name": "OAuth2",
            "scheme_type": "oauth2",
            "scopes": {
                "admin:write": "Admin full access",
                "doctor:clinical": "Doctor clinical records"
            }
        }
    ]

    endpoints = [
        {
            "method": "GET",
            "path": "/admin/dashboard",
            "tags": ["admin"],
            "security_required": True,
            "schemas": []
        },
        {
            "method": "GET",
            "path": "/doctor/patients",
            "tags": ["clinical"],
            "security_required": True,
            "schemas": []
        },
        {
            "method": "POST",
            "path": "/users",
            "tags": ["users"],
            "security_required": False,
            "schemas": [
                {
                    "schema_json": {
                        "properties": {
                            "role": {
                                "type": "string",
                                "enum": ["nurse", "manager"]
                            }
                        }
                    }
                }
            ]
        }
    ]

    analyzer = RoleAnalyzer()
    res = analyzer.analyze(endpoints, security_schemes)
    detected_role_names = [r.role_name for r in res.detected_roles]

    assert "admin" in detected_role_names
    assert "doctor" in detected_role_names
    assert "nurse" in detected_role_names
    assert "manager" in detected_role_names

    admin_role = next(r for r in res.detected_roles if r.role_name == "admin")
    assert admin_role.confidence >= 0.85
    assert len(admin_role.evidence) > 0
    assert len(admin_role.reasoning) > 0
