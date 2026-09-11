from app.services.simulation.identity_manager import IdentityManager


def test_identity_manager_tokens_and_redaction():
    mgr = IdentityManager(custom_tokens={
        "user": "custom-user-token-123",
        "admin": "custom-admin-token-789"
    })

    # Test token injection
    user_headers = mgr.inject_auth_headers({"Accept": "application/json"}, role="user")
    assert user_headers["Authorization"] == "Bearer custom-user-token-123"

    admin_headers = mgr.inject_auth_headers({}, role="admin")
    assert admin_headers["Authorization"] == "Bearer custom-admin-token-789"

    anon_headers = mgr.inject_auth_headers({}, role="anonymous")
    assert "Authorization" not in anon_headers

    # Test redaction
    sensitive_headers = {
        "Authorization": "Bearer custom-user-token-123",
        "X-Api-Key": "secret-key-xyz",
        "Content-Type": "application/json"
    }
    redacted = mgr.redact_sensitive_headers(sensitive_headers)
    assert redacted["Authorization"] == "[REDACTED_AUTH_CREDENTIAL]"
    assert redacted["X-Api-Key"] == "[REDACTED_AUTH_CREDENTIAL]"
    assert redacted["Content-Type"] == "application/json"
