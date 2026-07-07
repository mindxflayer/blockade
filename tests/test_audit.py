import pytest
from mcp_firewall.audit.db import AuditLogger

def test_secret_redaction():
    logger = AuditLogger(":memory:")
    
    raw_arguments = {
        "safe_arg": "hello world",
        "aws_key": "AKIAIOSFODNN7EXAMPLE",
        "jwt_token": "eyJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "nested": {
            "openai_api_key": "sk-proj-1234567890abcdef1234567890abcdef",
            "github_token": "ghp_1234567890abcdef1234567890abcdef123456",
            "auth_header": "Bearer some-long-token-value"
        },
        "password": "my_super_secret_password"
    }
    
    redacted = logger._redact_secrets(raw_arguments)
    
    assert redacted["password"] == "[REDACTED]"
    assert redacted["aws_key"] == "[REDACTED_PATTERN]"
    assert redacted["jwt_token"] == "[REDACTED_PATTERN]"
    assert redacted["nested"]["openai_api_key"] == "[REDACTED_PATTERN]"
    assert redacted["nested"]["github_token"] == "[REDACTED_PATTERN]"
    assert redacted["nested"]["auth_header"] == "[REDACTED_PATTERN]"
    assert redacted["safe_arg"] == "hello world"
