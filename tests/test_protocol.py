import pytest
import json
from mcp_firewall.interceptor.parser import intercept_request

pytestmark = pytest.mark.asyncio

@pytest.fixture
def mock_engine(monkeypatch):
    class MockEngine:
        def evaluate(self, *args, **kwargs):
            return "allow"
    monkeypatch.setattr("mcp_firewall.interceptor.parser.policy_engine", MockEngine())

async def test_valid_jsonrpc_request(mock_engine):
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "id": 1,
        "params": {
            "name": "read_file",
            "arguments": {"path": "/etc/passwd"}
        }
    }
    allowed, block_reason, modified = await intercept_request(request)
    assert allowed is True
    assert modified["id"] == 1
    assert modified["method"] == "tools/call"
    
async def test_missing_jsonrpc_version(mock_engine):
    request = {
        "method": "tools/call",
        "id": 1,
        "params": {"name": "test"}
    }
    allowed, block_reason, modified = await intercept_request(request)
    assert allowed is True
    assert modified == request
