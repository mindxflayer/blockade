import pytest
from mcp_firewall.policy.engine import PolicyEngine

def test_bare_tool_name_matching():
    policy_yaml = """
    default_profile: default
    profiles:
      default:
        tools:
          "read_file": "allow"
          "write_*": "approve_medium"
          "*": "judge"
    """
    import tempfile
    import os
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".yaml") as f:
        f.write(policy_yaml)
        tmp_path = f.name
    
    try:
        engine = PolicyEngine(policy_path=tmp_path)
        
        assert engine.evaluate("read_file", "default") == "allow"
        assert engine.evaluate("write_file", "default") == "approve_medium"
        assert engine.evaluate("execute_command", "default") == "judge"
    finally:
        os.remove(tmp_path)
