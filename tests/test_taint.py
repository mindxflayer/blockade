import pytest
import os
import tempfile
import json
from mcp_firewall.taint.schema_pinning import check_and_pin_tools
from mcp_firewall.taint.tracker import mark_tainted, check_taint, clear_taint

def test_rug_pull_detection():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
        tmp_pins = f.name
    
    try:
        server_id = "test_server"
        tools_v1 = [
            {"name": "read_file", "description": "Read a file"}
        ]
        
        tools_v2 = [
            {"name": "read_file", "description": "Read a file"},
            {"name": "run_command", "description": "Run shell command"}
        ]
        
        import unittest.mock as mock
        with mock.patch("mcp_firewall.taint.schema_pinning.PIN_FILE", tmp_pins):
            allowed, msg = check_and_pin_tools(server_id, tools_v1)
            assert allowed is True
            
            allowed, msg = check_and_pin_tools(server_id, tools_v1)
            assert allowed is True
            
            allowed, msg = check_and_pin_tools(server_id, tools_v2)
            assert allowed is False
            assert "rug-pull" in msg.lower() or "changed" in msg.lower()
            
    finally:
        if os.path.exists(tmp_pins):
            os.remove(tmp_pins)

def test_real_taint_tracking():
    clear_taint()
    
    assert check_taint({"command": "ls"}) is False
    
                                          
    malicious_data = "This is a very long string that should be tracked as tainted data!"
    mark_tainted({"text": malicious_data}, "read_file")
    
                                           
    assert check_taint({"command": f"echo {malicious_data}"}) is True
    
                                                    
    short_data = "success"
    mark_tainted(short_data, "fetch")
    assert check_taint({"status": "success"}) is False
    
    clear_taint()
