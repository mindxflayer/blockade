import os
import sys
import json
import asyncio
import pytest
from mcp_firewall.proxy.stdio import run_stdio_proxy

@pytest.mark.asyncio
async def test_integration_stdio_proxy(tmp_path):
                                                                               
    fake_server_code = """
import sys
import json
for line in sys.stdin:
    if not line.strip(): continue
    req = json.loads(line)
    if req.get("method") == "ping":
        print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": "pong"}))
    sys.stdout.flush()
"""
    server_script = tmp_path / "fake_server.py"
    server_script.write_text(fake_server_code)
    
    server_cmd = f"{sys.executable} {server_script}"
    
    async def interceptor_fn(request):
                                                   
        return (True, "", request)
        
                                                            
    import asyncio
    input_queue = asyncio.Queue()
    await input_queue.put(json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}))
    await input_queue.put(None)             
    
                                                                                                   
                                                                                                           
                    
                                                        
    pass

def test_integration_proxy_subprocess(tmp_path):
    import subprocess
    fake_server_code = """
import sys
import json
while True:
    line = sys.stdin.readline()
    if not line: break
    if not line.strip(): continue
    req = json.loads(line)
    if req.get("method") == "tools/call":
        print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": {"content": [{"type": "text", "text": "pong"}]}}))
    sys.stdout.flush()
"""
    server_script = tmp_path / "fake_server.py"
    server_script.write_text(fake_server_code)
    
    policy_yaml = """
default_profile: default
profiles:
  default:
    tools:
      "read_file": "allow"
"""
    policy_file = tmp_path / "policies.yaml"
    policy_file.write_text(policy_yaml)
    
    audit_db = tmp_path / "audit.db"

                                               
                                                                         
    fw_env = os.environ.copy()
    fw_env["MCP_PROFILE"] = "default"
    fw_env["MCP_POLICY_PATH"] = str(policy_file)
    fw_env["MCP_AUDIT_DB_PATH"] = str(audit_db)
    
                   
    payload = json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": "read_file", "arguments": {}}}) + "\n"
    
                                                    
    pkg_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
    fw_env["PYTHONPATH"] = pkg_dir
    
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_firewall", "wrap", sys.executable, str(server_script)],
        input=payload,
        text=True,
        capture_output=True,
        env=fw_env,
        timeout=10
    )
    
                                        
    if "pong" not in proc.stdout:
        print("STDOUT:", proc.stdout)
        print("STDERR:", proc.stderr)
    assert "pong" in proc.stdout
    assert proc.returncode == 0
