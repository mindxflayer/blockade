import subprocess
import sys

def test_wrap_smoke():
                                                                                     
    cmd = [sys.executable, "-m", "mcp_firewall.main", "wrap", sys.executable, "-c", "print('hello')"]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    assert result.returncode == 0, f"Wrap command crashed: {result.stderr}"
    assert "UnboundLocalError" not in result.stderr
    assert "TypeError" not in result.stderr
