import os
import pytest
from unittest.mock import patch, MagicMock

@pytest.mark.skipif(os.name != 'nt', reason="Windows-specific test")
def test_windows_tty_handling():
                                                                          
    from mcp_firewall.approval.cli import _sync_prompt
    
    with patch('builtins.open', create=True) as mock_open:
        mock_tty_in = MagicMock()
        mock_tty_out = MagicMock()
        mock_tty_in.readline.return_value = 'y\n'
        
                                                                  
                                                  
        mock_open.side_effect = [
            MagicMock(__enter__=MagicMock(return_value=mock_tty_in)),
            MagicMock(__enter__=MagicMock(return_value=mock_tty_out))
        ]
        
        result = _sync_prompt("test_tool", {"arg": "val"}, "test reason")
        
        assert result is True
        mock_open.assert_any_call('CON', 'r')
        mock_open.assert_any_call('CON', 'w')
