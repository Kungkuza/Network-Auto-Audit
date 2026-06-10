import unittest
from unittest.mock import patch, MagicMock
from NetworkAutomation import audit_single_device

class TestNetworkTool(unittest.TestCase):

    @patch('NetworkAutomation.ConnectHandler')
    def test_successful_audit(self, mock_connect_handler):
        """Test that a successful SSH connection processes audit rules correctly."""
        mock_ssh = MagicMock()
        mock_connect_handler.return_value.__enter__.return_value = mock_ssh
        
        # We simulate a CLEAN device (No Telnet, Type 9 secrets)
        mock_ssh.send_command.side_effect = [
            "transport input ssh",          # Output for VTY line check
            "username admin secret 9 $9$..." # Output for password hash check
        ]

        device_info = {"host": "192.168.1.10", "device_type": "cisco_ios", "port": 22}
        
        # Run the function with mocked dependencies
        report = audit_single_device(device_info, "user", "pass", config_commands=[])

        # Assertions
        self.assertEqual(report["status"], "Success")
        self.assertEqual(len(report["failed"]), 0)
        self.assertEqual(len(report["passed"]), 2)

if __name__ == '__main__':
    unittest.main()