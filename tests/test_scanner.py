import unittest
import json
from unittest.mock import patch
from src.scanner import SQLInjector

class TestSQLScanner(unittest.TestCase):
    @patch('src.http_client.HTTPClient.send_request')
    def test_scan_url(self, mock_request):
        # Mock response for vulnerable site
        mock_request.return_value = MockResponse(
            text="Error: unclosed quotation mark",
            status_code=500
        )
        
        scanner = SQLInjector()
        result = scanner.scan_url('http://testvuln.com')
        self.assertTrue(result)

    @patch('src.http_client.HTTPClient.send_request')
    def test_secure_site(self, mock_request):
        # Mock response for secure site
        mock_request.return_value = MockResponse(
            text="Login successful",
            status_code=200
        )
        
        scanner = SQLInjector()
        result = scanner.scan_url('http://securesite.com')
        self.assertFalse(result)

class MockResponse:
    def __init__(self, text, status_code):
        self.text = text
        self.status_code = status_code

if __name__ == '__main__':
    unittest.main()
