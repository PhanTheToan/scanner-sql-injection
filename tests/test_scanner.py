import unittest
from src.scanner import Scanner  # Assuming Scanner is the main class in scanner.py

class TestScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = Scanner()

    def test_valid_input(self):
        # Test with a valid input that should not trigger a vulnerability
        result = self.scanner.scan("SELECT * FROM users WHERE id = 1")
        self.assertFalse(result)

    def test_sql_injection(self):
        # Test with an input that is a potential SQL injection
        result = self.scanner.scan("1; DROP TABLE users; --")
        self.assertTrue(result)

    def test_empty_input(self):
        # Test with an empty input
        result = self.scanner.scan("")
        self.assertFalse(result)

    def test_malformed_input(self):
        # Test with malformed SQL input
        result = self.scanner.scan("SELECT * FROM users WHERE id = ' OR '1'='1")
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()