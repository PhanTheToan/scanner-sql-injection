import unittest
from src.parser import parse_html, parse_form

class TestParser(unittest.TestCase):

    def test_parse_html(self):
        html_content = "<html><body><h1>Test</h1></body></html>"
        expected_output = {"h1": "Test"}
        self.assertEqual(parse_html(html_content), expected_output)

    def test_parse_form(self):
        form_data = "username=test&password=1234"
        expected_output = {"username": "test", "password": "1234"}
        self.assertEqual(parse_form(form_data), expected_output)

if __name__ == '__main__':
    unittest.main()