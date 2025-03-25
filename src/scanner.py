import re
import time
import argparse
import yaml
import os
import logging
from collections import defaultdict
from src.http_client import HTTPClient
from src.models.vulnerability import Vulnerability
from src.parser import AdvancedHTMLParser
from src.utils.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

def load_config(file_path):
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

class AdvancedSQLInjector:
    def __init__(self, config_file='config.yaml'):
        self.config = load_config(config_file)
        self.http_client = HTTPClient(self.config['http'])
        self.parser = AdvancedHTMLParser
        self.payloads = self.load_payloads(self.config['scanner']['payload_file'])
        self.vulnerabilities = []
        self.current_url = None
        self.current_input = None

    def load_payloads(self, payload_file):
        with open(payload_file) as f:
            return {
                'generic': [],
                'mysql': [],
                'postgresql': [],
                'mssql': []
            }

    def _detect_db_type(self, response):
        # Tự động phát hiện loại database từ thông báo lỗi
        for db_type, pattern in self.parser.SQL_ERROR_PATTERNS.items():
            if re.search(pattern, response.text, re.IGNORECASE):
                return db_type
        return 'unknown'

    def _test_time_based_sqli(self, form, db_type):
        # Triển khai logic time-based
        test_payloads = [
            "' OR SLEEP(5)--",
            "' WAITFOR DELAY '0:0:5'--"
        ]
        for payload in test_payloads:
            start_time = time.time()
            response = self._send_payload(form, payload)
            if response and (time.time() - start_time) > 4:
                return True
        return False

    def _analyze_response(self, response, payload):
        # Phân tích response nâng cao
        db_type = self._detect_db_type(response)
        vulnerability = Vulnerability(
            name=f"SQL Injection ({db_type.upper()})",
            description=f"Detected {db_type} SQL injection vulnerability",
            severity='high',
            payload=payload,
            input_field=self.current_input,
            url=self.current_url
        )
        self.vulnerabilities.append(vulnerability)
    
    def scan_url(self, url):
        # Implement scan_url
        pass

    def generate_report(self):
        # Implement generate_report
        return self.vulnerabilities # Sửa ở đây

def main():
    parser = argparse.ArgumentParser(
        description='SQL Injection Scanner - Automated Web Security Tool',
        epilog='Example: python -m src.scanner --url http://testsite.com/login --report report.json'
    )
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--config', default='config.yaml', help='Path to config.yaml')
    parser.add_argument('--report', help='Output report file path')

    args = parser.parse_args()

    scanner = AdvancedSQLInjector(config_file=args.config)
    is_vulnerable = scanner.scan_url(args.url)

    report_generator = ReportGenerator()
    report_file_path = report_generator.generate(scanner.generate_report())
    print(f"Report saved to {report_file_path}")

if __name__ == "__main__":
    main()
