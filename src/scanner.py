import logging
from .http_client import HTTPClient
from src.parser import HTMLParser
import argparse
import json
import os

logger = logging.getLogger(__name__)
class SQLInjector:
    def __init__(self, payload_file='data/payloads.txt'):
        self.payloads = self.load_payloads(payload_file)
        self.http_client = HTTPClient()
        self.vulnerabilities = []

    def load_payloads(self, file_path):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        full_path = os.path.join(dir_path, '..', file_path)
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
             return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"[!] Lỗi: Không tìm thấy file payloads tại {full_path}")
            print("[!] Vui lòng tạo file payloads.txt trong thư mục data")
            exit(1)

    def scan_url(self, url):
        response = self.http_client.send_request(url)
        if not response:
            return False
            
        parser = HTMLParser(response.text, url)
        forms = parser.extract_forms()
        
        for form in forms:
            self.test_form(form)
        
        return len(self.vulnerabilities) > 0

    def test_form(self, form):
        for payload in self.payloads:
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] in ['hidden', 'submit']:
                    data[input_field['name']] = input_field['value']
                else:
                    data[input_field['name']] = payload

            response = self.http_client.send_request(
                url=form['action'],
                method=form['method'],
                data=data if form['method'] == 'POST' else None,
                params=data if form['method'] == 'GET' else None
            )

            if self.is_vulnerable(response):
                self.vulnerabilities.append({
                    'url': form['action'],
                    'payload': payload,
                    'form_details': form
                })

    def is_vulnerable(self, response):
        if not response:
            return False
            
        content = response.text.lower()
        return any(error in content for error in HTMLParser.SQL_ERRORS)

    def generate_report(self):
        return {
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities)
        }
def main():
    parser = argparse.ArgumentParser(
        description='SQL Injection Scanner - Automated Web Security Tool',
        epilog='Example: python -m src.scanner --url http://testsite.com/login --report report.json'
    )
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--payloads', default='data/payloads.txt', 
                      help='Custom payloads file path')
    parser.add_argument('--report', help='Output report file path')

    args = parser.parse_args()

    scanner = SQLInjector(payload_file=args.payloads)
    is_vulnerable = scanner.scan_url(args.url)
    
    if not is_vulnerable:
        print(f"[!] Không tìm thấy lỗ hổng SQL Injection tại {args.url}")
    
    if args.report:
        with open(args.report, 'w') as f:
            json.dump(scanner.generate_report(), f, indent=2)
        print(f"Report saved to {args.report}")
    else:
        print(json.dumps(scanner.generate_report(), indent=2))

if __name__ == "__main__":
    main()