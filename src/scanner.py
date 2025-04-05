import re
import time
import argparse
import yaml
import os
import logging
from src.http_client import HTTPClient
from src.models.vulnerability import Vulnerability
from src.parser import AdvancedHTMLParser
from src.utils.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

def load_config(file_path):
    with open(file_path, 'r') as f:
        config = yaml.safe_load(f)

    def replace_env_vars(obj):
        if isinstance(obj, str):
            return os.path.expandvars(obj)
        elif isinstance(obj, dict):
            return {k: replace_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [replace_env_vars(elem) for elem in obj]
        return obj

    return replace_env_vars(config)

class AdvancedSQLInjector:
    def __init__(self, config_file='config.yaml'):
        self.config = load_config(config_file)
        self.http_client = HTTPClient(self.config['http'])
        self.parser = AdvancedHTMLParser
        self.payloads = self.load_payloads(self.config['scanner']['payload_file'])
        self.vulnerabilities = []
        self.vuln_set = set()
        self.current_url = None

    def load_payloads(self, payload_file):
        payloads = {
            'error': [],
            'boolean': [],
            'time': []
        }
        with open(payload_file, 'r') as f:
            current_section = None
            for line in f.readlines():
                line = line.strip()
                if line.startswith('# Error-Based Payloads'):
                    current_section = 'error'
                elif line.startswith('# Boolean-Based Payloads'):
                    current_section = 'boolean'
                elif line.startswith('# Time-Based Payloads'):
                    current_section = 'time'
                elif line and not line.startswith('#') and current_section:
                    payloads[current_section].append(line)
        all_payloads = list(set(payloads['error'] + payloads['boolean'] + payloads['time']))
        logger.info(f"Loaded {len(payloads['error'])} error, {len(payloads['boolean'])} boolean, {len(payloads['time'])} time payloads. Total unique: {len(all_payloads)}")
        return {'all': all_payloads}

    def _send_payload(self, form, payload, input_field_name):
        url = form['action']
        method = form['method']
        data = {input_field['name']: input_field['value'] for input_field in form['inputs']}
        data[input_field_name] = payload
        
        logger.debug(f"Sending payload '{payload}' to {url} on field '{input_field_name}'")
        if method == 'POST':
            response = self.http_client.send_advanced_request(url, method='POST', data=data)
        else:
            response = self.http_client.send_advanced_request(url, method='GET', params=data)
        return response

    def _detect_db_type(self, response_text):
        for db_type, pattern in self.parser.SQL_ERROR_PATTERNS.items():
            if re.search(pattern, response_text, re.IGNORECASE):
                return db_type
        return 'unknown'

    def _analyze_response(self, response, payload, input_field_name, start_time):
        db_type = self._detect_db_type(response.text)
        
        logger.debug(f"Response for payload '{payload}' on field '{input_field_name}': {response.text[:200]}...")
        
        # Kiểm tra Error Based
        error_key = ('error', db_type, payload, input_field_name, self.current_url)
        is_error_based = any(re.search(pattern, response.text, re.IGNORECASE) for pattern in self.parser.SQL_ERROR_PATTERNS.values())
        logger.debug(f"Checking Error Based for '{payload}' on '{input_field_name}': {'Detected' if is_error_based else 'Not detected'}")
        if is_error_based:
            if error_key not in self.vuln_set:
                vulnerability = Vulnerability(
                    name=f"SQL Injection ({db_type.upper()}) - Error Based",
                    description=f"Detected {db_type} SQL injection vulnerability via error message",
                    severity='high',
                    payload=payload,
                    input_field=input_field_name,
                    url=self.current_url
                )
                self.vulnerabilities.append(vulnerability)
                self.vuln_set.add(error_key)
                logger.info(f"Found vulnerability: {vulnerability}")

        # Kiểm tra Boolean Based
        boolean_key = ('boolean', db_type, payload, input_field_name, self.current_url)
        is_boolean_based = "Welcome" in response.text
        logger.debug(f"Checking Boolean Based for '{payload}' on '{input_field_name}': {'Detected' if is_boolean_based else 'Not detected'}")
        if is_boolean_based:
            if boolean_key not in self.vuln_set:
                vulnerability = Vulnerability(
                    name=f"SQL Injection ({db_type.upper()}) - Boolean Based",
                    description=f"Detected {db_type} SQL injection vulnerability via successful login",
                    severity='high',
                    payload=payload,
                    input_field=input_field_name,
                    url=self.current_url
                )
                self.vulnerabilities.append(vulnerability)
                self.vuln_set.add(boolean_key)
                logger.info(f"Found vulnerability: {vulnerability}")

        # Kiểm tra Time Based
        time_key = ('time', db_type, payload, input_field_name, self.current_url)
        elapsed_time = time.time() - start_time
        contains_delay = any(func in payload.upper() for func in ['SLEEP', 'WAITFOR', 'DELAY'])
        is_time_based = elapsed_time > 4 and contains_delay
        logger.debug(f"Checking Time Based for '{payload}' on '{input_field_name}': {'Detected' if is_time_based else 'Not detected'} (Elapsed time: {elapsed_time:.2f}s, Contains delay function: {contains_delay})")
        if is_time_based:
            if time_key not in self.vuln_set:
                vulnerability = Vulnerability(
                    name=f"SQL Injection ({db_type.upper()}) - Time Based",
                    description="Detected SQL injection vulnerability via time delay",
                    severity='critical',
                    payload=payload,
                    input_field=input_field_name,
                    url=self.current_url
                )
                self.vulnerabilities.append(vulnerability)
                self.vuln_set.add(time_key)
                logger.info(f"Found vulnerability: {vulnerability}")

    def scan_url(self, url):
        self.current_url = url
        response = self.http_client.send_advanced_request(url)
        if not response:
            logger.error(f"Failed to fetch {url}")
            return
        
        parser_instance = self.parser(response.text, url)
        forms = parser_instance.extract_forms()
        logger.info(f"Found {len(forms)} forms on {url}")
        
        for form in forms:
            for input_field in form['inputs']:
                input_field_name = input_field['name']
                for payload in self.payloads['all']:
                    start_time = time.time()
                    response = self._send_payload(form, payload, input_field_name)
                    if response:
                        self._analyze_response(response, payload, input_field_name, start_time)

    def generate_report(self):
        return self.vulnerabilities

def main():
    parser = argparse.ArgumentParser(
        description='SQL Injection Scanner - Automated Web Security Tool',
        epilog='Example: python -m src.scanner --url http://testsite.com/login --report report.html'
    )
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--config', default='config.yaml', help='Path to config.yaml')
    parser.add_argument('--report', default='report.html', help='Output report file path')

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)
    scanner = AdvancedSQLInjector(config_file=args.config)
    scanner.scan_url(args.url)

    report_generator = ReportGenerator()
    report_file_path = report_generator.generate(scanner.generate_report(), args.report)
    print(f"Report saved to {report_file_path}")

if __name__ == "__main__":
    main()