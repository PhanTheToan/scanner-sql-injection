# filepath: /sql-scanner-injection/sql-scanner-injection/src/scanner.py
# This file implements the main logic for scanning inputs for potential SQL injection vulnerabilities.

class SQLScanner:
    def __init__(self, payloads):
        self.payloads = payloads

    def scan(self, input_data):
        vulnerabilities = []
        for payload in self.payloads:
            if self.is_vulnerable(input_data, payload):
                vulnerabilities.append(payload)
        return vulnerabilities

    def is_vulnerable(self, input_data, payload):
        # Simple check for SQL injection patterns
        return payload.lower() in input_data.lower()

def load_payloads(filepath):
    with open(filepath, 'r') as file:
        return [line.strip() for line in file.readlines()]

if __name__ == "__main__":
    payloads = load_payloads('../data/payloads.txt')
    scanner = SQLScanner(payloads)
    test_input = "SELECT * FROM users WHERE username = 'admin' --"
    vulnerabilities = scanner.scan(test_input)
    print("Vulnerabilities found:", vulnerabilities)