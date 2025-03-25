from jinja2 import Template
import os
import datetime
from collections import defaultdict

class ReportGenerator:
    TEMPLATES = {
        'html': 'templates/report.html'
    }

    def generate(self, vulnerabilities, format='html'):
        report_data = self._prepare_data(vulnerabilities)
        
        if format == 'html':
            return self._generate_html(report_data)
        else:
            return self._generate_json(report_data)

    def _prepare_data(self, vulnerabilities):
        return {
            'meta': {
                'generated_at': datetime.datetime.now().isoformat(),
                'scanner_version': '2.0'
            },
            'stats': {
                'total': len(vulnerabilities),
                'severity_distribution': self._calculate_severity(vulnerabilities)
            },
            'findings': [vuln.to_dict() for vuln in vulnerabilities]
        }

    def _calculate_severity(self, vulnerabilities):
        counts = defaultdict(int)
        for vuln in vulnerabilities:
            counts[vuln.severity] += 1
        return dict(counts)

    def _generate_html(self, report_data):
        template_path = os.path.join(os.getcwd(), self.TEMPLATES['html'])
        with open(template_path, 'r') as f:
            template = Template(f.read())
        html_content = template.render(**report_data)
        report_file_path = os.path.join(os.getcwd(), 'report.html')
        with open(report_file_path, 'w') as f:
            f.write(html_content)
        return report_file_path

    def _generate_json(self, report_data):
        # Logic tạo file JSON
        pass
