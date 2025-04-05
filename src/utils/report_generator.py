from jinja2 import Environment, FileSystemLoader
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader('templates'))

    def generate(self, vulnerabilities, output_path='report.html'):
        template = self.env.get_template('report.html')
        stats = {
            'total': len(vulnerabilities),
            'severity_distribution': {}
        }
        for vuln in vulnerabilities:
            stats['severity_distribution'][vuln.severity] = stats['severity_distribution'].get(vuln.severity, 0) + 1
        
        html_content = template.render(
            meta={'generated_at': datetime.now().isoformat()},
            stats=stats,
            findings=[vuln.to_dict() for vuln in vulnerabilities]
        )
        with open(output_path, 'w') as f:
            f.write(html_content)
        return output_path