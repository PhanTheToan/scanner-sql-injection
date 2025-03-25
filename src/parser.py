from bs4 import BeautifulSoup, SoupStrainer
from urllib.parse import urljoin

class AdvancedHTMLParser:
    SQL_ERROR_PATTERNS = {
        'mysql': r"SQL syntax.*MySQL",
        'postgresql': r"PostgreSQL.*ERROR",
        'oracle': r"ORA-\d{5}",
        'mssql': r"Microsoft SQL Server"
    }

    def __init__(self, html_content, base_url):
        self.strainer = SoupStrainer(['form', 'script'])
        self.soup = BeautifulSoup(html_content, 'lxml', parse_only=self.strainer)
        self.base_url = base_url
        self.dynamic_forms = []

    def _detect_dynamic_forms(self):
        # Phát hiện form được tạo bằng JavaScript
        for script in self.soup.find_all('script'):
            if 'document.createElement("form")' in script.text:
                self._parse_dynamic_forms(script.text)

    def _parse_dynamic_forms(self, script_content):
        # Logic phân tích JavaScript để tìm form động
        pass

    def extract_forms(self):
        forms = []
        # Xử lý form tĩnh
        for form in self.soup.find_all('form'):
            forms.append(self._parse_form(form))
            
        # Kết hợp form động
        forms.extend(self.dynamic_forms)
        return forms

    def _parse_form(self, form):
        return {
            'action': self._get_full_url(form.get('action')),
            'method': form.get('method', 'get').upper(),
            'inputs': self._get_form_inputs(form),
            'attributes': form.attrs
        }

    def _get_form_inputs(self, form):
        inputs = []
        for tag in form.find_all(['input', 'textarea', 'select']):
            if tag.get('name'):
                inputs.append({
                    'type': tag.get('type', 'text'),
                    'name': tag.get('name'),
                    'value': tag.get('value', ''),
                    'required': 'required' in tag.attrs
                })
        return inputs
