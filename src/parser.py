from bs4 import BeautifulSoup, SoupStrainer
from urllib.parse import urljoin, urlparse,urlunparse
import re

class AdvancedHTMLParser:
    SQL_ERROR_PATTERNS = {
        'mysql': r"SQL syntax.*MySQL|SQLSTATE\[42000\]",
        'postgresql': r"PostgreSQL.*ERROR",
        'oracle': r"ORA-\d{5}",
        'mssql': r"Microsoft SQL Server"
    }

    def __init__(self, html_content, base_url):
        self.strainer = SoupStrainer(['form', 'script','a'])
        self.soup = BeautifulSoup(html_content, 'lxml', parse_only=self.strainer)
        self.base_url = base_url
        self.dynamic_forms = []

    def _detect_dynamic_forms(self):
        for script in self.soup.find_all('script'):
            if 'document.createElement("form")' in script.text:
                self._parse_dynamic_forms(script.text)

    def _parse_dynamic_forms(self, script_content):
        pass

    def extract_forms(self):
        forms = []
        for form in self.soup.find_all('form'):
            forms.append(self._parse_form(form))
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
    def extract_links(self, same_domain_only=True):
        extracted_links = set()
        for a_tag in self.soup.find_all('a', href=True): 
            href_value = a_tag['href'].strip()

            if not href_value or \
               href_value.startswith('#') or \
               href_value.lower().startswith(('mailto:', 'javascript:', 'tel:', 'ftp:')):
                continue

            full_url = self._get_full_url(href_value)
            parsed_full_url = urlparse(full_url)

            if parsed_full_url.scheme not in ['http', 'https']:
                continue

            if same_domain_only:
                if parsed_full_url.netloc != self.parsed_base_url.netloc:
                    continue
            
            cleaned_url = urlunparse(parsed_full_url._replace(fragment=""))
            extracted_links.add(cleaned_url)
            
        return list(extracted_links)

    def _get_full_url(self, action):
        return urljoin(self.base_url, action) if action else self.base_url