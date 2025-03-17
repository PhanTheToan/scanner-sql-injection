from bs4 import BeautifulSoup
# from urllib.parse import urlparse
from urllib.parse import urljoin
class HTMLParser:
    SQL_ERRORS = [
        "quoted string not properly terminated",
        "unclosed quotation mark",
        "sql syntax error"
    ]

    def __init__(self, html_content, base_url):
        self.soup = BeautifulSoup(html_content, 'html.parser')
        self.base_url = base_url

    def extract_forms(self):
        forms = []
        for form in self.soup.find_all('form'):
            form_details = {
                'action': self.get_form_action(form),
                'method': form.get('method', 'get').upper(),
                'inputs': self.get_form_inputs(form),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded')
            }
            forms.append(form_details)
        return forms

    def get_form_action(self, form):
        action = form.get('action')
        if not action:
            return self.base_url
        return urljoin(self.base_url, action)

    def get_form_inputs(self, form):
        inputs = []
        for tag in form.find_all(['input', 'textarea', 'select']):
            input_details = {
                'type': tag.get('type', 'text'),
                'name': tag.get('name'),
                'value': tag.get('value', '')
            }
            if tag.name == 'select':
                input_details['options'] = [
                    option.get('value') 
                    for option in tag.find_all('option')
                ]
            inputs.append(input_details)
        return inputs
