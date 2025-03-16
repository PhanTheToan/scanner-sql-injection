import requests
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)

class HTTPClient:
    def __init__(self, timeout=15, verify_ssl=False):
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.headers = {
            'User-Agent': 'SQLScanner/1.0',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }

    def get_full_url(self, base_url, path):
        return urljoin(base_url, path)

    def send_request(self, url, method='GET', params=None, data=None):
     try:
        response = self.session.request(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=self.headers,
            timeout=self.timeout,
            verify=self.verify_ssl
        )
        response.raise_for_status()
        return response
     except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP Error: {str(e)}")
        if e.response.status_code == 404:
            print(f"[!] URL {url} không tồn tại.")
        return None
     except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {str(e)}")
        return None
