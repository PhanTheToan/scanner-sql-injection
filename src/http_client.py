import logging
import time

import requests

logger = logging.getLogger(__name__)  # Thêm dòng này

class HTTPClient:
    def __init__(self, config=None):
        self.session = requests.Session()
        self.config = {
            'timeout': 15,
            'verify_ssl': True,
            'user_agent': 'SQLScanner/2.0',
            'proxies': {},
            'retries': 3
        }
        if config:
            self.config.update(config)
            
        self.session.headers.update({
            'User-Agent': self.config['user_agent'],
            'Accept-Encoding': 'gzip, deflate'
        })

    def send_advanced_request(self, url, method='GET', **kwargs):
        params = {
            'timeout': self.config['timeout'],
            'verify': self.config['verify_ssl'],
            'proxies': self.config['proxies']
        }
        params.update(kwargs)
        
        for attempt in range(self.config['retries']):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    **params
                )
                response.raise_for_status()
                return response
            except requests.exceptions.RequestException as e:
                logger.error(f"Attempt {attempt+1} failed: {str(e)}")
                if attempt == self.config['retries'] - 1:
                    return None
                time.sleep(1) 
