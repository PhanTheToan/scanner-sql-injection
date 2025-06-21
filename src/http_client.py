import os
import requests
import logging
import time
import socket

logger = logging.getLogger(__name__)

def has_internet():
    try:
        socket.create_connection(("www.google.com", 80))
        return True
    except OSError:
        return False
    
class HTTPClient:
    def __init__(self, config=None):
        self.session = requests.Session()
        self.config = {
            'timeout': 15,
            'verify_ssl': True,
            'user_agent': 'SQLScanner/2.0',
            'proxies': {},
            'retries': 1
        }
        if config:
            # Chỉ cập nhật các giá trị proxy hợp lệ
            sanitized_config = {}
            for k, v in config.items():
                if k == 'proxies':
                    sanitized_proxies = {}
                    for pk, pv in v.items():
                        # Bỏ qua nếu giá trị là chuỗi biến môi trường chưa thay thế hoặc rỗng
                        if pv and not pv.startswith('${') and pv != '':
                            sanitized_proxies[pk] = pv
                    sanitized_config[k] = sanitized_proxies
                else:
                    sanitized_config[k] = v
            self.config.update(sanitized_config)
            
        self.session.headers.update({
            'User-Agent': self.config['user_agent'],
            'Accept-Encoding': 'gzip, deflate'
        })

    def send_advanced_request(self, url, method='GET', **kwargs):
        # Nếu là localhost, không dùng proxy
        if 'localhost' in url.lower() or '127.0.0.1' in url.lower():
            proxies = {}
        else:
            proxies = self.config['proxies'] if self.config['proxies'] else {}
        
        params = {
            'timeout': self.config['timeout'],
            'verify': self.config['verify_ssl'],
            'proxies': proxies
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
        print(self.config)