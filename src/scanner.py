import json
import re
import sys
import time
import argparse
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote, unquote, urlunparse
import yaml
import os
import logging
import threading
import concurrent.futures
from pathlib import Path
import copy
import requests # Import requests để bắt exception

try:
    from src.http_client import HTTPClient
    from src.models.vulnerability import Vulnerability
    from src.parser import AdvancedHTMLParser
    from src.utils.report_generator import ReportGenerator
except ImportError as e:
    print(f"Import Error: {e}. Please ensure the script is run as a module from the project root directory"
          " (e.g., python -m src.scanner ...) and all necessary modules (http_client, models, parser, utils) exist in the 'src' directory.")
    sys.exit(1)

logger = logging.getLogger(__name__) # Lấy logger với tên module (__main__ nếu chạy trực tiếp)



def load_config(file_path):
    """Tải và xử lý biến môi trường trong file config YAML."""
    try:
        config_path = Path(file_path)
        if not config_path.is_file():
             logger.error(f"Config file not found: {file_path}")
             return None
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        if config is None: # Xử lý trường hợp file YAML rỗng
             logger.error(f"Config file {file_path} is empty or invalid YAML.")
             return None
    except yaml.YAMLError as e:
         logger.error(f"Error parsing YAML config file {file_path}: {e}")
         return None
    except Exception as e:
         logger.error(f"Unexpected error loading config file {file_path}: {e}", exc_info=True)
         return None

    # --- Logic thay thế biến môi trường (cải tiến) ---
    def replace_env_vars(item):
        if isinstance(item, str):
            # Pattern tìm ${VAR} hoặc ${VAR:-default}
            pattern = r'\$\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(?::-)?([^}]*)?\s*\}'
            def replace_match(match):
                var_name, default_val = match.groups()
                env_value = os.getenv(var_name)
                if env_value is not None:
                    return env_value
                elif default_val is not None:
                    # Xử lý trường hợp default rỗng ${VAR:-}
                    return default_val
                else:
                    logger.warning(f"Environment variable '{var_name}' not found and no default value provided.")
                    # Trả về chuỗi rỗng hoặc giá trị gốc tùy theo yêu cầu
                    # return match.group(0) # Trả về gốc ${VAR}
                    return "" # Trả về rỗng nếu không tìm thấy
            try:
                # Thay thế nhiều lần để xử lý lồng nhau (ít khả năng nhưng có thể)
                new_item = item
                for _ in range(5): # Giới hạn số lần thay thế tránh vòng lặp vô hạn
                    replaced = re.sub(pattern, replace_match, new_item)
                    if replaced == new_item:
                        break
                    new_item = replaced
                return new_item
            except Exception as e:
                 logger.error(f"Error expanding variables in string '{item}': {e}")
                 return item # Trả về gốc nếu lỗi
        elif isinstance(item, dict):
            return {k: replace_env_vars(v) for k, v in item.items()}
        elif isinstance(item, list):
            return [replace_env_vars(elem) for elem in item]
        return item

    try:
        return replace_env_vars(config)
    except Exception as e:
        logger.error(f"Error replacing environment variables in config: {e}", exc_info=True)
        return config

class AdvancedSQLInjector:
    def __init__(self, config_file='config.yaml'):
        self.config = load_config(config_file)
        if self.config is None:
            logger.critical(f"FATAL: Failed to load configuration from {config_file}. Exiting.")
            sys.exit(1)

        # --- Khởi tạo các thành phần cốt lõi ---
        http_config = self.config.get('http', {})
        # Sửa lỗi truy cập config: dùng self.config trực tiếp
        self.scanner_config = self.config.get('scanner', {})
        payload_file_path = self.scanner_config.get('payload_file')

        if not http_config: logger.warning("HTTP configuration ('http') missing in config. Using defaults.")
        if not self.scanner_config: logger.critical("FATAL: Scanner configuration ('scanner') missing. Exiting."); sys.exit(1)
        if not payload_file_path: logger.critical("FATAL: Payload file path ('scanner.payload_file') missing. Exiting."); sys.exit(1)

        self.http_client = HTTPClient(http_config)
        self.parser = AdvancedHTMLParser("", "") # Khởi tạo parser rỗng ban đầu
        self.payloads = self.load_payloads(payload_file_path) # Dùng hàm load_payloads đã sửa
        self.vulnerabilities = []
        self.vuln_set = set()
        self.vulnerability_lock = threading.Lock() # Khóa để đồng bộ hóa truy cập vào danh sách lỗ hổng
        self.session = self.http_client.session
        self.current_scan_target = None

        # --- Đọc cấu hình quét mở rộng ---
        self.additional_targets = self.scanner_config.get('additional_targets', [])
        self.discovery_config = self.scanner_config.get('discovery', {})
        self.api_definitions = self.scanner_config.get('api_definitions', [])
        self.base_scan_url = None # Sẽ được gán trong main

        # --- Cấu hình Time-based ---
        self.time_threshold = self.scanner_config.get('time_delay_threshold', 4)

        # --- Login ---
        self._perform_login()

    def load_payloads(self, payload_file):
        """Tải và trả về danh sách payload duy nhất từ file."""
        all_payloads = []
        payload_file_abs = Path(payload_file)
        if not payload_file_abs.is_file():
             logger.debug(f"Payload file not found at: {payload_file}, trying relative to 'data/'...")
             payload_file_abs = Path('data') / payload_file
             if not payload_file_abs.is_file():
                  logger.error(f"Payload file not found: {payload_file} or {payload_file_abs}")
                  return []
             else:
                  logger.info(f"Using payload file: {payload_file_abs}")

        try:
            with open(payload_file_abs, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        all_payloads.append(line)
            unique_payloads = sorted(list(set(all_payloads)))
            logger.info(f"Loaded {len(unique_payloads)} unique payloads from {payload_file_abs}")
            if not unique_payloads:
                 logger.warning(f"Payload file {payload_file_abs} loaded successfully but contains no valid payloads.")
            return unique_payloads
        except Exception as e:
            logger.error(f"Error loading payloads from {payload_file_abs}: {e}", exc_info=True)
            return []

    def _perform_login(self):
        """Thực hiện đăng nhập nếu được bật trong config."""
        login_config = self.config.get('login', {})
        if not login_config.get('enabled', False):
            logger.info("Login is disabled in config.")
            return

        url = login_config.get('url')
        if not url: logger.error("Login enabled but login URL is missing."); return

        # Chuẩn hóa URL login dựa trên base_scan_url nếu cần
        if self.base_scan_url and not urlparse(url).scheme:
             url = urljoin(self.base_scan_url, url)

        method = login_config.get('method', 'POST').upper()
        data = login_config.get('data', {})
        success_criteria = login_config.get('success_criteria', {})
        timeout = self.config.get('http', {}).get('timeout', 15)

        logger.info(f"Attempting login to {url} with method {method}")
        try:
            response = self.http_client.send_advanced_request(
                url,
                method=method,
                data=data if method == 'POST' else None,
                params=data if method == 'GET' else None,
                timeout=timeout,
                allow_redirects=True
            )

            if not response:
                 logger.warning(f"Login request to {url} failed (no response).")
                 return

            logger.debug(f"Login response status: {response.status_code}")
            logger.debug(f"Login response URL (after redirects): {response.url}")
            logger.debug(f"Cookies after login attempt: {self.session.cookies.get_dict()}")

            # --- Kiểm tra các tiêu chí xác thực ---
            status_codes = success_criteria.get('status_codes', [200, 302])
            required_cookies = success_criteria.get('cookies', [])
            redirect_url_expected_rel = success_criteria.get('redirect_url') # Có thể là tương đối
            content_contains = success_criteria.get('content_contains')

            passed_status = response.status_code in status_codes
            logger.debug(f"Login Status Code Check: {'Passed' if passed_status else 'Failed'} (Got {response.status_code}, Expected {status_codes})")

            current_cookies = self.session.cookies.get_dict()
            passed_cookies = all(cookie in current_cookies for cookie in required_cookies) if required_cookies else True
            logger.debug(f"Login Cookies Check: {'Passed' if passed_cookies else 'Failed'} (Required: {required_cookies}, Got: {list(current_cookies.keys())})")

            passed_redirect = True
            if redirect_url_expected_rel:
                 expected_abs_url = urljoin(url, redirect_url_expected_rel) # Xử lý URL tương đối
                 passed_redirect = (response.url == expected_abs_url)
                 logger.debug(f"Login Redirect Check: {'Passed' if passed_redirect else 'Failed'} (Got {response.url}, Expected {expected_abs_url})")

            passed_content = True
            if content_contains:
                 try:
                     passed_content = (content_contains in response.text)
                     logger.debug(f"Login Content Check: {'Passed' if passed_content else 'Failed'} (Expected '{content_contains}')")
                 except Exception:
                      logger.warning("Could not check content in login response.")
                      passed_content = False # Coi là fail nếu không đọc được text

            # Coi là thành công nếu tất cả các tiêu chí ĐƯỢC ĐỊNH NGHĨA đều pass
            # (Tiêu chí không định nghĩa thì coi là pass)
            all_checks_passed = passed_status and passed_cookies and passed_redirect and passed_content
            if all_checks_passed:
                logger.info("Login successful based on defined criteria!")
            else:
                logger.warning("Login failed: Not all success criteria met.")

        except requests.exceptions.RequestException as e:
            logger.warning(f"Login request error: {str(e)}. Continuing without login.")
        except Exception as e:
            logger.warning(f"Login processing error: {str(e)}. Continuing without login.", exc_info=True)


    def _detect_db_type(self, response_text):
        """Phát hiện loại CSDL dựa trên mẫu lỗi trong phản hồi."""
        sql_error_patterns = getattr(AdvancedHTMLParser, 'SQL_ERROR_PATTERNS', {})
        for db_type, pattern in sql_error_patterns.items():
            # Thêm \b để tránh match lỗi của CSDL khác nằm trong text (ví dụ: "MySQL error in PostgreSQL system")
            # Cân nhắc: có thể làm miss match nếu lỗi không có khoảng trắng xung quanh
            # pattern_bounded = r'\b' + pattern + r'\b' # Thêm word boundary (có thể quá chặt)
            try:
                 if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL): # Thêm DOTALL để . khớp cả newline
                    return db_type
            except Exception: # Tránh lỗi regex nếu pattern phức tạp
                 continue
        return 'unknown'

    # --- Hàm Phân tích Phản hồi---
    def _analyze_inband_response(self, response, payload, input_field_name, start_time, injection_point_url):
        """Phân tích các dấu hiệu In-Band (Error, Boolean, Time) từ phản hồi HTTP."""
        if not response:
            logger.debug(f"Skipping in-band analysis for '{input_field_name}' at {injection_point_url} due to failed request.")
            return
        try:
            response_text = response.text
            status_code = response.status_code
        except Exception as e:
            logger.warning(f"Could not get text/status from response for '{input_field_name}' @ {injection_point_url}: {e}")
            response_text = ""
            status_code = None

        db_type = self._detect_db_type(response_text)
        logger.debug(f"Analyzing Response (Status: {status_code}) for Payload:'{payload}' | Field:'{input_field_name}' | URL:'{injection_point_url}'")

        # --- Error Based Check ---
        error_key = ('error', db_type, payload, input_field_name, injection_point_url)
        sql_error_patterns = getattr(AdvancedHTMLParser, 'SQL_ERROR_PATTERNS', {})
        is_error_based = any(re.search(pattern, response_text, re.IGNORECASE | re.DOTALL) for pattern in sql_error_patterns.values())
        if is_error_based and error_key not in self.vuln_set:
            vuln = Vulnerability(
                name=f"SQL Injection ({db_type.upper()}) - Error Based",
                description=f"Detected {db_type} SQL injection vulnerability via error message.",
                severity='high', payload=payload, input_field=input_field_name, url=injection_point_url
            )
            with self.vulnerability_lock: # Sử dụng lock
                if error_key not in self.vuln_set: # Kiểm tra lại trong critical section
                    self.vulnerabilities.append(vuln)
                    self.vuln_set.add(error_key)
                    logger.info(f"Found Error-Based vulnerability: {vuln}")
        # --- Boolean Based Check ---
        boolean_key = ('boolean', db_type, payload, input_field_name, injection_point_url)
        # Logic check Boolean cần cải thiện nhiều - hiện tại rất đơn giản
        is_boolean_based = ("Welcome" in response_text or "Login Successful" in response_text)
        if is_boolean_based and boolean_key not in self.vuln_set and not is_error_based: # Ưu tiên báo lỗi hơn boolean
            vuln = Vulnerability(
                name=f"SQL Injection ({db_type.upper()}) - Boolean Based",
                description=f"Detected potential {db_type} SQL injection via content change/keyword.",
                severity='high', payload=payload, input_field=input_field_name, url=injection_point_url
            )
            with self.vulnerability_lock: # Sử dụng lock
                if boolean_key not in self.vuln_set: # Kiểm tra lại
                    self.vulnerabilities.append(vuln)
                    self.vuln_set.add(boolean_key)
                    logger.info(f"Found Boolean-Based vulnerability: {vuln}")

        # --- Time Based Check ---
        time_key = ('time', db_type, payload, input_field_name, injection_point_url)
        elapsed_time = time.time() - start_time
        contains_delay_func = any(func in payload.upper() for func in ['SLEEP(', 'WAITFOR DELAY', 'PG_SLEEP(', 'DBMS_LOCK.SLEEP('])
        is_time_based = elapsed_time > self.time_threshold and contains_delay_func
        if is_time_based and time_key not in self.vuln_set and not is_error_based: # Ưu tiên báo lỗi hơn time
            vuln = Vulnerability(
                name=f"SQL Injection ({db_type.upper()}) - Time Based",
                description=f"Detected SQL injection vulnerability via time delay (>{self.time_threshold}s).",
                severity='critical', payload=payload, input_field=input_field_name, url=injection_point_url
            )
            with self.vulnerability_lock: # Sử dụng lock
                if time_key not in self.vuln_set: # Kiểm tra lại
                    self.vulnerabilities.append(vuln)
                    self.vuln_set.add(time_key)
                    logger.info(f"Found Time-Based vulnerability: {vuln}")
    def _scan_url_parameters(self, target_url):
        """Phân tích và thử inject vào các tham số query của URL."""
        logger.debug(f"Scanning URL parameters for: {target_url}")
        try:
            parsed_url = urlparse(target_url)
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        except Exception as e: logger.error(f"Failed to parse URL {target_url}: {e}"); return

        if not query_params: logger.debug("No query parameters found in URL."); return

        logger.info(f"Found {len(query_params)} parameters in URL: {list(query_params.keys())}")
        for param_name, original_values in query_params.items():
            original_value = original_values[0] if original_values else ""
            logger.debug(f"Testing URL parameter: '{param_name}' (Original: '{original_value}')")
            for payload in self.payloads:
                injected_params = query_params.copy()
                injected_params[param_name] = [payload]
                params_for_encode = {}
                for k, v_list in injected_params.items(): params_for_encode[k] = v_list # Giữ list cho doseq
                try:
                    injected_query_string = urlencode(params_for_encode, doseq=True, quote_via=quote)
                    # Xây dựng URL cẩn thận hơn, giữ lại fragment nếu có
                    injected_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, injected_query_string, parsed_url.fragment))
                except Exception as url_e: logger.error(f"Error building injected URL for param '{param_name}': {url_e}"); continue

                start_time = time.time()
                response = self.http_client.send_advanced_request(injected_url, method='GET')
                if response is not None:
                    # Gọi hàm phân tích ĐÚNG
                    self._analyze_inband_response(response, payload, param_name, start_time, injected_url)

    def _scan_html_forms(self, forms, base_url):
        """Quét các form HTML tìm thấy trên một trang."""
        logger.debug(f"Scanning {len(forms)} HTML forms found at {base_url}")
        for form in forms:
            raw_action = form.get('action')
            form_action_url = urljoin(base_url, raw_action) if raw_action else base_url # Xử lý action tương đối/tuyệt đối
            form_method = form.get('method', 'GET').upper()
            form_inputs = form.get('inputs', [])
            input_names = [inp.get('name') for inp in form_inputs if inp.get('name')]

            logger.debug(f"Scanning Form -> Action: {form_action_url}, Method: {form_method}, Inputs: {input_names}")
            for input_field in form_inputs:
                input_field_name = input_field.get('name')
                if not input_field_name: continue
                original_value = input_field.get('value', '')
                logger.debug(f"Testing form input: '{input_field_name}' (Original: '{original_value}')")
                for payload in self.payloads:
                    data_to_send = {}
                    for i in form_inputs:
                        i_name = i.get('name')
                        if i_name: data_to_send[i_name] = payload if i_name == input_field_name else i.get('value', '')

                    start_time = time.time()
                    response = None
                    request_args = {'url': form_action_url, 'timeout': self.config.get('http',{}).get('timeout', 15)}
                    if form_method == 'POST':
                        request_args['method'] = 'POST'; request_args['data'] = data_to_send
                    else:
                        request_args['method'] = 'GET'; request_args['params'] = data_to_send
                    try:
                        response = self.http_client.send_advanced_request(**request_args)
                    except Exception as e: logger.error(f"Error sending form request for field '{input_field_name}': {e}")
                    if response is not None:
                        # Gọi hàm phân tích ĐÚNG
                        self._analyze_inband_response(response, payload, input_field_name, start_time, form_action_url)

    def _scan_api_endpoint(self, target_url, api_def):
        """Quét một API endpoint dựa vào định nghĩa từ config."""
        method = api_def.get('method', 'GET').upper()
        params_in = api_def.get('params_in', 'query')
        params_to_test = api_def.get('params_to_test', [])
        json_template = api_def.get('json_template', None)

        if not params_to_test: logger.warning(f"No 'params_to_test' for API: {target_url}"); return
        logger.info(f"Scanning API endpoint: {method} {target_url} (Params in: {params_in})")

        base_json_body = {}
        if params_in == 'body_json':
            if isinstance(json_template, (dict, list)): base_json_body = json_template
            elif isinstance(json_template, str):
                try: base_json_body = json.loads(json_template)
                except json.JSONDecodeError: logger.error(f"Invalid JSON template for API {target_url}"); return
            else: logger.warning(f"No valid 'json_template' for API {target_url}. Using empty JSON.")

        for param_name in params_to_test:
            logger.debug(f"Testing API parameter: '{param_name}' in {params_in}")
            for payload in self.payloads:
                request_args = {'method': method, 'url': target_url, 'timeout': self.config.get('http',{}).get('timeout', 15)}
                headers = {}
                injection_url_or_target = target_url # URL để báo cáo

                try:
                    if params_in == 'query':
                        parsed_target = urlparse(target_url)
                        original_query_params = parse_qs(parsed_target.query, keep_blank_values=True)
                        params_for_encode = {}
                        for k, v_list in original_query_params.items(): params_for_encode[k] = v_list # Giữ list cho doseq
                        # Xử lý param lồng nhau (ít phổ biến trong query)
                        if '.' in param_name: logger.warning(f"Nested param '{param_name}' in query string not fully supported yet."); continue
                        params_for_encode[param_name] = [payload] # Inject (luôn là list)
                        injected_query = urlencode(params_for_encode, doseq=True, quote_via=quote)
                        injection_url_or_target = urlunparse((parsed_target.scheme, parsed_target.netloc, parsed_target.path, parsed_target.params, injected_query, parsed_target.fragment))
                        request_args['url'] = injection_url_or_target

                    elif params_in == 'body_form':
                        data_to_send = {param_name: payload}
                        request_args['data'] = data_to_send

                    elif params_in == 'body_json':
                        headers['Content-Type'] = 'application/json'
                        injected_body = copy.deepcopy(base_json_body)
                        keys = param_name.split('.')
                        target_obj = injected_body
                        try:
                            for i, key in enumerate(keys):
                                if i == len(keys) - 1:
                                    # Kiểm tra dict hoặc list (để hỗ trợ index dạng số)
                                    if isinstance(target_obj, dict): target_obj[key] = payload
                                    elif isinstance(target_obj, list):
                                        try: target_obj[int(key)] = payload # Thử index list
                                        except (ValueError, IndexError): raise TypeError(f"Invalid list index '{key}'")
                                    else: raise TypeError(f"Cannot set key/index '{key}' on type {type(target_obj)}")
                                else:
                                    if isinstance(target_obj, dict) and key in target_obj: target_obj = target_obj[key]
                                    elif isinstance(target_obj, list):
                                        try: target_obj = target_obj[int(key)] # Thử index list
                                        except (ValueError, IndexError): raise KeyError(f"Invalid list index '{key}'")
                                    else: raise KeyError(f"Intermediate key/index '{key}' not found or invalid type")
                        except Exception as json_e: logger.error(f"Error injecting into JSON path '{param_name}': {json_e}"); continue
                        request_args['data'] = json.dumps(injected_body)

                    else: logger.warning(f"Unsupported 'params_in': {params_in}"); continue

                    if headers: request_args['headers'] = headers

                    start_time = time.time()
                    response = self.http_client.send_advanced_request(**request_args)

                    if response is not None:
                        # Gọi hàm phân tích ĐÚNG
                        self._analyze_inband_response(response, payload, param_name, start_time, injection_url_or_target)

                except Exception as req_e:
                    logger.error(f"Error during API request for param '{param_name}': {req_e}", exc_info=True)

    def discover_targets(self, base_url):
        """Khám phá các endpoint/file tiềm năng dựa trên wordlist."""
        discovered = set()
        discovery_conf = self.discovery_config
        if not discovery_conf.get('enabled', False): logger.info("Discovery is disabled."); return []

        wordlist_path_str = discovery_conf.get('wordlist_file')
        if not wordlist_path_str: logger.error("Discovery enabled but 'wordlist_file' not specified."); return []

        wordlist_path = Path(wordlist_path_str)
        if not wordlist_path.is_file(): wordlist_path = Path('data') / wordlist_path_str
        if not wordlist_path.is_file(): logger.error(f"Discovery wordlist not found: {wordlist_path_str} or {wordlist_path}"); return []

        extensions = discovery_conf.get('extensions_to_append', [""])
        interesting_codes = discovery_conf.get('interesting_status_codes', [200, 403])
        parsed_base = urlparse(base_url)
        # Xác định thư mục gốc chính xác hơn
        base_path = parsed_base.path
        if not base_path.endswith('/'): base_path = os.path.dirname(base_path) + '/'
        clean_base_url = urljoin(base_url, base_path) # URL thư mục gốc

        logger.info(f"Starting discovery from base: {clean_base_url} using wordlist: {wordlist_path}")
        paths_to_check = []
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                 paths_to_check = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e: logger.error(f"Error reading wordlist file {wordlist_path}: {e}"); return []

        total_checks = len(paths_to_check) * len(extensions)
        logger.info(f"Generated {total_checks} potential targets for discovery.")
        count = 0

        # --- Tạm thời chạy tuần tự ---
        for path_word in paths_to_check:
            for ext in extensions:
                relative_path = path_word.lstrip('/') + ext # Bỏ / đầu nếu có
                target_url_to_check = urljoin(clean_base_url, relative_path)
                count += 1
                if count % 200 == 0: logger.info(f"Discovery progress: {count}/{total_checks}")

                try:
                    status_code = None
                    response = self.http_client.send_advanced_request(
                        target_url_to_check, method='HEAD',
                        allow_redirects=discovery_conf.get('follow_redirects', False), timeout=5)
                    status_code = response.status_code if response else None

                    if response is None or status_code == 405:
                        # logger.debug(f"HEAD failed/disallowed for {target_url_to_check}, trying GET...")
                        response = self.http_client.send_advanced_request(
                            target_url_to_check, method='GET',
                            allow_redirects=discovery_conf.get('follow_redirects', False), timeout=5)
                        status_code = response.status_code if response else None

                    if status_code in interesting_codes:
                        final_url = response.url if response and discovery_conf.get('follow_redirects', False) else target_url_to_check
                        # Tránh thêm lại URL gốc hoặc các URL rất giống URL gốc
                        if urlparse(final_url).path.rstrip('/') != parsed_base.path.rstrip('/'):
                             logger.info(f"Discovered: {final_url} (Status: {status_code})")
                             discovered.add(final_url)
                except Exception: pass # Bỏ qua lỗi trong discovery

        logger.info(f"Discovery finished. Found {len(discovered)} potential targets.")
        return sorted(list(discovered))

    def scan_target(self, target_url):
        """Quét một target URL cụ thể (URL params, Forms, API definitions)."""
        logger.info(f"--- Scanning Target: {target_url} ---")
        self.current_scan_target = target_url # Lưu URL đang quét

        # --- 1. Kiểm tra và Quét API nếu khớp định nghĩa ---
        matched_api_def = None
        api_scanned = False
        try:
            parsed_target = urlparse(target_url)
            target_path = parsed_target.path or '/'
            for api_def in self.api_definitions:
                api_path = api_def.get('path')
                if not api_path: continue
                # So khớp path chuẩn hóa
                normalized_target_path = target_path.rstrip('/') if target_path != '/' else '/'
                abs_api_url = urljoin(self.base_scan_url, api_path)
                normalized_api_path = urlparse(abs_api_url).path.rstrip('/') if urlparse(abs_api_url).path != '/' else '/'
                if normalized_target_path == normalized_api_path:
                    matched_api_def = api_def
                    logger.info(f"Target URL matches API definition: '{api_path}'. Running API scan.")
                    self._scan_api_endpoint(target_url, matched_api_def)
                    api_scanned = True
                    break # Chỉ quét theo định nghĩa API đầu tiên khớp
        except Exception as api_scan_e:
            logger.error(f"Error during API definition matching/scan for {target_url}: {api_scan_e}", exc_info=True)

        # --- 2. Quét tham số URL ---
        # Luôn quét tham số URL trừ khi nó là API đã được quét? Có thể cấu hình
        # if not api_scanned or self.scanner_config.get('scan_url_params_for_apis', False):
        try:
            self._scan_url_parameters(target_url)
        except Exception as url_scan_e:
            logger.error(f"Error scanning URL parameters for {target_url}: {url_scan_e}", exc_info=True)

        # --- 3. Quét Form nếu là HTML ---
        # Chỉ quét form nếu target không phải là API đã được quét (tránh GET/POST thừa)
        if not api_scanned:
            try:
                content_type = ""
                response_for_forms = None
                try:
                    head_response = self.http_client.send_advanced_request(target_url, method='HEAD', timeout=3)
                    if head_response: content_type = head_response.headers.get('Content-Type', '').lower()
                except Exception: pass

                fetch_body_for_forms = False
                if 'text/html' in content_type: fetch_body_for_forms = True
                elif not content_type: fetch_body_for_forms = True # Thử GET nếu không biết type

                if fetch_body_for_forms:
                    logger.debug(f"Fetching content for potential form scan: {target_url}")
                    response_for_forms = self.http_client.send_advanced_request(target_url, method='GET')
                    if response_for_forms and 'text/html' in response_for_forms.headers.get('Content-Type', '').lower():
                        # Cập nhật base_url cho parser dựa trên URL hiện tại
                        self.parser = AdvancedHTMLParser(response_for_forms.text, target_url)
                        forms = self.parser.extract_forms()
                        if forms:
                            logger.info(f"Found {len(forms)} forms on {target_url}. Scanning forms.")
                            self._scan_html_forms(forms, target_url) # Truyền target_url làm base
                        else: logger.debug(f"No forms found on HTML page: {target_url}")
                    # else: logger.debug(f"Target {target_url} content not HTML or fetch failed. Skipping form scan.")
            except Exception as form_scan_e:
                logger.error(f"Error during form scanning phase for {target_url}: {form_scan_e}", exc_info=True)
        else:
            logger.debug(f"Skipping form scan for {target_url} as it was scanned as a defined API.")

    def generate_report(self):
        """Trả về danh sách các lỗ hổng tìm thấy, đã sắp xếp."""
        self.vulnerabilities.sort(key=lambda v: (v.url, v.input_field or '', v.severity))
        return self.vulnerabilities
def main():
    # --- Argparse Setup (giữ nguyên) ---
    parser = argparse.ArgumentParser(
        description='Advanced SQL Injection Scanner with Discovery & API Support',
        epilog='Example: python -m src.scanner --url http://localhost:8000/ --config config.yaml --report report.html --logfile scan.log'
    )
    parser.add_argument('--url', required=True, help='Base Target URL for scanning and discovery')
    parser.add_argument('--config', default='config.yaml', help='Path to config.yaml')
    parser.add_argument('--report', default='report.html', help='Output report file path')
    parser.add_argument('--loglevel', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set logging level for console and file')
    parser.add_argument('--logfile', help='Optional: Path to save the log output file.')
    args = parser.parse_args()

    log_level = getattr(logging, args.loglevel.upper(), logging.INFO)
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    log_datefmt = '%Y-%m-%d %H:%M:%S'
    formatter = logging.Formatter(log_format, datefmt=log_datefmt)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)

    if args.logfile:
        try:
            log_dir = os.path.dirname(args.logfile)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
                logger.info(f"Created log directory: {log_dir}") 

            file_handler = logging.FileHandler(args.logfile, mode='a', encoding='utf-8')
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            logging.info(f"Logging enabled to file: {args.logfile}")
        except Exception as log_e:
            logging.error(f"Failed to configure file logging to {args.logfile}: {log_e}") # Log lỗi này ra console

    if log_level > logging.DEBUG:
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("chardet").setLevel(logging.WARNING)

    logger.info("Initializing SQL Injection Scanner...")
    scanner = None
    try:
        scanner = AdvancedSQLInjector(config_file=args.config)
        parsed_original_url = urlparse(args.url)
        if not parsed_original_url.path or parsed_original_url.path.endswith('/'):
             scanner.base_scan_url = args.url.rstrip('/') + '/'
        else:
             scanner.base_scan_url = urljoin(args.url, os.path.dirname(parsed_original_url.path).rstrip('/')+'/')
        logger.info(f"Scanner initialized. Base scan URL set to: {scanner.base_scan_url}")
    except Exception as init_e:
        logger.critical(f"Failed to initialize scanner: {init_e}", exc_info=True); sys.exit(1)

    # --- Chuẩn bị danh sách Target (giữ nguyên) ---
    targets_to_scan = set()
    targets_to_scan.add(scanner.base_scan_url)
    if args.url != scanner.base_scan_url: targets_to_scan.add(args.url); logger.debug(f"Added original file target: {args.url}")
    for target in scanner.additional_targets:
        abs_target = urljoin(scanner.base_scan_url, target); targets_to_scan.add(abs_target); logger.debug(f"Added target from config [additional]: {abs_target}")
    for api_def in scanner.api_definitions:
        path = api_def.get('path')
        if path: abs_path = urljoin(scanner.base_scan_url, path); targets_to_scan.add(abs_path); logger.debug(f"Added target from config [api]: {abs_path}")

    # --- Chạy Discovery (giữ nguyên) ---
    if scanner.discovery_config.get('enabled', False):
        discovered_targets = scanner.discover_targets(scanner.base_scan_url)
        for target in discovered_targets: targets_to_scan.add(target)

    # --- Chạy quét trên từng Target (giữ nguyên) ---
    final_target_list = sorted(list(targets_to_scan))
    logger.info(f"--- Starting scan for {len(final_target_list)} unique targets ---")
    scan_successful = True
    max_workers = scanner.scanner_config.get('max_threads', min(10, os.cpu_count() + 4 if os.cpu_count() else 5))
    logger.info(f"Using up to {max_workers} threads for scanning.")
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Tạo một future cho mỗi target
            future_to_url = {executor.submit(scanner.scan_target, target_url): target_url for target_url in final_target_list}
            
            processed_count = 0
            total_targets = len(final_target_list)

            for future in concurrent.futures.as_completed(future_to_url):
                target_url_completed = future_to_url[future]
                processed_count += 1
                try:
                    future.result()  # Lấy kết quả hoặc exception nếu có
                    logger.info(f"Finished scanning target {processed_count}/{total_targets}: {target_url_completed}")
                except Exception as exc:
                    logger.error(f"Target {target_url_completed} generated an exception: {exc}", exc_info=True)
                    scan_successful = False # Đánh dấu thất bại nếu có lỗi nghiêm trọng trong một luồng
                except KeyboardInterrupt: # Xử lý ngắt từ bàn phím trong luồng
                    logger.warning(f"Scan for {target_url_completed} interrupted by user.")
                    # Quyết định xem có nên hủy các future khác không
                    # executor.shutdown(wait=False, cancel_futures=True) # Cần Python 3.9+
                    # Hoặc đơn giản là để các luồng khác hoàn thành
                    scan_successful = False
                    break # Thoát khỏi vòng lặp chờ future
    except KeyboardInterrupt: logger.warning("Scan interrupted by user."); scan_successful = False
    except Exception as main_e: logger.critical(f"Uncaught exception during scan loop: {main_e}", exc_info=True); scan_successful = False
    finally: pass # OOB check nếu có

    # --- Generate Report (giữ nguyên) ---
    if scanner:
        logger.info("--- Generating Report ---")
        try: report_generator = ReportGenerator() # Giả sử lớp này tồn tại
        except NameError: logger.error("ReportGenerator class not defined."); report_generator = None

        if report_generator:
            try:
                vulnerabilities_found = scanner.generate_report()
                report_file_path = report_generator.generate(vulnerabilities_found, args.report)
                print(f"Report saved to {report_file_path}")
                logger.info(f"Scan finished. Found {len(vulnerabilities_found)} vulnerabilities. Report saved to {report_file_path}")
            except FileNotFoundError as report_fnf_e: logger.error(f"Failed to generate report: Template file error - {report_fnf_e}. Check 'templates/report.html'.")
            except Exception as report_e: logger.error(f"Failed to generate report: {report_e}", exc_info=True)
    else: logger.error("Scanner object not available, cannot generate report.")

    logger.info("Scanner execution finished.") # Log cuối cùng
    if not scan_successful: sys.exit(1)

if __name__ == "__main__":
    main()