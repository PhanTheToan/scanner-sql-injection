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
import collections
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
        self.api_definitions = self._load_api_definitions()
        self.additional_targets = self._load_additional_targets()
        self.discovery_config = self.scanner_config.get('discovery', {})
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
    def _load_api_definitions(self):
        """Tải định nghĩa API từ file được chỉ định trong config hoặc từ inline config."""
        api_defs_file_path_str = self.scanner_config.get('api_definitions_file')
        inline_api_defs = self.scanner_config.get('api_definitions', [])
        
        loaded_definitions = []

        if api_defs_file_path_str:
            api_defs_file = Path(api_defs_file_path_str)
            if not api_defs_file.is_file() and not api_defs_file.is_absolute():
                 logger.debug(f"API definitions file '{api_defs_file_path_str}' not found directly, trying relative to 'data/' directory...")
                 api_defs_file = Path('data') / api_defs_file_path_str
            
            if api_defs_file.is_file():
                try:
                    with open(api_defs_file, 'r', encoding='utf-8') as f:
                        defs_from_file = yaml.safe_load(f)
                        if isinstance(defs_from_file, list):
                            loaded_definitions.extend(defs_from_file)
                            logger.info(f"Successfully loaded {len(defs_from_file)} API definitions from {api_defs_file.resolve()}")
                        else:
                            logger.warning(f"API definitions file {api_defs_file.resolve()} does not contain a list of definitions. Skipping file.")
                except yaml.YAMLError as e:
                    logger.error(f"Error parsing YAML from API definitions file {api_defs_file.resolve()}: {e}")
                except Exception as e:
                    logger.error(f"Error reading API definitions file {api_defs_file.resolve()}: {e}", exc_info=True)
            else:
                logger.warning(f"Specified API definitions file was not found: '{api_defs_file_path_str}' (also checked as '{api_defs_file.resolve()}').")
        
        if inline_api_defs:
            logger.info(f"Loading {len(inline_api_defs)} API definitions from inline 'scanner.api_definitions' in config.")
            loaded_definitions.extend(inline_api_defs) 

        if not loaded_definitions:
            logger.info("No API definitions were loaded (neither from file nor inline). API scanning might be limited.")
        else:
            pass
            
        return loaded_definitions
    def _load_additional_targets(self):
        """Tải các mục tiêu bổ sung từ file hoặc từ inline config."""
        additional_targets_file_path_str = self.scanner_config.get('additional_targets_file')
        inline_targets_config = self.scanner_config.get('additional_targets', [])
        
        loaded_targets = []

        if additional_targets_file_path_str:
            file_path = Path(additional_targets_file_path_str)
            if not file_path.is_file() and not file_path.is_absolute(): # Kiểm tra tương đối với 'data/'
                file_path = Path('data') / additional_targets_file_path_str
            
            if file_path.is_file():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        targets_from_file = yaml.safe_load(f)
                        if isinstance(targets_from_file, list):
                            for item in targets_from_file:
                                if isinstance(item, dict) and 'url' in item:
                                    loaded_targets.append(item)
                                elif isinstance(item, str): 
                                    loaded_targets.append({'url': item, '_is_simple_string': True})
                                else:
                                    logger.warning(f"Định dạng item không hợp lệ trong {file_path.resolve()}: {item}. Bỏ qua.")
                            logger.info(f"Đã tải {len(loaded_targets)} mục tiêu bổ sung từ {file_path.resolve()}")
                        else:
                            logger.warning(f"File mục tiêu bổ sung {file_path.resolve()} không chứa danh sách. Bỏ qua.")
                except yaml.YAMLError as e:
                    logger.error(f"Lỗi parsing YAML từ file mục tiêu bổ sung {file_path.resolve()}: {e}")
                except Exception as e:
                    logger.error(f"Lỗi đọc file mục tiêu bổ sung {file_path.resolve()}: {e}", exc_info=True)
            else:
                logger.warning(f"Không tìm thấy file mục tiêu bổ sung: '{additional_targets_file_path_str}' (đã kiểm tra cả '{file_path.resolve()}').")
        
        if inline_targets_config:
            logger.info(f"Đang tải {len(inline_targets_config)} mục tiêu bổ sung từ inline 'scanner.additional_targets'.")
            for item in inline_targets_config:
                if isinstance(item, str): 
                    loaded_targets.append({'url': item, '_is_simple_string': True})
                elif isinstance(item, dict) and 'url' in item: 
                    loaded_targets.append(item)
                else:
                    logger.warning(f"Item '{item}' không được hỗ trợ trong 'additional_targets' inline. Bỏ qua.")
        
        if not loaded_targets:
            logger.info("Không có mục tiêu bổ sung nào được tải (từ file hoặc inline).")
        return loaded_targets
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
                        self._analyze_inband_response(response, payload, input_field_name, start_time, form_action_url)

    def _scan_api_endpoint(self, target_url, api_def):
        """Quét một API endpoint dựa vào định nghĩa từ config."""
        method = api_def.get('method', 'GET').upper()
        
        params_in = api_def.get('params_in', 'query')  
        params_to_test = api_def.get('params_to_test', [])
        body_template = api_def.get('body_template', api_def.get('json_template'))
        custom_headers_from_def = api_def.get('headers', {}) 

        if not params_to_test:
            logger.warning(f"No 'params_to_test' defined for API: {method} {target_url}. Skipping.")
            return
        logger.info(f"Scanning API endpoint: {method} {target_url} (Params in: {params_in}, Testing: {params_to_test})")

        # Chuẩn bị base_body_data cho body_json (đã parse) hoặc body_xml (chuỗi)
        base_body_data = None
        if params_in == 'body_json':
            if isinstance(body_template, (dict, list)):
                base_body_data = body_template
            elif isinstance(body_template, str) and body_template.strip():
                try:
                    base_body_data = json.loads(body_template)
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON string in 'body_template' for API {target_url} with params_in 'body_json'. Skipping this API definition."); return
            else: 
                logger.warning(f"No valid 'body_template' for API {target_url} with 'body_json'. Will attempt to inject into an empty JSON object if 'params_to_test' are simple keys.")
                base_body_data = {} 
        elif params_in == 'body_xml':
            if isinstance(body_template, str):
                base_body_data = body_template
            else:
                logger.error(f"'body_template' (string) is required and must be a string for 'body_xml' for API {target_url}. Skipping this API definition."); return

        for param_name_to_inject in params_to_test:
            logger.debug(f"Testing API parameter: '{param_name_to_inject}' in {params_in} for {method} {target_url}")
            for payload in self.payloads:
                current_request_headers = self.http_client.session.headers.copy()
                current_request_headers.update(custom_headers_from_def) # Header từ api_def sẽ ghi đè header session nếu trùng key

                request_args = {
                    'method': method,
                    'url': target_url, 
                    'timeout': self.config.get('http', {}).get('timeout', 15),
                    'headers': current_request_headers
                }
                reporting_url_or_target_id = target_url 

                try:
                    if params_in == 'query':
                        parsed_target = urlparse(target_url)
                        original_query_params = parse_qs(parsed_target.query, keep_blank_values=True)
                        params_for_encode = {k: v_list[:] for k, v_list in original_query_params.items()} # Copy list
                        
                        if '.' in param_name_to_inject:
                            logger.warning(f"Nested param format '{param_name_to_inject}' in query string (e.g., field.subfield) is not standard. Treating as a literal key name. Ensure your server handles this, or use 'field[subfield]' format if applicable.")
                        
                        params_for_encode[param_name_to_inject] = [payload] # Inject payload
                        
                        injected_query_string = urlencode(params_for_encode, doseq=True, quote_via=quote)
                        reporting_url_or_target_id = urlunparse((parsed_target.scheme, parsed_target.netloc, parsed_target.path, parsed_target.params, injected_query_string, parsed_target.fragment))
                        request_args['url'] = reporting_url_or_target_id

                    elif params_in == 'body_form':
                        form_data_to_send = {}
                        if isinstance(body_template, dict):
                            form_data_to_send.update(body_template)
                        form_data_to_send[param_name_to_inject] = payload 
                        request_args['data'] = form_data_to_send
                        if 'Content-Type' not in current_request_headers: 
                            current_request_headers['Content-Type'] = 'application/x-www-form-urlencoded'

                    elif params_in == 'body_json':
                        if base_body_data is None:
                            logger.error(f"Base JSON data is not available for injection (param '{param_name_to_inject}'). Skipping payload '{payload}'."); continue
                        
                        if 'Content-Type' not in current_request_headers: 
                             current_request_headers['Content-Type'] = 'application/json; charset=utf-8'
                        
                        
                        injected_json_body = copy.deepcopy(base_body_data)
                        keys_path = param_name_to_inject.split('.')
                        current_level_obj = injected_json_body
                        
                        try:
                            for i, key_part in enumerate(keys_path):
                                if i == len(keys_path) - 1: 
                                    if isinstance(current_level_obj, dict):
                                        current_level_obj[key_part] = payload
                                    elif isinstance(current_level_obj, list):
                                        try: current_level_obj[int(key_part)] = payload 
                                        except (ValueError, IndexError) as list_e:
                                            raise TypeError(f"Invalid list index '{key_part}' for JSON path '{param_name_to_inject}': {list_e}")
                                    else:
                                        raise TypeError(f"Cannot set key/index '{key_part}' on non-dict/list type ({type(current_level_obj)}) at JSON path '{param_name_to_inject}'")
                                else: 
                                    if isinstance(current_level_obj, dict):
                                        if key_part not in current_level_obj: 
                                            current_level_obj[key_part] = {}
                                        current_level_obj = current_level_obj[key_part]
                                    elif isinstance(current_level_obj, list):
                                        try: current_level_obj = current_level_obj[int(key_part)]
                                        except (ValueError, IndexError) as list_e:
                                            raise KeyError(f"Invalid list index '{key_part}' in JSON path '{param_name_to_inject}': {list_e}")
                                    else:
                                        raise KeyError(f"Intermediate key/index '{key_part}' in JSON path '{param_name_to_inject}' is not dict/list or not found.")
                        except Exception as json_inject_e:
                            logger.error(f"Error injecting payload into JSON path '{param_name_to_inject}': {json_inject_e}", exc_info=True); continue
                        
                        request_args['data'] = json.dumps(injected_json_body)

                    elif params_in == 'body_xml': 
                        if not isinstance(base_body_data, str): 
                             logger.error(f"Base XML template (string) is not available for injection (param '{param_name_to_inject}'). Skipping."); continue
                        
                        if 'Content-Type' not in current_request_headers: 
                            current_request_headers['Content-Type'] = 'application/xml; charset=utf-8'
                        
                        if param_name_to_inject not in base_body_data:
                            logger.warning(f"Placeholder '{param_name_to_inject}' not found in XML template for API {target_url}. Payload '{payload}' might not be injected correctly. Sending template as is with other potential injections if any.")   
                            injected_xml_string = base_body_data 
                        else:
                            injected_xml_string = base_body_data.replace(param_name_to_inject, payload)
                        
                        request_args['data'] = injected_xml_string.encode('utf-8') 

                    else:
                        logger.warning(f"Unsupported 'params_in' type: '{params_in}' for API {target_url}. Skipping parameter '{param_name_to_inject}'."); continue
                    
                    request_args['headers'] = current_request_headers 

                    start_time = time.time()
                    response = self.http_client.send_advanced_request(**request_args)

                    if response is not None:
                        # Sử dụng reporting_url_or_target_id vì nó chứa URL đầy đủ với payload cho GET
                        self._analyze_inband_response(response, payload, param_name_to_inject, start_time, reporting_url_or_target_id)

                except Exception as req_build_send_e:
                    logger.error(f"Error during API request construction or sending for param '{param_name_to_inject}' in '{params_in}' on {method} {target_url}: {req_build_send_e}", exc_info=True)

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

    def scan_target(self, target_input):
        """
        Quét một mục tiêu đầu vào.
        target_input có thể là một URL string hoặc một dictionary (mục tiêu có cấu trúc).
        """
        if isinstance(target_input, str):
            # Xử lý URL string đơn giản (ví dụ: từ discovery, args.url)
            resolved_url = urljoin(self.base_scan_url, target_input)
            self._scan_simple_url_target(resolved_url)
        elif isinstance(target_input, dict) and 'url' in target_input:
            # Xử lý mục tiêu có cấu trúc từ additional_targets.yaml
            if target_input.get('_is_simple_string'): # Cờ đánh dấu URL string từ file/inline
                resolved_url = urljoin(self.base_scan_url, target_input['url'])
                self._scan_simple_url_target(resolved_url)
            else:
                self._scan_structured_target_object(target_input)
        else:
            logger.warning(f"Loại mục tiêu đầu vào không hợp lệ: {type(target_input)}. Bỏ qua.")

    def _scan_simple_url_target(self, target_url):
        """Quét một URL string đơn giản."""
        logger.info(f"--- 🎯 Đang quét URL đơn giản: {target_url} ---")
        self.current_scan_target = target_url

        # 1. Kiểm tra và Quét API nếu URL khớp với một định nghĩa API
        api_definition_matched_and_scanned = False
        try:
            parsed_target_url = urlparse(target_url)
            target_path = parsed_target_url.path or '/'
            normalized_target_path = target_path.rstrip('/') if target_path != '/' else '/'

            for api_def in self.api_definitions:
                api_def_path = api_def.get('path')
                if not api_def_path:
                    continue

                abs_api_url_from_def = urljoin(self.base_scan_url, api_def_path)
                normalized_api_path_from_def = urlparse(abs_api_url_from_def).path.rstrip('/') if urlparse(abs_api_url_from_def).path != '/' else '/'

                if normalized_target_path == normalized_api_path_from_def:
                    logger.info(f"URL {target_url} khớp với định nghĩa API '{api_def_path}'. Chạy quét API chuyên dụng.")
                    self._scan_api_endpoint(target_url, api_def) # target_url đã được resolve
                    api_definition_matched_and_scanned = True
                    break  # Chỉ quét theo định nghĩa API đầu tiên khớp
        except Exception as api_match_exc:
            logger.error(f"Lỗi trong quá trình khớp/quét định nghĩa API cho {target_url}: {api_match_exc}", exc_info=True)

        # 2. Quét tham số URL (luôn chạy, trừ khi có cấu hình khác)
        # if not api_definition_matched_and_scanned or self.scanner_config.get('scan_url_params_anyway', True):
        try:
            self._scan_url_parameters(target_url)
        except Exception as url_scan_exc:
            logger.error(f"Lỗi quét tham số URL cho {target_url}: {url_scan_exc}", exc_info=True)

        # 3. Quét Form HTML (chỉ chạy nếu không phải API đã quét, hoặc theo cấu hình)
        # if not api_definition_matched_and_scanned or self.scanner_config.get('scan_forms_anyway', False):
        try:
            self._fetch_and_scan_forms_on_url(target_url)
        except Exception as form_scan_exc:
            logger.error(f"Lỗi trong pha quét form cho {target_url}: {form_scan_exc}", exc_info=True)

    def _fetch_and_scan_forms_on_url(self, target_url):
        """Lấy nội dung URL và quét các form HTML nếu có."""
        try:
            content_type = ""
            head_response = self.http_client.send_advanced_request(target_url, method='HEAD', timeout=self.config.get('http', {}).get('timeout', 5))
            if head_response and head_response.headers:
                content_type = head_response.headers.get('Content-Type', '').lower()

            should_fetch_body = 'text/html' in content_type or not content_type
            if not should_fetch_body and head_response and head_response.status_code == 405: # Method Not Allowed for HEAD
                logger.debug(f"HEAD request tới {target_url} bị từ chối (405). Thử GET để quét form.")
                should_fetch_body = True


            if should_fetch_body:
                logger.debug(f"Đang lấy nội dung để quét form tiềm năng: {target_url}")
                get_response = self.http_client.send_advanced_request(target_url, method='GET')

                if get_response and get_response.text and \
                   'text/html' in get_response.headers.get('Content-Type', '').lower():
                    self.parser = AdvancedHTMLParser(get_response.text, target_url) # target_url đã resolve
                    forms = self.parser.extract_forms()
                    if forms:
                        logger.info(f"Tìm thấy {len(forms)} form trên {target_url}. Đang quét form.")
                        self._scan_html_forms(forms, target_url)
                    else:
                        logger.debug(f"Không tìm thấy form nào trên trang HTML: {target_url}")
                # else:
                    # logger.debug(f"Nội dung của {target_url} (GET) không phải HTML hoặc không lấy được. Bỏ qua quét form.")
            # elif 'text/html' not in content_type and content_type: # Content-Type xác định không phải HTML
                # logger.debug(f"Content-Type của {target_url} là '{content_type}', không phải HTML. Bỏ qua quét form.")

        except requests.exceptions.RequestException as req_ex:
            logger.warning(f"Request lỗi khi lấy form từ {target_url}: {req_ex}. Bỏ qua quét form.")
        except Exception as e:
            logger.error(f"Lỗi không xác định khi lấy và quét form từ {target_url}: {e}", exc_info=True)

    def _scan_structured_target_object(self, structured_target_def):
        """Quét một mục tiêu được định nghĩa có cấu trúc (từ additional_targets.yaml)."""
        target_url_from_def = structured_target_def['url']
        target_url = urljoin(self.base_scan_url, target_url_from_def) 

        method = structured_target_def.get('method', 'GET').upper()
        base_data_template = structured_target_def.get('base_data', {})
        params_in = structured_target_def.get('params_in') 
        params_to_test_list = structured_target_def.get('params_to_test', [])
        custom_headers = structured_target_def.get('headers', {})

        logger.info(f"--- 🧱 Đang quét mục tiêu có cấu trúc: {method} {target_url} ---")
        self.current_scan_target = target_url

        if method == 'GET' and not params_to_test_list:
            logger.debug(f"Mục tiêu GET có cấu trúc {target_url} không có 'params_to_test'. Sẽ quét các tham số query trong URL và form.")
            self._scan_url_parameters(target_url)
            self._fetch_and_scan_forms_on_url(target_url)
            return
        if base_data_template and not params_to_test_list and method in ['POST', 'PUT']:
            params_to_test_list = list(base_data_template.keys()) # Mặc định test tất cả key trong base_data
            logger.debug(f"Mục tiêu {method} {target_url} có 'base_data' nhưng không 'params_to_test'. Mặc định test: {params_to_test_list}")

        if not params_to_test_list:
            logger.warning(f"Không có tham số để kiểm thử cho mục tiêu có cấu trúc {method} {target_url}.")
            if method == 'GET': self._fetch_and_scan_forms_on_url(target_url) # Vẫn có thể có form
            return

        for param_name_to_inject in params_to_test_list:
            logger.debug(f"Kiểm thử tham số của mục tiêu cấu trúc: '{param_name_to_inject}' trong {method} {target_url}")
            for payload in self.payloads:
                request_headers = self.http_client.session.headers.copy()
                request_headers.update(custom_headers) 
                request_args = {
                    'method': method,
                    'url': target_url,
                    'timeout': self.config.get('http', {}).get('timeout', 15),
                    'headers': request_headers
                }
                injection_point_id = f"{target_url}|{method}|{params_in or 'query'}|{param_name_to_inject}"

                try:
                    if method == 'GET':
                        parsed_original_url = urlparse(target_url)
                        original_query_dict = parse_qs(parsed_original_url.query, keep_blank_values=True)
                        injected_query_data = {k: v_list[:] for k, v_list in original_query_dict.items()}
                        injected_query_data[param_name_to_inject] = [payload]
                        injected_query_string = urlencode(injected_query_data, doseq=True, quote_via=quote)
                        final_url_for_get = urlunparse((parsed_original_url.scheme, parsed_original_url.netloc, parsed_original_url.path, parsed_original_url.params, injected_query_string, parsed_original_url.fragment))
                        request_args['url'] = final_url_for_get
                        injection_point_id = final_url_for_get

                    elif method in ['POST', 'PUT']:
                        data_to_send = copy.deepcopy(base_data_template) if base_data_template else {}
                        if params_in == 'body_json':
                            if 'Content-Type' not in request_headers:
                                request_headers['Content-Type'] = 'application/json; charset=utf-8'
                            keys_path = param_name_to_inject.split('.')
                            current_level_obj = data_to_send
                            for i, key_part in enumerate(keys_path):
                                if i == len(keys_path) - 1:
                                    if isinstance(current_level_obj, dict): current_level_obj[key_part] = payload
                                    elif isinstance(current_level_obj, list): current_level_obj[int(key_part)] = payload
                                    else: raise TypeError(f"Không thể gán key '{key_part}' cho {type(current_level_obj)}")
                                else:
                                    if isinstance(current_level_obj, dict):
                                        if key_part not in current_level_obj: current_level_obj[key_part] = {}
                                        current_level_obj = current_level_obj[key_part]
                                    elif isinstance(current_level_obj, list): current_level_obj = current_level_obj[int(key_part)]
                                    else: raise KeyError(f"Key trung gian '{key_part}' không hợp lệ")
                            request_args['data'] = json.dumps(data_to_send)
                        elif params_in == 'body_form' or not params_in:
                            if 'Content-Type' not in request_headers:
                                request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
                            data_to_send[param_name_to_inject] = payload
                            request_args['data'] = data_to_send
                        else:
                            logger.warning(f"Kiểu 'params_in': '{params_in}' không được hỗ trợ cho {method} {target_url}. Bỏ qua.")
                            continue
                    else: 
                        logger.debug(f"Method {method} không hỗ trợ inject body params trong mục tiêu cấu trúc. Bỏ qua.")
                        continue

                    request_args['headers'] = request_headers 

                    start_time = time.time()
                    response = self.http_client.send_advanced_request(**request_args)
                    if response:
                        self._analyze_inband_response(response, payload, param_name_to_inject, start_time, injection_point_id)
                except Exception as req_ex:
                    logger.error(f"Lỗi request cho tham số '{param_name_to_inject}' của mục tiêu cấu trúc ({method} {target_url}): {req_ex}", exc_info=True)

        if method == 'GET':
            self._fetch_and_scan_forms_on_url(target_url)

    def generate_report(self):
        """Trả về danh sách các lỗ hổng tìm thấy, đã sắp xếp."""
        self.vulnerabilities.sort(key=lambda v: (v.url, v.input_field or '', v.severity))
        return self.vulnerabilities
def main():
    # --- Thiết lập Argparse ---
    parser = argparse.ArgumentParser(
        description='Advanced SQL Injection Scanner with Discovery & API Support',
        epilog='Example: python -m src.scanner --url http://localhost:8000/ --config config.yaml --report report.html'
    )
    parser.add_argument('--url', required=True, help='Base Target URL for scanning and discovery')
    parser.add_argument('--config', default='config.yaml', help='Path to config.yaml')
    parser.add_argument('--report', default='report.html', help='Output report file path')
    parser.add_argument('--loglevel', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set logging level')
    parser.add_argument('--logfile', help='Optional: Path to save the log output file.')
    args = parser.parse_args()

    # --- Thiết lập Logging ---
    log_level = getattr(logging, args.loglevel.upper(), logging.INFO)
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    log_datefmt = '%Y-%m-%d %H:%M:%S'
    formatter = logging.Formatter(log_format, datefmt=log_datefmt)
    root_logger = logging.getLogger() # Lấy root logger
    root_logger.setLevel(log_level)
    for handler in root_logger.handlers[:]: root_logger.removeHandler(handler) # Xóa handler cũ
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    if args.logfile:
        try:
            log_dir = os.path.dirname(args.logfile)
            if log_dir and not os.path.exists(log_dir): os.makedirs(log_dir, exist_ok=True)
            file_handler = logging.FileHandler(args.logfile, mode='a', encoding='utf-8')
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            logging.info(f"Logging được kích hoạt tới file: {args.logfile}")
        except Exception as log_e:
            logging.error(f"Không thể cấu hình logging file tới {args.logfile}: {log_e}")
    if log_level > logging.DEBUG: # Giảm output từ thư viện bên thứ ba
        for lib_logger_name in ["urllib3", "requests", "chardet"]:
            logging.getLogger(lib_logger_name).setLevel(logging.WARNING)

    # --- Khởi tạo Scanner ---
    logger.info("🏁 Khởi tạo SQL Injection Scanner...")
    scanner = None
    try:
        scanner = AdvancedSQLInjector(config_file=args.config) # AdvancedSQLInjector phải được import đúng
        parsed_cli_url = urlparse(args.url)
        if not (parsed_cli_url.scheme and parsed_cli_url.netloc):
            logger.critical(f"URL đầu vào --url '{args.url}' phải là một URL tuyệt đối (ví dụ: http://example.com).")
            sys.exit(1)
        
        # Thiết lập base_scan_url dựa trên args.url
        if parsed_cli_url.path == "" or parsed_cli_url.path.endswith('/'):
            scanner.base_scan_url = args.url.rstrip('/') + '/'
        else:
            # Lấy thư mục cha của path, đảm bảo nó kết thúc bằng /
            base_path_dir = os.path.dirname(parsed_cli_url.path)
            if not base_path_dir.endswith('/'): base_path_dir += '/'
            scanner.base_scan_url = urljoin(args.url, base_path_dir)
        logger.info(f"Scanner đã khởi tạo. Base scan URL được đặt thành: {scanner.base_scan_url}")

    except NameError: # Nếu AdvancedSQLInjector chưa được import
        logger.critical("Lớp AdvancedSQLInjector không được tìm thấy. Hãy đảm bảo bạn đã import đúng.")
        sys.exit(1)
    except Exception as init_e:
        logger.critical(f"Không thể khởi tạo scanner: {init_e}", exc_info=True)
        sys.exit(1)

    # --- Chuẩn bị các tác vụ quét ban đầu ---
    tasks_to_submit_queue = collections.deque()
    processed_or_queued_urls = set() # Lưu trữ URL đã chuẩn hóa (tuyệt đối, không fragment)

    def add_task_to_queue_if_new(task_item):
        url_to_check_in_task = ""
        if isinstance(task_item, str):
            url_to_check_in_task = task_item
        elif isinstance(task_item, dict) and 'url' in task_item:
            url_to_check_in_task = task_item['url']
        else: return False # Không phải định dạng task hợp lệ

        absolute_url = urljoin(scanner.base_scan_url, url_to_check_in_task)
        canonical_url = urlunparse(urlparse(absolute_url)._replace(fragment=""))

        if canonical_url not in processed_or_queued_urls:
            processed_or_queued_urls.add(canonical_url)
            tasks_to_submit_queue.append(task_item)
            # logger.debug(f"📥 Đã thêm vào hàng đợi: '{canonical_url}'")
            return True
        return False

    logger.info("🔍 Đang chuẩn bị các mục tiêu quét ban đầu...")
    for target_obj_from_config in scanner.additional_targets: # Từ additional_targets.yaml
        add_task_to_queue_if_new(target_obj_from_config)

    initial_simple_urls = set()
    initial_simple_urls.add(args.url) # URL từ dòng lệnh
    for api_def in scanner.api_definitions: # URL từ định nghĩa API
        if api_def.get('path'): initial_simple_urls.add(api_def['path'])
    if scanner.discovery_config.get('enabled', False): # URL từ discovery
        discovered_urls = scanner.discover_targets(scanner.base_scan_url)
        for disc_url in discovered_urls: initial_simple_urls.add(disc_url)
    for url_s_to_add in sorted(list(initial_simple_urls)):
        add_task_to_queue_if_new(url_s_to_add)

    if not tasks_to_submit_queue:
        logger.info("Không có mục tiêu nào để quét. Kết thúc.")
        sys.exit(0)

    # --- Thực thi quét với ThreadPoolExecutor ---
    logger.info(f"--- 🚀 Bắt đầu quét với {len(tasks_to_submit_queue)} tác vụ ban đầu trong hàng đợi ---")
    scan_successful = True
    completed_tasks_count = 0
    total_submitted_tasks_ever = 0
    max_workers = scanner.scanner_config.get('max_threads', min(10, (os.cpu_count() or 1) + 4))
    logger.info(f"Sử dụng tối đa {max_workers} luồng.")
    active_futures = {} # {future: task_description_string}

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            while tasks_to_submit_queue or active_futures:
                # Submit tác vụ mới nếu có chỗ và có tác vụ trong hàng đợi
                while tasks_to_submit_queue and len(active_futures) < max_workers * 2:
                    current_task_item = tasks_to_submit_queue.popleft()
                    total_submitted_tasks_ever += 1
                    task_desc_for_log = ""
                    if isinstance(current_task_item, str): task_desc_for_log = f"URL: {urljoin(scanner.base_scan_url, current_task_item)}"
                    elif isinstance(current_task_item, dict): task_desc_for_log = f"Structured: {current_task_item.get('method','GET')} {urljoin(scanner.base_scan_url, current_task_item.get('url','N/A'))}"
                    
                    # logger.debug(f"📤 Đang submit tác vụ ({total_submitted_tasks_ever}): {task_desc_for_log}")
                    future = executor.submit(scanner.scan_target, current_task_item)
                    active_futures[future] = task_desc_for_log

                if not active_futures: break # Không còn future nào đang chạy, thoát

                done_futures, _ = concurrent.futures.wait(active_futures.keys(), timeout=1.0, return_when=concurrent.futures.FIRST_COMPLETED)

                for future in done_futures:
                    completed_tasks_count += 1
                    task_description = active_futures.pop(future)
                    try:
                        newly_discovered_links = future.result() # scanner.scan_target trả về list link mới
                        logger.info(f"✅ ({completed_tasks_count}/{total_submitted_tasks_ever}) Hoàn thành: {task_description}")
                        if newly_discovered_links:
                            link_plural = "link" if len(newly_discovered_links) == 1 else "links"
                            logger.info(f"🔗 Khám phá được {len(newly_discovered_links)} {link_plural} mới từ '{task_description.split(': ',1)[-1]}'")
                            for new_link_str in newly_discovered_links:
                                add_task_to_queue_if_new(new_link_str)
                    except KeyboardInterrupt:
                        logger.warning(f"⚠️ Tác vụ bị dừng (KeyboardInterrupt trong worker): {task_description}")
                        scan_successful = False
                        active_futures.clear()
                        tasks_to_submit_queue.clear()
                        raise
                    except Exception as exc_worker:
                        logger.error(f"❌ ({completed_tasks_count}/{total_submitted_tasks_ever}) Lỗi tác vụ '{task_description}': {exc_worker}", exc_info=True)
                        scan_successful = False
                
                if not done_futures and not tasks_to_submit_queue and not active_futures: break
    except KeyboardInterrupt:
        logger.warning("🚦 Quá trình quét bị dừng bởi người dùng (Ctrl+C ở luồng chính).")
        scan_successful = False
    except Exception as main_loop_exc:
        logger.critical(f"💥 Lỗi nghiêm trọng trong vòng lặp quản lý tác vụ: {main_loop_exc}", exc_info=True)
        scan_successful = False
    finally:
        logger.info(f"--- 📬 Hoàn tất vòng lặp quản lý tác vụ. Trong hàng đợi: {len(tasks_to_submit_queue)}. Đang hoạt động (nếu lỗi): {len(active_futures)} ---")
        logger.info(f"--- Tổng số tác vụ đã submit: {total_submitted_tasks_ever}. Số tác vụ đã xử lý: {completed_tasks_count} ---")

    # --- Tạo Báo Cáo ---
    if scanner:
        logger.info("--- 📊 Đang tạo báo cáo ---")
        report_generator = None # Khởi tạo trước try-except
        try:
            report_generator = ReportGenerator() # ReportGenerator phải được import đúng
        except NameError:
            logger.error("Lớp ReportGenerator không được tìm thấy. Không thể tạo báo cáo.")
        
        if report_generator:
            try:
                vulnerabilities_found = scanner.generate_report()
                log_msg = f"Tìm thấy tổng cộng {len(vulnerabilities_found)} lỗ hổng." if vulnerabilities_found else "Không tìm thấy lỗ hổng nào."
                logger.info(log_msg)
                
                report_file_path = report_generator.generate(vulnerabilities_found, args.report)
                if report_file_path:
                    logger.info(f"Báo cáo đã được lưu tại: {os.path.abspath(report_file_path)}")
                    print(f"\nBáo cáo đã được lưu tại: {os.path.abspath(report_file_path)}")
                else:
                    logger.error("Không thể tạo file báo cáo (ReportGenerator.generate trả về None).")
            except FileNotFoundError as report_fnf_e:
                logger.error(f"Lỗi tạo báo cáo: Không tìm thấy file template - {report_fnf_e}. Kiểm tra 'templates/report.html'.")
            except Exception as report_gen_e:
                logger.error(f"Lỗi tạo báo cáo: {report_gen_e}", exc_info=True)
    else:
        logger.error("Đối tượng scanner không tồn tại, không thể tạo báo cáo.")

    logger.info("--- 🏁 Kết thúc quá trình quét ---")
    if not scan_successful:
        sys.exit(1)

if __name__ == "__main__":
    main()