# 🛡️ Advanced SQL Injection Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/) 
[![Next.js](https://img.shields.io/badge/Next.js-11.1.3-brightgreen.svg)](https://nextjs.org/) 
[![HTML5](https://img.shields.io/badge/HTML5-E34F26.svg?logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/HTML) 
[![PHP](https://img.shields.io/badge/PHP-7.4+-blue.svg)](https://www.php.net/)


Một công cụ quét lỗ hổng SQL injection mạnh mẽ, được thiết kế để tự động phát hiện các điểm yếu trong ứng dụng web. Công cụ này có khả năng phân tích form, khám phá các endpoint ẩn, thực hiện quét sau khi đã xác thực và kiểm thử các API phức tạp.

## ✨ Tính năng nổi bật

Công cụ có các khả năng chính sau:

* **Hỗ trợ nhiều kỹ thuật tấn công**: Tự động kiểm thử các lỗ hổng SQL injection theo kiểu **Error-based**, **Boolean-based**, và **Time-based**.
* **Khám phá (Discovery)**: Tự động tìm kiếm các trang và thư mục tiềm năng dựa trên một wordlist tùy chỉnh (`common_paths.txt`).
* **Phân tích HTML**: Tự động trích xuất các form và link từ các trang web để xác định các điểm có thể bị tấn công.
* **Quét sau khi xác thực**: Hỗ trợ đăng nhập vào một phiên làm việc (session) trước khi bắt đầu quét, cho phép kiểm tra các khu vực yêu cầu quyền truy cập.
* **Quét API chuyên sâu**: Khả năng kiểm thử các API endpoint phức tạp với các phương thức (GET, POST, PUT, etc.) và các loại body khác nhau (JSON, Form Data) thông qua file định nghĩa `api_endpoints.yaml`.
* **Cấu hình linh hoạt**: Hầu hết các hành vi của máy quét, từ thông tin đăng nhập, proxy, đến danh sách payload, đều có thể được tùy chỉnh dễ dàng qua các file cấu hình YAML và text.
* **Xử lý đồng thời (Concurrency)**: Sử dụng đa luồng để thực hiện nhiều tác vụ quét song song, giúp tăng tốc độ đáng kể.
* **Báo cáo trực quan**: Tạo ra báo cáo chi tiết dưới dạng file HTML tương tác, tổng hợp các lỗ hổng đã tìm thấy cùng với mức độ nghiêm trọng và payload tương ứng.

## 🏗️ Kiến trúc hệ thống

Hệ thống bao gồm 3 thành phần chính:

1.  **Scanner Backend (Python)**: Hạt nhân của dự án, chịu trách nhiệm gửi các request, phân tích response và phát hiện lỗ hổng.
2.  **Web Application (PHP)**: Một môi trường web được dàn dựng sẵn với các lỗ hổng SQL injection cố ý để làm mục tiêu cho máy quét.
3.  **Frontend UI (Next.js - Tùy chọn)**: Giao diện người dùng để tương tác và theo dõi quá trình quét trong thời gian thực thông qua WebSocket.

## 🚀 Bắt đầu

### Yêu cầu

* Python 3.8+ và `pip`
* PHP 7.4+ (để chạy môi trường web thử nghiệm)
* Node.js và `npm` (nếu bạn muốn chạy giao diện frontend)

### Cài đặt & Cấu hình

1.  **Clone a repository:**
    ```bash
    git clone https://github.com/PhanTheToan/scanner-sql-injection.git
    cd scanner-sql-injection
    ```

2.  **Cài đặt các gói phụ thuộc cho Scanner (Python):**
    ```bash
    # Tạo và kích hoạt môi trường ảo (khuyến khích)
    python -m venv .venv
    source .venv/bin/activate
    
    # Cài đặt các gói cần thiết
    pip install -r requirements.txt
    ```

3.  **Cài đặt các gói cho Frontend (Tùy chọn):**
    ```bash
    cd scanner-ui
    npm install
    cd ..
    ```

## ⚙️ Hướng dẫn sử dụng

Thực hiện các bước sau trong các cửa sổ terminal riêng biệt.

#### 1. Khởi động Web Server thử nghiệm (PHP)

Terminal này sẽ chạy ứng dụng web có lỗ hổng để máy quét có thể tấn công.

```bash
# Đảm bảo bạn đang ở thư mục gốc của dự án
php -S localhost:8000
```
#### 3. Khởi động Giao diện (Tùy chọn)
Terminal này dùng để giao tiếp real-time giữa scanner và giao diện frontend.
```bash
cd scanner-ui
npm run ws
```
Terminal này sẽ phục vụ giao diện Next.js.
```bash
cd scanner-ui
npm run dev
```
Bây giờ bạn có thể truy cập giao diện tại `http://localhost:3000`

#### 4. Chạy Scanner
Lệnh chính để chạy dự án
```bash
# Chạy ở thư mục gốc & đã kích hoạt môi trường ảo
python -m src.scanner --url http://localhost:8000/ --config config.yaml --report report.html --loglevel INFO --logfile scanner.log
```
- `--url`: URL gốc của ứng dụng web cần quét.
- `--config`: Đường dẫn tới file cấu hình chính.
- `--report`: Tên file báo cáo HTML sẽ được tạo ra.
- `--loglevel`: Mức độ log (DEBUG, INFO, WARNING, ERROR). Dùng DEBUG để xem chi tiết nhất.
- `--logfile`: Tên file để lưu lại toàn bộ log của phiên quét.

Sau khi quét xong, file kết quả sẽ ở `report.html` và log của chương trình `scanner.log`

## 🔧 Tùy chỉnh
Có thể thay đổi & bổ xung các file dưới đây để sử dụng tools hiệu quả hơn

- `config.yaml`: Cấu hình chính cho HTTP client (timeout, user-agent), thông tin đăng nhập, cấu hình máy quét (số luồng, wordlist).
- `data/api_endpoints.yaml`: Thêm hoặc sửa các định nghĩa API phức tạp mà bạn muốn máy quét kiểm thử chuyên sâu.
- `data/payloads.txt`: Chứa danh sách các payload SQL injection sẽ được sử dụng để tấn công.
- `data/common_paths.txt`: Chứa danh sách các đường dẫn phổ biến để sử dụng trong quá trình khám phá (discovery).

## 🤝 Đóng góp
Mọi đóng góp đều được chào đón! Vui lòng tạo một Pull Request hoặc mở một Issue để đề xuất cải tiến hoặc báo lỗi.

