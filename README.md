# SQL Scanner Injection

This project is designed to identify potential SQL injection vulnerabilities in web applications. It includes a parser for HTML forms and a scanner that analyzes inputs for malicious payloads.
- Ensure: `source .venv/bin/activate`
-Chạy server PHP:
```
cd /media/ptt/New Volume/HUST/2024.2/project2/scanner-sql-injection
php -S localhost:8000
```
Chạy scanner Python:
`python -m src.scanner --url http://localhost:8000/ --config config.yaml --report report.html --loglevel INFO --logfile scanner.log`
Chạy WebSocket server:
```
cd /media/ptt/New Volume/HUST/2024.2/project2/scanner-sql-injection/scanner-ui
npm run ws
```

Chạy Next.js app:
```
npm run dev
```

Truy cập giao diện:
Mở `http://localhost:3000`.

Kiểm tra log thời gian thực và báo cáo.
- Thay http://localhost:8000/ bằng URL gốc của web server test của bạn. Dùng `--loglevel DEBUG` để xem log chi tiết
## Installation
To install the required dependencies, run:

```
pip install -r requirements.txt
```

## Usage

1. Import the necessary modules from the `src` package.
2. Use the `parser.py` to extract data from HTML forms.
3. Utilize the `scanner.py` to analyze inputs for potential SQL injection vulnerabilities.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.