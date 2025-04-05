# SQL Scanner Injection

This project is designed to identify potential SQL injection vulnerabilities in web applications. It includes a parser for HTML forms and a scanner that analyzes inputs for malicious payloads.
- Run project: `python -m src.scanner --url <target_url> --config config.yaml`
- Local test: `php -S localhost:8000`, `python -m src.scanner --url http://localhost:8000/index.php --config config.yaml --report report.html`
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