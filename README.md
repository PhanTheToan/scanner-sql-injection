# SQL Scanner Injection

This project is designed to identify potential SQL injection vulnerabilities in web applications. It includes a parser for HTML forms and a scanner that analyzes inputs for malicious payloads.
- Run project: `python -m src.scanner --url http://testsite.com`
## Project Structure

```
sql-scanner-injection
├── src
│   ├── parser.py          # Functions for parsing HTML and forms
│   ├── scanner.py         # Main logic for scanning inputs for SQL injection vulnerabilities
│   ├── utils              # Utility functions for various tasks
│   │   ├── __init__.py
│   │   └── helpers.py     # Helper functions for data manipulation and validation
│   ├── models             # Definitions related to vulnerabilities
│   │   ├── __init__.py
│   │   └── vulnerability.py # Class/functions for managing vulnerabilities
│   └── __init__.py
├── tests                  # Unit tests for the project
│   ├── __init__.py
│   ├── test_parser.py     # Tests for parser functions
│   └── test_scanner.py    # Tests for scanner functions
├── data                   # Test data
│   └── payloads.txt       # List of payloads for testing
├── requirements.txt       # Project dependencies
├── .gitignore             # Files and directories to ignore in Git
├── setup.py               # Packaging information
└── README.md              # Project documentation
```

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