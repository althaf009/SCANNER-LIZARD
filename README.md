# LIZARD Vulnerability Scanner

**LIZARD** is a simple yet effective vulnerability scanner designed to identify common security issues such as SQL Injection, Cross-Site Scripting (XSS), and authentication vulnerabilities. It performs a series of tests against a provided URL to help you identify potential security weaknesses in your web applications.

## Features

- **SQL Injection Testing**: Detects various SQL Injection vulnerabilities including error-based, boolean-based, time-based, and union-based SQL Injection.
- **XSS Testing**: Identifies different types of XSS vulnerabilities such as stored, reflected, and DOM-based XSS.
- **Authentication Testing**: Checks for vulnerabilities in basic and form-based authentication mechanisms using a default set of credentials.

## Getting Started

### Prerequisites

- Python 3.x
- `requests` library (install using `pip install requests`)

### Installation

Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/LIZARD.git
cd LIZARD
Usage
Run the Scanner:

Execute the script from the command line:

bash
Copy code
python lizard_scanner.py
Provide Input:

Enter the URL you want to test.
Provide the parameter name if you're testing for SQL Injection or XSS vulnerabilities.
For authentication testing, provide URLs where authentication is implemented.
Example
bash
Copy code
Enter the URL to test: https://example.com
Enter the parameter to test: id
Enter the POST URL for SQL Injection testing (leave empty to skip): https://example.com/login
Enter the URL for Basic Authentication testing: https://example.com/admin
Enter the URL for Form Authentication testing: https://example.com/login
Results
The script will print out the results of the SQL Injection, XSS, and authentication tests directly in the terminal.
Vulnerabilities found will be highlighted in red, and if no vulnerabilities are found, the results will be indicated in green.
Contributing
Contributions to enhance the functionality of LIZARD are welcome! Please follow these steps:

Fork the repository.
Create a new branch (git checkout -b feature-branch).
Make your changes.
Commit your changes (git commit -am 'Add new feature').
Push to the branch (git push origin feature-branch).
Create a new Pull Request.
License
This project is licensed under the MIT License - see the LICENSE file for details.
