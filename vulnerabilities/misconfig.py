import requests

def scan_misconfig(target):
    """
    Scans the target for common security misconfigurations:
      1. Checks if HTTPS is used.
      2. Attempts to detect directory listing on common paths.
      3. Looks for exposed files (.git, .env, etc.).
      4. Checks server headers (Server, X-Powered-By).
      5. Tries form-based default credentials on /login.jsp (Altoro style: uid & passwrd).

    Returns:
        A multiline string describing any findings.
    """
    result_text = f"Security Misconfigurations Scan for: {target}\n\n"

    # 1) Check if HTTPS is used
    if target.startswith("http://"):
        result_text += "[!] Insecure scheme: using HTTP instead of HTTPS.\n\n"

    # 2) Check for directory listing or exposed files
    endpoints = ["", "admin", ".git/", ".env", ".htaccess"]
    for endpoint in endpoints:
        url = target.rstrip("/") + "/" + endpoint
        try:
            resp = requests.get(url, timeout=5)
            if "Index of" in resp.text or "<title>Index of" in resp.text:
                result_text += f"[!] Possible directory listing found at: {url}\n"
            elif endpoint and resp.status_code == 200:
                # If .env, .git, or .htaccess is accessible, it's a big misconfig
                result_text += f"[!] {endpoint} might be exposed: {url}\n"
        except requests.RequestException:
            pass

    # 3) Check server headers
    try:
        resp_head = requests.head(target, timeout=5)
        server_header = resp_head.headers.get("Server", "")
        powered_by = resp_head.headers.get("X-Powered-By", "")
        
        if server_header:
            result_text += f"\n[Server Header] {server_header}\n"
        if powered_by:
            result_text += f"[X-Powered-By] {powered_by}\n"
    except requests.RequestException:
        pass

    # 4) Check form-based default creds (Altoro style: uid & passwrd)
    creds_found = check_form_creds(target)
    if creds_found:
        result_text += "\n[!] Potential default form credentials found:\n"
        for (u, p) in creds_found:
            result_text += f"    - {u}:{p}\n"

    # If nothing was flagged
    if all(x not in result_text for x in [
        "Insecure scheme", "directory listing", ".env", ".git", 
        ".htaccess", "default form credentials"
    ]):
        result_text += "\nNo obvious misconfigurations found (basic checks only)."

    return result_text


def check_form_creds(target):
    """
    Checks form-based logins with common credentials on the Altoro-like login:
    - /login.jsp with fields uid & passwrd
    - Looks for 'Sign Off' in the response to confirm a successful login.

    Common credentials tried:
      - admin:admin
      - admin:password
      - user:password
      - root:root

    Returns:
        A list of (username, password) pairs that actually log in successfully.
    """
    common_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("user", "password"),
        ("root", "root"),
    ]
    found = []

    # If the user gave a direct URL with /login.jsp, use that; otherwise, append /login.jsp
    if "login.jsp" in target:
        login_url = target
    else:
        login_url = target.rstrip("/") + "/login.jsp"

    for (u, p) in common_creds:
        data = {
            "uid": u,
            "passwrd": p  # <-- Correct field name
        }
        try:
            # Follow redirects, as a successful login might lead to a different page
            r = requests.post(login_url, data=data, timeout=5, allow_redirects=True)
            # On Altoro, a successful login typically shows "Sign Off" in the response
            if "Sign Off" in r.text or "Logout" in r.text:
                found.append((u, p))
        except requests.RequestException:
            pass

    return found
