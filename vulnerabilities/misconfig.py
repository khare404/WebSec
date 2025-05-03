import requests

def scan_misconfig(target):
    result_text = f"Security Misconfigurations Scan for: {target}\n\n"

    # 1) Insecure scheme
    if target.startswith("http://"):
        result_text += "[!] Insecure scheme: using HTTP instead of HTTPS.\n\n"

    # 2) Directory listings & exposed files
    endpoints = ["", "admin", ".git/", ".env", ".htaccess"]
    for ep in endpoints:
        url = target.rstrip("/") + "/" + ep
        try:
            r = requests.get(url, timeout=5)
            if "Index of" in r.text or "<title>Index of" in r.text:
                result_text += f"[!] Possible directory listing at: {url}\n"
            elif ep and r.status_code == 200:
                result_text += f"[!] Exposed: {ep} at {url}\n"
        except requests.RequestException:
            pass

    # 3) Server headers
    try:
        r = requests.head(target, timeout=5)
        srv = r.headers.get("Server")
        xp  = r.headers.get("X-Powered-By")
        if srv:
            result_text += f"\n[Server Header] {srv}\n"
        if xp:
            result_text += f"[X-Powered-By] {xp}\n"
    except requests.RequestException:
        pass

    # 4) Default credentials on login form
    creds = check_form_creds(target)
    if creds:
        result_text += "\n[!] Potential default form credentials found:\n"
        for u, p in creds:
            result_text += f"    - {u}:{p}\n"

    # nothing found?
    if all(tag not in result_text for tag in [
        "Insecure scheme", "directory listing", "Exposed", "default form credentials"
    ]):
        result_text += "\nNo obvious misconfigurations found (basic checks only)."

    return result_text


def check_form_creds(target):
    """
    Attempts default creds on Altoro Testfire’s login form.
    Uses a session, correct field names, and the submit button.
    """
    # Determine actual login URL
    login_url = target if target.lower().endswith("login.jsp") else target.rstrip("/") + "/login.jsp"

    session = requests.Session()
    try:
        session.get(login_url, timeout=5)  # prime cookies
    except requests.RequestException:
        return []

    common_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("user",  "password"),
        ("root",  "root"),
    ]
    found = []

    for u, p in common_creds:
        data = {
            "uid":       u,
            "passwrd":   p,         # correct Altoro field name
            "btnSubmit": "Login"    # Altoro’s submit button name/value
        }
        try:
            r = session.post(login_url, data=data, timeout=5, allow_redirects=True)
            if "Sign Off" in r.text or "Logout" in r.text:
                found.append((u, p))
        except requests.RequestException:
            continue

    return found
