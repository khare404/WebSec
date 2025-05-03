# import os
# import requests
# import socket
# import subprocess
# import time

# def get_ip(target):
#     try:
#         return socket.gethostbyname(target)
#     except socket.gaierror:
#         return None

# def port_scan(target):
#     common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 8080]
#     open_ports = []
    
#     for port in common_ports:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.settimeout(1)
#         result = sock.connect_ex((target, port))
#         if result == 0:
#             open_ports.append(port)
#         sock.close()
    
#     return open_ports

# def subdomain_enum(target):
#     subdomains = ['www', 'mail', 'ftp', 'test', 'api', 'blog', 'dev']
#     found_subdomains = []
    
#     for sub in subdomains:
#         url = f"{sub}.{target}"
#         try:
#             ip = socket.gethostbyname(url)
#             found_subdomains.append(url)
#         except socket.gaierror:
#             continue
    
#     return found_subdomains

# def run_nmap(target):
#     try:
#         result = subprocess.run(["nmap", "-F", target], capture_output=True, text=True)
#         return result.stdout
#     except FileNotFoundError:
#         return "Nmap is not installed or not found in system PATH."

     



# def enumerate_target(target):
#     # Resolve IP
#     ip = get_ip(target)
#     if not ip:
#         return "Could not resolve target IP."
    
#     # Perform scans
#     open_ports = port_scan(ip)
#     subdomains = subdomain_enum(target)
#     nmap_results = run_nmap(target)
#     # directory_results = directory_enum(target)

#     # Build a multi-line result string with line breaks
#     result_text = (
#         f"[+] Enumerating target: {target}\n\n"
#         f"IP Address: {ip}\n"
#         f"Open Ports: {open_ports}\n"
#         f"Subdomains Found: {subdomains}\n\n"
#         f"Nmap Scan Results:\n{nmap_results}"
    
#     )

#     return result_text

# if __name__ == "__main__":
#     target = input("Enter the target domain or IP: ")
#     results = enumerate_target(target)
#     print("\nEnumeration Completed.\n")
#     print(results)
import os
import socket
import subprocess

def get_ip(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def port_scan(target):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 8080]
    open_ports = []

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    return open_ports

def subdomain_enum(target):
    subdomains = ['www', 'mail', 'ftp', 'test', 'api', 'blog', 'dev']
    found_subdomains = []

    for sub in subdomains:
        url = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(url)
            found_subdomains.append(url)
        except socket.gaierror:
            continue

    return found_subdomains

# ✅ Updated Nmap with version detection and vulners script
def run_nmap(target):
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--script", "vulners", target],
            capture_output=True, text=True
        )
        return result.stdout
    except FileNotFoundError:
        return "Nmap is not installed or not found in system PATH."

def enumerate_target(target):
    ip = get_ip(target)
    if not ip:
        return "Could not resolve target IP."

    open_ports = port_scan(ip)
    subdomains = subdomain_enum(target)
    nmap_results = run_nmap(target)

    result_text = (
        f"[+] Enumerating target: {target}\n\n"
        f"IP Address: {ip}\n"
        f"Open Ports: {open_ports}\n"
        f"Subdomains Found: {subdomains}\n\n"
        f"Service Versions and Vulnerabilities (via Nmap Vulners):\n{nmap_results}"
    )

    return result_text

if __name__ == "__main__":
    target = input("Enter the target domain or IP: ")
    results = enumerate_target(target)
    print("\nEnumeration Completed.\n")
    print(results)
