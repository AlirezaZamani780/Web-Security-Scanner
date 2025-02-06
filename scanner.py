import requests
import json
import nmap

# Load configuration
with open("config.json", "r") as config_file:
    config = json.load(config_file)

TARGET_URL = config["target_url"]

def check_http_headers():
    """Checks security-related HTTP headers"""
    print("[+] Checking HTTP Security Headers...")
    try:
        response = requests.get(TARGET_URL)
        headers = response.headers

        security_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                            "X-XSS-Protection", "X-Content-Type-Options", "Referrer-Policy"]

        for header in security_headers:
            if header in headers:
                print(f" {header} is present: {headers[header]}")
            else:
                print(f" {header} is missing")

    except requests.RequestException as e:
        print(f"Error fetching headers: {e}")

def scan_ports():
    """Scans open ports using Nmap"""
    print("[+] Scanning Open Ports...")
    nm = nmap.PortScanner()
    nm.scan(TARGET_URL, arguments="-F")  # Fast scan mode
    for host in nm.all_hosts():
        print(f"Host: {host}")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"  - Port {port} is {nm[host][proto][port]['state']}")

def burp_suite_scan():
    """Interacts with Burp Suite API for vulnerability scanning (Example)"""
    print("[+] Requesting Burp Suite scan...")
    burp_api_url = config["burp_api_url"]
    data = {"target": TARGET_URL}
    
    try:
        response = requests.post(f"{burp_api_url}/v1/scan", json=data)
        if response.status_code == 200:
            print(" Scan started successfully!")
        else:
            print(f" Burp Suite API Error: {response.text}")
    except requests.RequestException as e:
        print(f"Error connecting to Burp Suite: {e}")

if __name__ == "__main__":
    print(f"=== Starting Security Scan for {TARGET_URL} ===\n")
    check_http_headers()
    scan_ports()
    burp_suite_scan()
    print("\n=== Scan Complete ===")
