#!/usr/bin/env python3
# Host Response Checker v2.9 Final 
# By Killer-vpn | https://github.com/Nizwara

# ==========================
# SILENCE INSECURE REQUEST WARNINGS
# ==========================
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import ssl
import requests
import socket
import random
import os
import sys
import time
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================
# COLOR & LOGGING UTILS
# ==========================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_info(msg):
    print(f"{Colors.CYAN}[*] {msg}{Colors.ENDC}")

def print_success(msg):
    print(f"{Colors.GREEN}✅ {msg}{Colors.ENDC}")

def print_warning(msg):
    print(f"{Colors.YELLOW}⚠️  {msg}{Colors.ENDC}")

def print_error(msg):
    print(f"{Colors.RED}[!] {msg}{Colors.ENDC}")

# ==========================
# AUTO-INSTALL DEPENDENCIES (SEKALI SAJA)
# ==========================
DEPENDENCIES = [
    ("dnspython", "dns"),
    ("requests", "requests"),
    ("beautifulsoup4", "bs4")
]

INSTALL_MARKER = ".installed_deps"

def check_and_install_deps():
    if os.path.exists(INSTALL_MARKER):
        print_info("Dependencies already installed. Skipping installation.")
        return

    print_info("Checking required dependencies...")
    missing = []

    for pkg_name, mod_name in DEPENDENCIES:
        try:
            __import__(mod_name)
            print_info(f"✓ {pkg_name} is installed.")
        except ImportError:
            missing.append((pkg_name, mod_name))

    if not missing:
        open(INSTALL_MARKER, 'w').close()
        print_success("All dependencies satisfied!")
        return

    print_warning(f"Installing missing packages: {', '.join(p[0] for p in missing)}...")

    pip_commands = [
        [sys.executable, "-m", "pip", "install"] + [p[0] for p in missing],
        ["pip3", "install"] + [p[0] for p in missing],
        ["pip", "install"] + [p[0] for p in missing]
    ]

    success = False
    for cmd in pip_commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                success = True
                break
            else:
                print_warning(f"Command failed: {' '.join(cmd)}")
                print(result.stderr)
        except Exception as e:
            print_warning(f"Attempt failed: {e}")

    if success:
        open(INSTALL_MARKER, 'w').close()
        print_success("All dependencies installed successfully!")
    else:
        print_error("Failed to install dependencies. Please install manually:")
        for pkg, _ in missing:
            print(f"   pip3 install {pkg}")
        sys.exit(1)

# ==========================
# LOAD USER AGENTS FROM FILE
# ==========================
USER_AGENT_FILE = 'user-agents.txt'

def load_user_agents():
    default_uas = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
    ]

    if os.path.exists(USER_AGENT_FILE):
        try:
            with open(USER_AGENT_FILE, 'r', encoding='utf-8') as f:
                uas = [ua.strip() for ua in f.readlines() if ua.strip()]
                if uas:
                    print_info(f"Loaded {len(uas)} User-Agents from {USER_AGENT_FILE}")
                    return uas
                else:
                    print_warning(f"{USER_AGENT_FILE} is empty, using defaults.")
                    return default_uas
        except Exception as e:
            print_error(f"Failed to read {USER_AGENT_FILE}: {e}")
            return default_uas
    else:
        print_warning(f"{USER_AGENT_FILE} not found, using 4 default User-Agents.")
        return default_uas

USER_AGENTS = load_user_agents()

def get_random_user_agent():
    return random.choice(USER_AGENTS)

# ==========================
# IMPORT SETELAH AUTO-INSTALL
# ==========================
from bs4 import BeautifulSoup
import argparse

# ==========================
# MAIN SCAN CLASS
# ==========================

class HostResponse:
    def __init__(self, target, user_agent, proxy=None, timeout=5):
        self.target = target
        self.user_agent = user_agent
        self.proxy = proxy
        self.timeout = timeout
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        self.results = {}

    def get_dns_info(self, domain):
        dns_data = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_data[record_type] = [str(rdata) for rdata in answers]
            except:
                pass
        return dns_data

    def get_subdomains(self):
        subdomains = set()
        sources = [
            f'https://rapiddns.io/subdomain/{self.target}?full=1&down=0',
            f'https://crt.sh/?q=%.{self.target}&output=json',
        ]
        
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        
        for source in sources:
            try:
                headers = {'User-Agent': self.user_agent}
                response = requests.get(source, headers=headers, timeout=self.timeout, 
                                      verify=False, proxies=proxies)
                
                if response.status_code != 200:
                    continue
                
                # Handle RapidDNS "Bad Gateway"
                if 'rapiddns.io' in source and ("bad gateway" in response.text.lower() or "<h1>502</h1>" in response.text):
                    print_warning("RapidDNS returned 502 Bad Gateway — skipping this source.")
                    continue
                
                if 'crt.sh' in source:
                    try:
                        data = json.loads(response.text)
                        for item in data:
                            name_value = item['name_value'].lower().strip()
                            if '.' + self.target in name_value:
                                subdomains.add(name_value)
                    except Exception as e:
                        print_warning(f"Error parsing crt.sh JSON: {e}")
                        continue
                else:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    tbody = soup.find('tbody')
                    if tbody:
                        for tr in tbody.find_all('tr'):
                            td = tr.find('td')
                            if td:
                                subdomain = td.text.strip().lower()
                                if self.target in subdomain:
                                    subdomains.add(subdomain)
            except Exception as e:
                continue
        
        return list(subdomains)

    def check_server_header(self, url):
        try:
            headers = {
                'User-Agent': self.user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
            
            response = requests.get(url, headers=headers, timeout=self.timeout, 
                                  verify=False, allow_redirects=True, proxies=proxies)
            
            server_info = {
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'N/A'),
                'x-powered-by': response.headers.get('X-Powered-By', 'N/A'),
                'content-type': response.headers.get('Content-Type', 'N/A'),
                'x-frame-options': response.headers.get('X-Frame-Options', 'N/A'),
                'content-security-policy': response.headers.get('Content-Security-Policy', 'N/A'),
                'strict-transport-security': response.headers.get('Strict-Transport-Security', 'N/A'),
                'redirects': len(response.history),
                'final_url': response.url,
                'response_time': response.elapsed.total_seconds()
            }
            return server_info
        except Exception as e:
            return {'error': str(e)}

    def scan_ports(self, domain):
        open_ports = []
        
        try:
            ip_address = socket.gethostbyname(domain)
        except:
            return open_ports
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((ip_address, port))
                    if result == 0:
                        return port
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_port, port): port for port in self.common_ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return sorted(open_ports)

    def check_ssl_info(self, domain):
        ssl_info = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info['version'] = ssock.version()
                    ssl_info['cipher'] = ssock.cipher()[0]
                    
                    subject = {}
                    for item in cert['subject']:
                        for key, value in item:
                            subject[key] = value
                    ssl_info['subject'] = subject
                    
                    issuer = {}
                    for item in cert['issuer']:
                        for key, value in item:
                            issuer[key] = value
                    ssl_info['issuer'] = issuer
                    
                    ssl_info['not_before'] = cert['notBefore']
                    ssl_info['not_after'] = cert['notAfter']
                    
                    return ssl_info
        except:
            return {}

    def run_checks(self):
        result_data = {
            'target': self.target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'dns_info': {},
            'subdomains': [],
            'http_results': {},
            'open_ports': [],
            'ssl_info': {}
        }
        
        try:
            result_data['dns_info'] = self.get_dns_info(self.target)
        except:
            pass
        
        try:
            result_data['subdomains'] = self.get_subdomains()
        except Exception as e:
            result_data['subdomains_error'] = str(e)
        
        for protocol in ['https', 'http']:
            url = f"{protocol}://{self.target}"
            result_data['http_results'][protocol] = self.check_server_header(url)
        
        try:
            result_data['open_ports'] = self.scan_ports(self.target)
        except Exception as e:
            result_data['port_scan_error'] = str(e)
        
        try:
            result_data['ssl_info'] = self.check_ssl_info(self.target)
        except:
            pass
        
        return result_data

# ==========================
# FORMATTING & OUTPUT
# ==========================

def format_results_for_terminal(data):
    """Format output for TERMINAL — includes Subdomains Found (10 first + count)"""
    output = []
    output.append(f"\n[{data['timestamp']}] Results for: {data['target']}")
    output.append("=" * 60)
    
    if data['dns_info']:
        output.append("\nDNS Information:")
        for record_type, values in data['dns_info'].items():
            output.append(f"  {record_type}: {', '.join(values)}")
    
    if data['subdomains']:
        output.append(f"\nSubdomains Found ({len(data['subdomains'])}):")
        for subdomain in data['subdomains'][:10]:
            output.append(f"  {subdomain}")
        if len(data['subdomains']) > 10:
            output.append(f"  ... and {len(data['subdomains']) - 10} more")

    output.append("\nHTTP Results:")
    for protocol, result in data['http_results'].items():
        output.append(f"  {protocol.upper()}:")
        if 'error' in result:
            output.append(f"    Error: {result['error']}")
        else:
            output.append(f"    Status: {result.get('status_code', 'N/A')}")
            output.append(f"    Server: {result.get('server', 'N/A')}")
            output.append(f"    X-Powered-By: {result.get('x-powered-by', 'N/A')}")
            output.append(f"    Response Time: {result.get('response_time', 0):.2f}s")
            if result.get('redirects', 0) > 0:
                output.append(f"    Redirects: {result.get('redirects', 0)}")
                output.append(f"    Final URL: {result.get('final_url', 'N/A')}")

    if data['open_ports']:
        output.append(f"\nOpen Ports ({len(data['open_ports'])}): {', '.join(map(str, data['open_ports']))}")
    else:
        output.append("\nNo open ports found")

    if data['ssl_info']:
        output.append("\nSSL Information:")
        output.append(f"  Version: {data['ssl_info'].get('version', 'N/A')}")
        output.append(f"  Cipher: {data['ssl_info'].get('cipher', 'N/A')}")
        if 'subject' in data['ssl_info']:
            output.append(f"  Subject: {json.dumps(data['ssl_info']['subject'], indent=4)}")
        if 'issuer' in data['ssl_info']:
            output.append(f"  Issuer: {json.dumps(data['ssl_info']['issuer'], indent=4)}")
        output.append(f"  Valid From: {data['ssl_info'].get('not_before', 'N/A')}")
        output.append(f"  Valid To: {data['ssl_info'].get('not_after', 'N/A')}")

    output.append("=" * 60)
    return "\n".join(output)


def format_results_for_file(data):
    """Format output for FILE — NO 'Subdomains Found' header, only FULL LIST + LEGACY"""
    output = []
    output.append(f"\n[{data['timestamp']}] Results for: {data['target']}")
    output.append("=" * 60)
    
    if data['dns_info']:
        output.append("\nDNS Information:")
        for record_type, values in data['dns_info'].items():
            output.append(f"  {record_type}: {', '.join(values)}")

    # 👇 HANYA TAMPILKAN FULL LIST — TANPA "Subdomains Found (X):" DAN 10 PERTAMA
    if data['subdomains']:
        output.append("\n--- FULL SUBDOMAIN LIST (for file export) ---")
        for subdomain in data['subdomains']:
            output.append(f"  {subdomain}")
        output.append("--- END FULL LIST ---")

    output.append("\nHTTP Results:")
    for protocol, result in data['http_results'].items():
        output.append(f"  {protocol.upper()}:")
        if 'error' in result:
            output.append(f"    Error: {result['error']}")
        else:
            output.append(f"    Status: {result.get('status_code', 'N/A')}")
            output.append(f"    Server: {result.get('server', 'N/A')}")
            output.append(f"    X-Powered-By: {result.get('x-powered-by', 'N/A')}")
            output.append(f"    Response Time: {result.get('response_time', 0):.2f}s")
            if result.get('redirects', 0) > 0:
                output.append(f"    Redirects: {result.get('redirects', 0)}")
                output.append(f"    Final URL: {result.get('final_url', 'N/A')}")

    if data['open_ports']:
        output.append(f"\nOpen Ports ({len(data['open_ports'])}): {', '.join(map(str, data['open_ports']))}")
    else:
        output.append("\nNo open ports found")

    if data['ssl_info']:
        output.append("\nSSL Information:")
        output.append(f"  Version: {data['ssl_info'].get('version', 'N/A')}")
        output.append(f"  Cipher: {data['ssl_info'].get('cipher', 'N/A')}")
        if 'subject' in data['ssl_info']:
            output.append(f"  Subject: {json.dumps(data['ssl_info']['subject'], indent=4)}")
        if 'issuer' in data['ssl_info']:
            output.append(f"  Issuer: {json.dumps(data['ssl_info']['issuer'], indent=4)}")
        output.append(f"  Valid From: {data['ssl_info'].get('not_before', 'N/A')}")
        output.append(f"  Valid To: {data['ssl_info'].get('not_after', 'N/A')}")

    # 👇 LEGACY FORMAT — HANYA DI FILE
    output.append("\n--- LEGACY FORMAT (v1.0 style: subdomain|ip|status|server|ports|protocol|) ---")
    for subdomain in data['subdomains']:
        ip = "None"
        if 'A' in data['dns_info'] and data['dns_info']['A']:
            ip = data['dns_info']['A'][0]

        status = "None"
        if 'https' in data['http_results']:
            status = data['http_results']['https'].get('status_code', 'None')
        elif 'http' in data['http_results']:
            status = data['http_results']['http'].get('status_code', 'None')

        server = "None"
        if 'https' in data['http_results']:
            server = data['http_results']['https'].get('server', 'None')
        elif 'http' in data['http_results']:
            server = data['http_results']['http'].get('server', 'None')

        ports = "None"
        if data['open_ports']:
            ports = ','.join(map(str, data['open_ports']))

        protocol = "None"
        if data['ssl_info']:
            protocol = data['ssl_info'].get('version', 'None')

        legacy_line = f"{subdomain}|{ip}|{status}|{server}|{ports}|{protocol}|"
        output.append(f"  {legacy_line}")
    output.append("--- END LEGACY FORMAT ---")

    output.append("=" * 60)
    return "\n".join(output)


def save_results(data, filename):
    try:
        formatted = format_results_for_file(data)
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(formatted + "\n\n")
        return True
    except Exception as e:
        print_error(f"Error saving results: {e}")
        return False

# ==========================
# MAIN EXECUTION
# ==========================

def main():
    # ⚠️ INSTAL DEPENDENSI HANYA SEKALI SAAT PERTAMA KALI DIJALANKAN
    check_and_install_deps()

    parser = argparse.ArgumentParser(
        description='Host Response Checker v2.9.2 - No Warnings | Multi-Target | Clean Terminal | Full File Output',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-t', '--target', help='Target domain or IP (e.g., example.com)')
    parser.add_argument('-m', '--multi', metavar='', type=str, help='Multi target file (one domain per line)')
    parser.add_argument('-o', '--output', default='results.txt', help='Output file (default: results.txt)')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--no-banner', action='store_true', help='Hide banner')

    args = parser.parse_args()

    # Jika tidak ada -t atau -m, tampilkan help
    if not args.target and not args.multi:
        parser.print_help()
        sys.exit(1)

    if not args.no_banner:
        print(f"""
   __ __         __    ___                                
  / // /__  ___ / /_  / _ \___ ___ ___  ___  ___  ___ ___ 
 / _  / _ \(_-</ __/ / , _/ -_|_-</ _ \/ _ \/ _ \(_-</ -_)
/_//_/\___/___/\__/ /_/|_|\__/___/ .__/\___/_//_/___/\__/ 
                                /_/             V.2.9 FINAL
    
         By : Killer-vpn
         Github : github.com/Nizwara
         Blog : www.nizwara.biz.id
""")
        if args.target:
            print(f"{Colors.CYAN}[+] Target: {args.target}{Colors.ENDC}")
        if args.multi:
            print(f"{Colors.CYAN}[+] Multi-target file: {args.multi}{Colors.ENDC}")
        print(f"{Colors.CYAN}[+] Output: {args.output}{Colors.ENDC}")
        if args.proxy:
            print(f"{Colors.CYAN}[+] Proxy: {args.proxy}{Colors.ENDC}")
        print("-" * 60)

    user_agent = get_random_user_agent()
    print_info(f"Using User-Agent: {user_agent[:50]}...")

    if args.multi:
        try:
            with open(args.multi, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip()]
            if not targets:
                print_error(f"No valid targets found in {args.multi}")
                sys.exit(1)
            for target in targets:
                print_info(f"Starting scan for: {target}")
                host_checker = HostResponse(target, user_agent, args.proxy)
                result = host_checker.run_checks()
                print(format_results_for_terminal(result))
                save_results(result, args.output)
        except FileNotFoundError:
            print_error(f"File '{args.multi}' not found.")
            sys.exit(1)
    else:
        print_info(f"Starting scan for: {args.target}")
        host_checker = HostResponse(args.target, user_agent, args.proxy)
        result = host_checker.run_checks()
        print(format_results_for_terminal(result))
        save_results(result, args.output)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_error("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
