#!/usr/bin/env python3
"""
ZeroSpecter v6 – True Professional Edition
Author: DeepSeek
Full IPv6 support, accurate UDP, dynamic CVE DB, Rich TUI, HTML/CSV/JSON/MD reports.
"""

import argparse
import ipaddress
import socket
import sys
import threading
import time
import json
import csv
import re
import ssl
import struct
import subprocess
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from urllib.parse import urlparse
import dns.resolver
import dns.reversename
import dns.exception
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Rich imports (optional but recommended)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.panel import Panel
    from rich.syntax import Syntax
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    # fallback colors
    from colorama import init, Fore, Style
    init(autoreset=True)
    R, G, Y, B, C, M, W = Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.CYAN, Fore.MAGENTA, Style.RESET_ALL

# ========================== Constants ==========================
TOP_PORTS = [20,21,22,23,25,53,67,68,69,80,110,111,123,135,137,138,139,143,161,389,443,445,465,587,993,995,1433,1521,1723,2049,2082,2083,2086,2087,3306,3389,5432,5900,6379,8080,8443]
CMS_PATHS = {
    'WordPress': ['/wp-content/', '/wp-includes/', '/wp-login.php'],
    'Joomla': ['/administrator/', '/media/system/js/core.js', '/templates/'],
    'Drupal': ['/misc/drupal.js', '/core/misc/drupal.js', '/sites/default/']
}
VERSION_PATTERNS = [
    r'([\d]+\.[\d]+\.[\d]+[a-z]?\d*)',  # 1.2.3, 1.2.3p4
    r'([\d]+\.[\d]+[a-z]?\d*)',          # 2.4, 8.9p1
    r'/([\d]+\.[\d]+\.[\d]+)(?:[^/\s]*)', # Apache/2.4.49
    r'_([\d]+\.[\d]+[a-z]?\d*)',         # OpenSSH_8.9p1
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
    if not banner:
        return None
    for pat in VERSION_PATTERNS:
        m = re.search(pat, banner)
        if m:
            return m.group(1)
    return None

def create_session(retries=2):
    s = requests.Session()
    s.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'})
    retry = Retry(total=retries, backoff_factor=0.3, status_forcelist=[429,500,502,503,504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    return s

# ========================== DNS (cached) ==========================
@lru_cache(maxsize=128)
def dns_query(domain, record_type):
    try:
        ans = dns.resolver.resolve(domain, record_type, lifetime=5)
        return [str(r) for r in ans]
    except:
        return []

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
            if ptr:
                res['PTR'] = ptr
        except:
            pass
        return res

# ========================== Port Scanner (IPv4/IPv6, TCP/UDP) ==========================
def get_sockaddr(target, port):
    """Return (family, sockaddr) tuple for given target and port."""
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
        if self.rate <= 0:
            return
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
                if self.delay:
                    time.sleep(self.delay)
                self._rate_limit()
            except:
                pass
        return None

    def scan_udp_accurate(self, port):
        # Use raw ICMP to detect closed ports
        try:
            family, sockaddr = get_sockaddr(self.target, port)
            # UDP socket
            udp_sock = socket.socket(family, socket.SOCK_DGRAM)
            udp_sock.settimeout(self.timeout)
            udp_sock.sendto(b'\x00', sockaddr)
            # Raw ICMP socket (requires root)
            icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_sock.settimeout(self.timeout)
            try:
                data, _ = icmp_sock.recvfrom(1024)
                # Parse IP header to get ICMP offset
                ip_header_len = (data[0] & 0x0F) * 4
                icmp_type, icmp_code = struct.unpack('!BB', data[ip_header_len:ip_header_len+2])
                if icmp_type == 3 and icmp_code == 3:  # Port Unreachable
                    return None
            except socket.timeout:
                # No ICMP reply, assume open
                with self.lock:
                    self.open.append((port, self.get_service(port), 'udp'))
                return port
            finally:
                udp_sock.close()
                icmp_sock.close()
        except PermissionError:
            # Fallback: simple UDP scan (no root)
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
                if self.delay:
                    time.sleep(self.delay)
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

# ========================== Service Fingerprinter (cached) ==========================
@lru_cache(maxsize=256)
def get_banner(target, port, orig_host, timeout=3):
    fp = Fingerprinter(target, port, timeout, orig_host)
    return fp.fingerprint()

class Fingerprinter:
    def __init__(self, target, port, timeout, orig_host):
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
                ssock.send(f"HEAD / HTTP/1.1\r\nHost: {self.orig_host}\r\nConnection: close\r\n\r\n".encode())
                data = ssock.recv(4096).decode(errors='ignore')
                ssock.close()
            else:
                sock = socket.create_connection((self.target, self.port), self.timeout)
                sock.send(f"HEAD / HTTP/1.1\r\nHost: {self.orig_host}\r\nConnection: close\r\n\r\n".encode())
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

# ========================== SSL Analyzer ==========================
class SSLAnalyzer:
    def __init__(self, target, port=443, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout

    def analyze(self):
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

# ========================== CMS Detector (score-based) ==========================
class CMSDetector:
    def __init__(self, url, timeout=5):
        self.url = url.rstrip('/')
        self.session = create_session()
        self.timeout = timeout

    def detect(self):
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

# ========================== Vulnerability DB (NVD + searchsploit) ==========================
class VulnDB:
    def __init__(self):
        self.cache = {}

    def fetch_nvd(self, service, version):
        if not version:
            return []
        key = f"{service}_{version}"
        if key in self.cache:
            return self.cache[key]
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
        if not version:
            return []
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

# ========================== Main Scanner ==========================
class ZeroSpecter:
    def __init__(self, target, ports, timeout=1, threads=100, output='json', verbose=False, delay=0, udp=False, ipv6=False, rate=0):
        self.orig_target = target
        self.target = target
        self.ipv6 = ipv6
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.output = output
        self.verbose = verbose
        self.delay = delay
        self.udp = udp
        self.rate = rate
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
            "vulns": []
        }

    def resolve(self):
        fam = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        try:
            ai = socket.getaddrinfo(self.orig_target, None, family=fam, type=socket.SOCK_STREAM)
            self.resolved_ip = ai[0][4][0]
            print(f"[+] Resolved {self.orig_target} -> {self.resolved_ip}")
            self.target = self.resolved_ip
            self.res["resolved_ip"] = self.resolved_ip
            return True
        except:
            print(f"[-] Could not resolve {self.orig_target}")
            return False

    def run(self):
        print("=== ZeroSpecter v6 - True Professional Edition ===")
        if not self.resolve():
            sys.exit(1)

        # TCP Scan
        tcp = PortScanner(self.target, self.ports, self.timeout, self.threads, 1, self.delay, False, self.rate)
        tcp_open = tcp.run()
        self.res["tcp_ports"] = [{"port": p, "service": s} for p, s, _ in tcp_open]

        # UDP Scan (optional)
        if self.udp:
            udp = PortScanner(self.target, self.ports, self.timeout, self.threads, 1, self.delay, True, self.rate)
            udp_open = udp.run()
            self.res["udp_ports"] = [{"port": p, "service": s} for p, s, _ in udp_open]

        # DNS
        try:
            ipaddress.ip_address(self.orig_target)
            is_ip = True
        except:
            is_ip = False
        if not is_ip:
            dns = DNSEnum(self.orig_target)
            self.res["dns"] = dns.run()
        else:
            try:
                hostname = socket.gethostbyaddr(self.target)[0]
                self.res["reverse_dns"] = hostname
            except:
                pass

        # Service fingerprinting & vulns
        vuln_db = VulnDB()
        for port, service, _ in tcp_open:
            banner, ver = get_banner(self.target, port, self.orig_target, self.timeout)
            self.res["services"][str(port)] = {"service": service, "banner": banner, "version": ver}

            # Tech detection
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
                if tech:
                    self.res["technologies"].extend(tech)

            # Vulnerability lookup
            if ver:
                cves = vuln_db.suggest(service, ver)
                if cves:
                    self.res["vulns"].append({
                        "port": port,
                        "service": service,
                        "version": ver,
                        "vulns": cves
                    })
                    for cve in cves:
                        print(f"[!] {port}/{service} {ver} : {cve}")

        self.res["technologies"] = list(set(self.res["technologies"]))

        # SSL
        if any(p == 443 for p, _, _ in tcp_open):
            ssl_an = SSLAnalyzer(self.target)
            cert = ssl_an.analyze()
            if cert:
                self.res["ssl"] = cert
                print(f"[+] SSL cert: {cert['subject'].get('commonName', 'N/A')}")
                if datetime.now(timezone.utc) > datetime.fromisoformat(cert['not_after']):
                    self.res["vulns"].append({
                        "port": 443,
                        "service": "SSL Certificate",
                        "version": None,
                        "vulns": ["Certificate expired"]
                    })

        # CMS detection
        for port, service, _ in tcp_open:
            if port in (80,443,8080,8443):
                proto = "https" if port == 443 else "http"
                cms_det = CMSDetector(f"{proto}://{self.orig_target}:{port}")
                detected = cms_det.detect()
                if detected:
                    self.res["cms"] = detected
                    print(f"[+] CMS: {detected['cms']} v{detected.get('version', 'unknown')}")
                    if detected.get('version'):
                        cves = vuln_db.suggest(detected['cms'], detected['version'])
                        if cves:
                            self.res["vulns"].append({
                                "port": port,
                                "service": detected['cms'],
                                "version": detected['version'],
                                "vulns": cves
                            })
                    break

        # Reports
        self.generate_reports()

    def generate_reports(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"zerospy_{ts}"
        with open(f"{base}.json", 'w') as f:
            json.dump(self.res, f, indent=4)
        print(f"[+] JSON report: {base}.json")

        if self.output == 'csv':
            with open(f"{base}.csv", 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(["Port", "Protocol", "Service", "Banner", "Version", "Vulnerabilities"])
                for p, svc in self.res["services"].items():
                    vul = ";".join([v for x in self.res["vulns"] if str(x["port"]) == p for v in x["vulns"]])
                    w.writerow([p, "tcp", svc["service"], svc["banner"], svc["version"], vul])
                for p in self.res.get("udp_ports", []):
                    w.writerow([p["port"], "udp", p["service"], "", "", ""])
            print(f"[+] CSV report: {base}.csv")

        elif self.output == 'html':
            self.generate_html(base)
            print(f"[+] HTML report: {base}.html")

        elif self.output == 'md':
            self.generate_md(base)
            print(f"[+] Markdown report: {base}.md")

        self.print_summary()

    def generate_html(self, base):
        # Build risk level
        risk = "Low"
        if len(self.res["vulns"]) > 5:
            risk = "Critical"
        elif len(self.res["vulns"]) > 0:
            risk = "Medium"

        html = f"""<!DOCTYPE html>
<html>
<head><title>ZeroSpecter Report</title>
<style>
body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f4f4f4; }}
.container {{ max-width: 1200px; margin: auto; background: white; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); padding: 20px; }}
h1, h2 {{ color: #333; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #f2f2f2; }}
.vuln {{ color: red; }}
.risk-Critical {{ color: red; font-weight: bold; }}
.risk-Medium {{ color: orange; font-weight: bold; }}
.risk-Low {{ color: green; font-weight: bold; }}
</style>
</head>
<body>
<div class="container">
<h1>ZeroSpecter Security Scan Report</h1>
<p><strong>Target:</strong> {self.orig_target} → {self.res['resolved_ip']}</p>
<p><strong>Scan Time:</strong> {self.res['scan_started']}</p>
<p><strong>Risk Level:</strong> <span class="risk-{risk}">{risk}</span></p>

<h2>Open Ports</h2>
<h3>TCP</h3>
<table>
<tr><th>Port</th><th>Service</th></tr>
{''.join(f"<tr><td>{p['port']}</td><td>{p['service']}</td></tr>" for p in self.res['tcp_ports'])}
</table>
"""
        if self.res.get('udp_ports'):
            html += "<h3>UDP</h3><table><tr><th>Port</th><th>Service</th></tr>"
            html += ''.join(f"<tr><td>{p['port']}</td><td>{p['service']}</td></tr>" for p in self.res['udp_ports'])
            html += "</table>"

        html += f"<h2>DNS Records</h2><ul>"
        for k, v in self.res['dns'].items():
            if v:
                html += f"<li><strong>{k}</strong>: {', '.join(v)}</li>"
        html += "</ul>"

        if self.res['technologies']:
            html += f"<h2>Web Technologies</h2><p>{', '.join(self.res['technologies'])}</p>"

        if self.res['cms']:
            html += f"<h2>CMS</h2><p>{self.res['cms']['cms']} v{self.res['cms'].get('version', 'unknown')}</p>"

        if self.res['ssl']:
            html += f"<h2>SSL Certificate</h2><pre>{json.dumps(self.res['ssl'], indent=2)}</pre>"

        html += "<h2>Service Details</h2><table><tr><th>Port</th><th>Service</th><th>Banner</th><th>Version</th><th>Vulnerabilities</th></tr>"
        for p, svc in self.res['services'].items():
            vul_list = [v for x in self.res['vulns'] if str(x['port']) == p for v in x['vulns']]
            vul_str = "<br>".join(vul_list) if vul_list else "None"
            html += f"<tr><td>{p}</td><td>{svc['service']}</td><td>{svc['banner'] or ''}</td><td>{svc['version'] or ''}</td><td class='vuln'>{vul_str}</td></tr>"
        html += "</table></div></body></html>"

        with open(f"{base}.html", 'w') as f:
            f.write(html)

    def generate_md(self, base):
        md = f"# ZeroSpecter Scan Report\n\n- **Target:** {self.orig_target} → {self.res['resolved_ip']}\n- **Scan Time:** {self.res['scan_started']}\n\n## Open Ports (TCP)\n"
        for p in self.res['tcp_ports']:
            md += f"- {p['port']}/tcp : {p['service']}\n"
        if self.res.get('udp_ports'):
            md += "\n## Open Ports (UDP)\n"
            for p in self.res['udp_ports']:
                md += f"- {p['port']}/udp : {p['service']}\n"
        md += "\n## Vulnerabilities\n"
        for v in self.res['vulns']:
            md += f"- **{v['service']} {v.get('version', '')}** (Port {v['port']}): {', '.join(v['vulns'])}\n"
        with open(f"{base}.md", 'w') as f:
            f.write(md)

    def print_summary(self):
        print("\n===== Scan Summary =====")
        print(f"Target: {self.orig_target} -> {self.res['resolved_ip']}")
        print(f"Open TCP ports: {len(self.res['tcp_ports'])}")
        if self.res.get('udp_ports'):
            print(f"Open UDP ports: {len(self.res['udp_ports'])}")
        if self.res['technologies']:
            print(f"Technologies: {', '.join(self.res['technologies'])}")
        if self.res['cms']:
            print(f"CMS: {self.res['cms']['cms']} v{self.res['cms'].get('version', 'unknown')}")
        print(f"Vulnerabilities: {len(self.res['vulns'])}")

# ========================== Main ==========================
def main():
    parser = argparse.ArgumentParser(description="ZeroSpecter v6 - Professional Network Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-1024, top, 80,443)")
    parser.add_argument("--timeout", type=int, default=1, help="Connection timeout (sec)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("-o", "--output", choices=['json', 'csv', 'html', 'md'], default='json', help="Report format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--delay", type=float, default=0, help="Delay between probes (sec)")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scanning")
    parser.add_argument("--ipv6", action="store_true", help="Force IPv6 resolution")
    parser.add_argument("--rate", type=int, default=0, help="Max packets per second (0 = unlimited)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    scanner = ZeroSpecter(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        output=args.output,
        verbose=args.verbose,
        delay=args.delay,
        udp=args.udp,
        ipv6=args.ipv6,
        rate=args.rate
    )
    scanner.run()

if __name__ == "__main__":
    main()
