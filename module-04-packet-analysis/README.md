# Module 04 — Packet Analysis with Wireshark & Scapy

> **Prerequisites:** [Module 03 — Wireless Reconnaissance](../module-03-reconnaissance/)
> **Next Module:** [Module 05 — WEP Cracking](../module-05-wep-cracking/)

---

## Table of Contents

1. [Why Packet Analysis Matters](#1-why-packet-analysis-matters)
2. [Wireshark Setup for Wireless](#2-wireshark-setup-for-wireless)
3. [802.11 Frame Types & Subtypes](#3-80211-frame-types--subtypes)
4. [Essential Wireshark Display Filters](#4-essential-wireshark-display-filters)
5. [Analyzing Beacon Frames & RSN IE](#5-analyzing-beacon-frames--rsn-ie)
6. [Probe Request / Response Analysis](#6-probe-request--response-analysis)
7. [WPA2 4-Way Handshake Deep Dive](#7-wpa2-4-way-handshake-deep-dive)
8. [EAPOL Key Information Field Decoder](#8-eapol-key-information-field-decoder)
9. [CCMP Header Analysis](#9-ccmp-header-analysis)
10. [Decrypting WPA2 Traffic in Wireshark](#10-decrypting-wpa2-traffic-in-wireshark)
11. [airdecap-ng — Offline Decryption](#11-airdecap-ng--offline-decryption)
12. [tshark Command-Line Analysis](#12-tshark-command-line-analysis)
13. [Scapy — Sniffing, Filtering & Crafting Frames](#13-scapy--sniffing-filtering--crafting-frames)
14. [Common Packet Patterns Reference](#14-common-packet-patterns-reference)
15. [Troubleshooting Capture Issues](#15-troubleshooting-capture-issues)
16. [Knowledge Check](#16-knowledge-check)

---

## 1. Why Packet Analysis Matters

Every attack in this course leaves a trace at the frame level. Packet analysis lets you:

- **Verify captures** — Confirm all 4 EAPOL handshake messages were captured
- **Diagnose failures** — Was the deauth frame received? Did the client reconnect?
- **Understand protocols** — See exactly what happens during WPA2 authentication
- **Detect defenses** — Identify 802.11w PMF, RADIUS, and anomaly detection
- **Craft payloads** — Know the exact byte layout before injecting

---

## 2. Wireshark Setup for Wireless

### Starting Wireshark

```bash
# Open directly on monitor interface (starts capture immediately)
sudo wireshark -i wlan0mon -k

# Open existing capture file
wireshark capture-01.cap

# tshark (command-line) on live interface
sudo tshark -i wlan0mon
```

### Critical Preferences for 802.11 Captures

**1. FCS (Frame Check Sequence) Setting**
```
Edit → Preferences → Protocols → IEEE 802.11
  ✓ Assume packets have FCS
```
Most drivers include the FCS in captures. Without this setting, Wireshark misidentifies the last 4 bytes of the frame body as FCS and shows "Malformed packet" errors.

**2. Ignore WEP/TKIP MIC Errors**
```
Edit → Preferences → Protocols → IEEE 802.11
  ✓ Ignore the protection bit
```
Allows viewing decrypted frame structure even when the MIC doesn't validate.

**3. Add WPA2 Decryption Keys**
```
Edit → Preferences → Protocols → IEEE 802.11
  → Decryption keys → Edit
  → + Add key
  Key type: wpa-pwd
  Key:      password:SSID   (e.g., "Password1!:HomeNet")
  OR
  Key type: wpa-psk
  Key:      <64-char PMK hex>
```
With the correct PSK, Wireshark will **automatically decrypt all WPA2 data frames** in the capture if the 4-way handshake is present.

**4. Colorization Rules (Recommended)**
```
View → Coloring Rules
  Add rule: "EAPOL"    → orange background  (handshake frames)
  Add rule: "wlan.fc.subtype == 12" → red (deauth frames)
  Add rule: "wlan.fc.subtype == 8" → blue  (beacons)
```

---

## 3. 802.11 Frame Types & Subtypes

### Frame Type Field (bits 2-3 of Frame Control)

| Type Value | Category | Use Case |
|-----------|----------|----------|
| `0b00` (0) | **Management** | Network setup: Beacon, Probe, Auth, Assoc, Deauth |
| `0b01` (1) | **Control** | Medium access: ACK, RTS, CTS, Block-ACK |
| `0b10` (2) | **Data** | Payload delivery: encrypted/cleartext IP packets |
| `0b11` (3) | Extension | 802.11ax DMG/EDMG (rare) |

### Management Frame Subtypes (Type 0)

| Decimal | Hex | Frame Name | Attack Relevance |
|---------|-----|------------|-----------------|
| 0 | 0x00 | Association Request | Client → AP: contains SSID, RSN IE |
| 1 | 0x01 | Association Response | AP accepts/rejects |
| 2 | 0x02 | Reassociation Request | Roaming — reveals SSID |
| 4 | 0x04 | **Probe Request** | **PNL leakage — KARMA attack target** |
| 5 | 0x05 | Probe Response | AP responds to probe |
| 8 | 0x08 | **Beacon** | **Primary AP advertisement — RSN IE here** |
| 10 | 0x0A | Disassociation | Drops client to State 2 |
| 11 | 0x0B | Authentication | State 1→2 transition |
| 12 | 0x0C | **Deauthentication** | **The deauth attack vector — drops to State 1** |
| 13 | 0x0D | Action | Block-ACK negotiation, channel switch |

### Wireshark `type_subtype` Combined Filter

The `wlan.fc.type_subtype` field combines type and subtype into a single 8-bit value:

```
type_subtype = (type << 4) | subtype
```

| type_subtype | Decimal | Frame |
|-------------|---------|-------|
| `0x08` | 8 | Beacon |
| `0x04` | 4 | Probe Request |
| `0x05` | 5 | Probe Response |
| `0x0B` | 11 | Authentication |
| `0x0C` | 12 | Deauthentication |
| `0x00` | 0 | Association Request |
| `0x08` (data) | 32 | Data |
| `0x28` | 40 | QoS Data |

```wireshark
# Clean single-field filter (preferred over type+subtype combination)
wlan.fc.type_subtype == 8    # Beacon
wlan.fc.type_subtype == 4    # Probe Request
wlan.fc.type_subtype == 12   # Deauthentication
```

---

## 4. Essential Wireshark Display Filters

### Frame Type Filters

```wireshark
# Management frames (all subtypes)
wlan.fc.type == 0

# Control frames
wlan.fc.type == 1

# Data frames
wlan.fc.type == 2
```

### Specific Frame Subtype Filters

```wireshark
# Beacon frames
wlan.fc.type_subtype == 8

# Probe Requests (PNL leakage)
wlan.fc.type_subtype == 4

# Probe Responses
wlan.fc.type_subtype == 5

# Deauthentication (deauth attack)
wlan.fc.type_subtype == 12

# Disassociation
wlan.fc.type_subtype == 10

# Authentication frames
wlan.fc.type_subtype == 11

# Association Request
wlan.fc.type_subtype == 0

# WPA2 4-way handshake
eapol
```

### Address Filters

```wireshark
# Filter by AP BSSID (all frames to/from AP)
wlan.bssid == aa:bb:cc:dd:ee:ff

# Filter by any MAC address (source OR destination)
wlan.addr == 11:22:33:44:55:66

# Filter by transmitter (source MAC)
wlan.ta == 11:22:33:44:55:66

# Filter by receiver (destination MAC)
wlan.ra == ff:ff:ff:ff:ff:ff

# Filter by SSID name
wlan.ssid == "HomeNet"
```

### Encryption & Security Filters

```wireshark
# Encrypted frames (Protected bit = 1)
wlan.fc.protected == 1

# Unencrypted data (Protected bit = 0 on data frame = interesting!)
wlan.fc.type == 2 && wlan.fc.protected == 0

# Retransmitted frames (useful for diagnosing injection issues)
wlan.fc.retry == 1

# Frames with PMF (Management Frame Protection)
# PMF-protected deauths will have Protected=1
wlan.fc.type_subtype == 12 && wlan.fc.protected == 1
```

### Compound Filters

```wireshark
# Beacons from specific AP
wlan.fc.type_subtype == 8 && wlan.bssid == aa:bb:cc:dd:ee:ff

# Probe Requests from specific client
wlan.fc.type_subtype == 4 && wlan.sa == 11:22:33:44:55:66

# Deauth frames (both sent and received by AP)
wlan.fc.type_subtype == 12 && (wlan.sa == aa:bb:cc:dd:ee:ff || wlan.da == aa:bb:cc:dd:ee:ff)

# All 4-way handshake frames between AP and client
eapol && wlan.bssid == aa:bb:cc:dd:ee:ff

# Data frames showing TKIP (vulnerable to injection)
wlan.fc.type == 2 && wlan.wep.icv
```

---

## 5. Analyzing Beacon Frames & RSN IE

### Beacon Frame Structure

```
Frame Control: Type=0 (Mgmt) Subtype=8 (Beacon)
Destination:   ff:ff:ff:ff:ff:ff  (broadcast)
Source (BSSID): aa:bb:cc:dd:ee:ff

Fixed Fields:
  Timestamp:        8 bytes (microseconds since AP started)
  Beacon Interval:  0x0064 = 100 TU = 102.4 ms
  Capabilities:     0x0431

Tagged Parameters (Information Elements):
  ID 0:  SSID = "HomeNet"
  ID 1:  Supported Rates: 1,2,5.5,11,6,9,12,18 Mbps
  ID 3:  DS Parameter Set: Channel 6
  ID 48: RSN Information Element ← CRITICAL for security analysis
  ID 50: Extended Supported Rates: 24,36,48,54 Mbps
  ID 45: HT Capabilities (802.11n)
  ID 61: HT Operation
  ID 221: Vendor Specific (WPA, WPS)
```

### RSN IE in Wireshark — Full Field Breakdown

In the packet tree, expand:
```
IEEE 802.11 Wireless Management
  └── Tagged parameters
       └── Tag: RSN Information (Tag Number: 48)
            ├── Tag Number: 48
            ├── Tag length: [N]
            ├── RSN Version: 1
            ├── Group Cipher Suite: 00:0f:ac (Ieee8021) CCMP-128 (0x04)
            │    → 00:0f:ac:04 = AES/CCMP — WPA2 grade cipher
            │    → 00:0f:ac:02 = TKIP — weak, WPA1 grade
            │    → 00:0f:ac:06 = GCMP-128 — WPA3
            ├── Pairwise Cipher Suite Count: 1
            ├── Pairwise Cipher Suite List: 00:0f:ac (CCMP-128)
            ├── Auth Key Management (AKM) Suite Count: 1
            ├── Auth Key Management List: 00:0f:ac (PSK)  ← or 802.1X for Enterprise
            └── RSN Capabilities: 0x000c
                 ├── Bit 6: Pre-Auth capable (0)
                 ├── Bit 7: No Pairwise (0)
                 ├── Bit 8-9: PTKSA Replay Counter: 1
                 ├── Bit 10-11: GTKSA Replay Counter: 1
                 ├── Bit 12: Management Frame Protection Required (MFP Req)
                 └── Bit 13: Management Frame Protection Capable (MFP Cap)
```

**Reading cipher suites:** The OUI `00:0f:ac` = IEEE 802.11 standard suite. The last byte is the selector:
- `:02` = TKIP (weak)
- `:04` = CCMP-128 / AES (strong)
- `:06` = GCMP-128 (WPA3)
- `:08` = GCMP-256 (WPA3-192)

**Reading AKM suites:**
- `00:0f:ac:01` = 802.1X (Enterprise)
- `00:0f:ac:02` = PSK (WPA2-Personal)
- `00:0f:ac:06` = SAE (WPA3-Personal)

---

## 6. Probe Request / Response Analysis

### Probe Request Structure

```
Frame Control: Subtype=4 (Probe Request)
Destination:   ff:ff:ff:ff:ff:ff (broadcast)
Source:        11:22:33:44:55:66 (client MAC)
BSSID:         ff:ff:ff:ff:ff:ff (broadcast)

Tagged Parameters:
  ID 0:  SSID = "HomeWiFi"  ← the PNL leakage — network client is looking for
  ID 1:  Supported Rates
  ID 45: HT Capabilities   ← fingerprints device as 802.11n capable
  ID 127: Extended Capabilities
  ID 107: Interworking      ← fingerprints 802.11u (Hotspot 2.0) support
```

### Extracting PNL from Wireshark

```wireshark
# Filter probe requests with non-empty SSID (directed probes = PNL disclosure)
wlan.fc.type_subtype == 4 && wlan.ssid != ""

# For each frame, look at: wlan.ssid → the SSID the client is looking for
# Collect all unique SSIDs per client MAC = complete PNL
```

### Null SSID Probe Requests (Broadcast Probes)

```wireshark
# Wildcard probes (no specific SSID — passive scan mode)
wlan.fc.type_subtype == 4 && wlan.ssid == ""
```

Broadcast probes don't disclose PNL but are still used to detect clients' presence and supported capabilities.

---

## 7. WPA2 4-Way Handshake Deep Dive

### The Four EAPOL Messages

The complete handshake in Wireshark (`eapol` filter):

```
Frame  Direction  Key Info   Contents                       Min for Cracking?
──────────────────────────────────────────────────────────────────────────────
  M1   AP→Client  0x008a     ANonce (Authenticator Nonce)   No (no MIC yet)
  M2   Client→AP  0x010a     SNonce + MIC ← CRITICAL        YES: M1+M2 sufficient
  M3   AP→Client  0x13ca     ANonce + encrypted GTK + MIC   Confirms crackability
  M4   Client→AP  0x030a     ACK + MIC                      Not needed for cracking
```

**Minimum requirement for offline cracking:** Messages 1 and 2 (or 2 and 3). Message 2 contains the SNonce and MIC — which allows an attacker to brute-force the PMK by recomputing the PTK and verifying the MIC.

### EAPOL Frame Breakdown in Wireshark

```
IEEE 802.1X Authentication
  ├── Version: 1 (or 2 for EAPOL-Key frames)
  ├── Type: 3 (Key)
  └── EAPOL-Key
       ├── Key Descriptor Type: 2 (RSN)
       ├── Key Information: 0x010a   ← decode this (Section 8)
       ├── Key Length: 16
       ├── Replay Counter: 1         ← detects replayed handshakes
       ├── Key Nonce: [32 bytes]     ← SNonce (M2) or ANonce (M1,M3)
       ├── Key IV: [all zeros for M1/M2/M4]
       ├── Key RSC: [all zeros]
       ├── Key MIC: [16 bytes]       ← HMAC-SHA1 over EAPOL frame using KCK
       └── Key Data: [variable]      ← encrypted GTK in M3; RSN IE in M2
```

### Verifying Handshake Quality

```bash
# Method 1: aircrack-ng
aircrack-ng capture-01.cap
# Output: "WPA2 (1) handshake" = valid capture

# Method 2: tshark EAPOL message number check
tshark -r capture-01.cap -Y "eapol" \
  -T fields -e eapol.keydes.msgnr -e wlan.sa | sort
# Should see messages 1,2,3,4 (or at minimum 1,2)

# Method 3: hcxpcapngtool verification
hcxpcapngtool --info capture-01.cap
# Shows exact count of M1/M2/M3/M4 pairs and PMKIDs found
```

---

## 8. EAPOL Key Information Field Decoder

The **Key Information** field (2 bytes) in EAPOL-Key frames is a bitmask encoding the message type and required processing. Understanding it lets you identify which handshake message you're looking at directly from the hex value.

```
Key Information Field Bit Layout (16 bits):
Bits:  15  14  13  12  11  10   9   8   7   6   5   4  3-0
       └── Key Descriptor Version ──┘ │   │   │   │   │   │
                                      │   │   │   │   │   └── Reserved
                                      │   │   │   │   └────── Install (Key)
                                      │   │   │   └────────── Key Ack (AP confirms PTK)
                                      │   │   └────────────── Key MIC (frame has MIC)
                                      │   └────────────────── Secure (GTK installed)
                                      └────────────────────── Error / Request
```

### Decoding the Four Messages

| Message | Key Info (hex) | Key Info (bin) | What It Means |
|---------|---------------|----------------|---------------|
| **M1** (AP→Client) | `0x008a` | `0000 0000 1000 1010` | Key Ack=1, MIC=0 → AP sending ANonce, no MIC yet |
| **M2** (Client→AP) | `0x010a` | `0000 0001 0000 1010` | Key MIC=1, Secure=0 → Client sending SNonce with MIC |
| **M3** (AP→Client) | `0x13ca` | `0001 0011 1100 1010` | Install=1, Key Ack=1, MIC=1, Secure=1 → AP sends GTK |
| **M4** (Client→AP) | `0x030a` | `0000 0011 0000 1010` | Key MIC=1, Secure=1 → Final confirmation |

### Wireshark Key Information Expansion

In Wireshark, expanding the EAPOL-Key frame shows:
```
Key Information: 0x010a
  .... .... .... .010 = Key Descriptor Version: AES Cipher, HMAC-SHA1 MIC (2)
  .... .... .... 0... = Install: Not set
  .... .... ...0 .... = Key ACK: Not set
  .... .... ..1. .... = Key MIC: Set ← means this frame has a valid MIC
  .... .... .0.. .... = Secure: Not set
  .... .... 0... .... = Error: Not set
  .... ...0 .... .... = Request: Not set
  .... ..0. .... .... = Encrypted Key Data: Not set
  .... .0.. .... .... = SMK Message: Not set
```

**Key Descriptor Version** (bits 0-2):
- `001` = HMAC-MD5 / RC4 (deprecated WPA-TKIP)
- `010` = HMAC-SHA1-128 / AES (WPA2-CCMP) ← most common
- `011` = AES-128-CMAC (WPA3-SAE)

---

## 9. CCMP Header Analysis

When a WPA2 data frame is encrypted with CCMP (AES), it has a special 8-byte header between the 802.11 MAC header and the encrypted payload.

### CCMP Header Structure

```
CCMP Header (8 bytes)
Offset  Field         Size  Description
──────────────────────────────────────────────────────
  0     PN0           1     Packet Number byte 0 (lowest)
  1     PN1           1     Packet Number byte 1
  2     Reserved      1     Always 0x00
  3     Key ID + Ext  1     Bits 4-5: key ID (0=PTK, 1-3=GTK); bit 5: ExtIV=1
  4     PN2           1     Packet Number byte 2
  5     PN3           1     Packet Number byte 3
  6     PN4           1     Packet Number byte 4
  7     PN5           1     Packet Number byte 5 (highest)
```

**The 48-bit Packet Number (PN0–PN5)** is the CCMP replay counter. It increments with every encrypted frame. If a receiver sees a PN that is not strictly greater than the previous, it discards the frame as a replay.

**Why this matters for attacks:**
- In KRACK (CVE-2017-13077), replaying EAPOL M3 causes the **receiver to reset PN to 0**, enabling nonce reuse
- Nonce reuse in CCMP breaks confidentiality — the same keystream can be used twice → XOR the two ciphertexts to recover plaintext

### CCMP in Wireshark

```wireshark
# Filter CCMP-encrypted data frames
wlan.fc.type == 2 && wlan.fc.protected == 1

# In the packet tree, expand:
# IEEE 802.11 → CCMP parameters
# → PN (Packet Number): shows the 48-bit counter
```

### TKIP vs CCMP in Captures

```wireshark
# Identify TKIP frames (have WEP/ICV field in frame structure)
wlan.wep.icv

# Identify CCMP frames (have CCMP header ExtIV=1)
# Look for wlan.ccmp.extiv in expanded frame view
```

---

## 10. Decrypting WPA2 Traffic in Wireshark

With the correct PSK and a captured 4-way handshake, Wireshark can decrypt all WPA2 CCMP/TKIP traffic in your capture file.

### Setup

```
Edit → Preferences → Protocols → IEEE 802.11
  → Decryption keys → Edit → Add (+)

Key type: wpa-pwd
Key value: password:SSID
  Example: "Password1!:HomeNet"
  Note: SSID is case-sensitive and required (affects PMK derivation)

OR use hex PMK directly:
Key type: wpa-psk
Key value: <64-hex-char PMK>
  (Generate with: wpa_passphrase "HomeNet" "Password1!" | grep psk= | cut -d= -f2)
```

### Generating the Hex PMK

```bash
# wpa_passphrase derives the PMK from passphrase + SSID
wpa_passphrase "HomeNet" "Password1!"

# Output:
# network={
#     ssid="HomeNet"
#     #psk="Password1!"
#     psk=a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9  ← PMK
# }
```

### Verifying Decryption Worked

After adding the key, apply filter:
```wireshark
# Check if you can now see HTTP/DNS inside data frames
http || dns || dhcp

# If decryption worked, you'll see plaintext protocols inside
# frames that previously showed only "Encrypted data"
```

---

## 11. airdecap-ng — Offline Decryption

`airdecap-ng` decrypts a WPA2 capture file and outputs a new `.cap` with all frames decrypted — readable by Wireshark without any key configuration.

```bash
# WPA2-PSK decryption
airdecap-ng \
  -e "HomeNet" \       # SSID (must be exact)
  -p "Password1!" \    # WPA2 passphrase
  capture-01.cap

# Flags explained:
# -e "HomeNet"     → SSID. Case-sensitive. Affects PMK derivation via PBKDF2.
# -p "Password1!"  → WPA2 passphrase. Combined with SSID → PMK.
# capture-01.cap   → Input capture file (must contain the 4-way handshake)

# Output: capture-01-dec.cap
# All encrypted frames are now decrypted in the new file

# WEP decryption (legacy)
airdecap-ng \
  -w 1234567890 \      # WEP key in hex
  capture-01.cap

# Verify decrypted output
wireshark capture-01-dec.cap
# You should see DNS, HTTP, DHCP, etc. in plaintext
```

### When airdecap-ng Fails

```bash
# Error: "No valid WPA handshakes found"
# → The capture doesn't contain the 4-way handshake
# → Solution: recapture with deauth to force re-authentication (Module 06)

# Error: "0 WPA frames decrypted"
# → Wrong passphrase or SSID
# → Verify with: aircrack-ng -w /path/to/wordlist capture-01.cap

# Verify the handshake is present first:
aircrack-ng capture-01.cap
# Must show: WPA2 (1) handshake
```

---

## 12. tshark Command-Line Analysis

`tshark` is the command-line version of Wireshark — essential for scripting and processing large captures.

### Essential tshark Commands

```bash
# Count frames by type
tshark -r capture-01.cap -q -z io,stat,0

# List all SSID names from beacons
tshark -r capture-01.cap \
  -Y "wlan.fc.type_subtype == 8" \
  -T fields -e wlan.bssid -e wlan_mgt.ssid | sort -u

# Extract all EAPOL messages with their message number
tshark -r capture-01.cap \
  -Y "eapol" \
  -T fields \
  -e frame.number \
  -e wlan.sa \
  -e wlan.da \
  -e eapol.keydes.msgnr \
  -e eapol.keydes.key_info
# eapol.keydes.msgnr    → message 1/2/3/4
# eapol.keydes.key_info → hex key information value

# Extract all probe requests (PNL)
tshark -r capture-01.cap \
  -Y "wlan.fc.type_subtype == 4" \
  -T fields -e wlan.sa -e wlan_mgt.ssid | sort -u

# Count data frames per BSSID (traffic volume)
tshark -r capture-01.cap \
  -Y "wlan.fc.type == 2" \
  -T fields -e wlan.bssid | sort | uniq -c | sort -rn

# Find deauthentication frames with reason codes
tshark -r capture-01.cap \
  -Y "wlan.fc.type_subtype == 12" \
  -T fields \
  -e wlan.sa -e wlan.da \
  -e wlan_mgt.fixed.reason_code

# Live capture with filter (no file — direct from interface)
sudo tshark -i wlan0mon \
  -Y "wlan.fc.type_subtype == 4" \
  -T fields -e wlan.sa -e wlan_mgt.ssid
```

### Deauth Reason Codes Reference

When analyzing deauth frames, the reason code explains why the disconnection occurred:

| Code | Meaning | Injection Indicator |
|------|---------|---------------------|
| 1 | Unspecified | Common in fake deauths |
| 2 | Auth no longer valid | — |
| 3 | STA leaving IBSS/ESS | — |
| 6 | Class 2 frame from unauth STA | — |
| 7 | Class 3 frame from unassoc STA | **Most common in aireplay-ng deauths** |
| 15 | 4-way HS timeout | Legitimate |

---

## 13. Scapy — Sniffing, Filtering & Crafting Frames

### Passive Sniffing with PNL Extraction

```python
#!/usr/bin/env python3
# pnl-sniffer.py — Capture probe requests and extract PNL
# sudo python3 pnl-sniffer.py

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt

pnl = {}  # {client_mac: set(ssids)}

def handle_probe(pkt):
    if not pkt.haslayer(Dot11ProbeReq):
        return
    client_mac = pkt[Dot11].addr2
    ssid_layer = pkt.getlayer(Dot11Elt)
    while ssid_layer:
        if ssid_layer.ID == 0 and ssid_layer.info:  # ID 0 = SSID
            ssid = ssid_layer.info.decode('utf-8', errors='replace')
            if client_mac not in pnl:
                pnl[client_mac] = set()
            if ssid not in pnl[client_mac]:
                pnl[client_mac].add(ssid)
                print(f"  [PNL] {client_mac} → looking for: '{ssid}'")
        ssid_layer = ssid_layer.payload.getlayer(Dot11Elt) if ssid_layer.payload else None

print("[*] Sniffing probe requests... Ctrl+C to stop")
sniff(iface="wlan0mon", prn=handle_probe, store=False,
      lfilter=lambda p: p.haslayer(Dot11ProbeReq))
```

### EAPOL Handshake Detector

```python
#!/usr/bin/env python3
# handshake-detector.py — Alert when 4-way handshake is in progress
# sudo python3 handshake-detector.py

from scapy.all import *
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL

seen = {}  # Track which EAPOL messages seen per (bssid, client)

def handle_eapol(pkt):
    if not pkt.haslayer(EAPOL):
        return
    if pkt[EAPOL].type != 3:  # EAPOL-Key = type 3
        return

    bssid = pkt[Dot11].addr3
    src = pkt[Dot11].addr2
    key = (bssid, src)
    
    # Key Information field identifies message number
    key_info = bytes(pkt[EAPOL])[5:7]
    ki = int.from_bytes(key_info, 'big')
    
    # Determine message based on Key Info flags
    ack = bool(ki & 0x0080)    # Key ACK bit
    mic = bool(ki & 0x0100)    # Key MIC bit
    secure = bool(ki & 0x0200) # Secure bit
    install = bool(ki & 0x0040)# Install bit
    
    if ack and not mic:
        msg = "M1"
    elif mic and not secure:
        msg = "M2"
    elif mic and secure and install:
        msg = "M3"
    elif mic and secure and not install:
        msg = "M4"
    else:
        msg = "??"
    
    if key not in seen:
        seen[key] = set()
    seen[key].add(msg)
    
    print(f"  [EAPOL] {msg} captured | BSSID: {bssid} | Client: {src}")
    
    if {'M1','M2'}.issubset(seen[key]):
        print(f"\n  [!] HANDSHAKE CAPTURED (M1+M2) — BSSID: {bssid} | Client: {src}\n")

print("[*] Watching for WPA2 handshakes...")
sniff(iface="wlan0mon", prn=handle_eapol, store=False,
      lfilter=lambda p: p.haslayer(EAPOL))
```

### Beacon Frame Injection

```python
#!/usr/bin/env python3
# beacon-flood.py — Inject fake beacon frames
# sudo python3 beacon-flood.py

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
import random, time

def random_mac():
    return ':'.join(['%02x' % random.randint(0,255) for _ in range(6)])

networks = [
    ("FreeAirport_WiFi", 6),
    ("Starbucks_Guest", 11),
    ("xfinitywifi", 1),
    ("ATT_WiFi", 6),
]

for ssid, channel in networks:
    mac = random_mac()
    pkt = (
        RadioTap() /
        Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac) /
        Dot11Beacon(cap=0x2104) /
        Dot11Elt(ID="SSID", info=ssid) /
        Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24') /
        Dot11Elt(ID="DSSet", info=bytes([channel]))
    )
    print(f"[+] Injecting beacon: '{ssid}' on channel {channel} from {mac}")
    sendp(pkt, iface="wlan0mon", count=10, inter=0.05, verbose=False)
```

---

## 14. Common Packet Patterns Reference

### Complete Wireshark Filter Reference

| Goal | Filter | Notes |
|------|--------|-------|
| All beacons | `wlan.fc.type_subtype == 8` | |
| Beacons from AP | `wlan.fc.type_subtype == 8 && wlan.bssid == aa:bb:cc:dd:ee:ff` | |
| Probe Requests | `wlan.fc.type_subtype == 4` | |
| Directed Probes only | `wlan.fc.type_subtype == 4 && wlan.ssid != ""` | PNL leakage |
| Authentication | `wlan.fc.type_subtype == 11` | State 1→2 |
| Association | `wlan.fc.type_subtype == 0` | State 2→3 |
| Deauth frames | `wlan.fc.type_subtype == 12` | Deauth attack |
| EAPOL handshake | `eapol` | 4-way handshake |
| EAPOL M2 only | `eapol && eapol.keydes.msgnr == 2` | Crackable message |
| Encrypted data | `wlan.fc.type == 2 && wlan.fc.protected == 1` | |
| Unencrypted data | `wlan.fc.type == 2 && wlan.fc.protected == 0` | Open networks |
| Retransmissions | `wlan.fc.retry == 1` | Injection/quality issues |
| PMF-protected deauth | `wlan.fc.type_subtype == 12 && wlan.fc.protected == 1` | 802.11w enabled |
| All from/to a MAC | `wlan.addr == aa:bb:cc:dd:ee:ff` | |
| WPA (tag 221) | `wlan.tag.number == 221` | WPA1 IE |
| RSN (WPA2) | `wlan.tag.number == 48` | WPA2 RSN IE |

---

## 15. Troubleshooting Capture Issues

### Problem: "Malformed packet" errors everywhere

```bash
# Cause: Wireshark expects FCS but it's missing (or vice versa)
# Fix A: Tell Wireshark FCS is present
# Edit → Preferences → Protocols → IEEE 802.11 → ✓ Assume packets have FCS

# Fix B: If FCS is genuinely not in the capture (stripped by driver)
# Edit → Preferences → Protocols → IEEE 802.11 → ✗ Uncheck FCS option
```

### Problem: Handshake shows "WPA (0) handshake"

```bash
# 0 handshake = no complete EAPOL exchange captured
# Check what EAPOL messages you have:
tshark -r capture-01.cap -Y "eapol" -T fields -e eapol.keydes.msgnr
# If you only see message 1 or 3 — the client's response was missed
# Solution: Re-deauth and recapture while locked to channel
```

### Problem: airdecap-ng outputs 0 decrypted frames

```bash
# Verify handshake is present
aircrack-ng capture-01.cap  # Must show "WPA2 (1) handshake"

# Verify SSID is correct (case-sensitive)
tshark -r capture-01.cap -Y "wlan.fc.type_subtype == 8" \
  -T fields -e wlan_mgt.ssid | sort -u
# Compare exact SSID characters including spaces and case

# Try generating PMK and using hex form
wpa_passphrase "ExactSSID" "password" | grep -v '#'
airdecap-ng -p "password" -e "ExactSSID" capture-01.cap
```

### Problem: Can't see data frames in Wireshark

Data frames between two stations on an encrypted network are only visible if:
1. You're on the correct channel AND
2. The network uses WEP (broadcast key) OR
3. You have the WPA2 key in Wireshark preferences AND the handshake is in the capture

```wireshark
# Check: do you see any data at all?
wlan.fc.type == 2
# If blank → wrong channel or no traffic
# If shows encrypted → add WPA2 key to preferences
# If shows plaintext → open network or decryption working
```

---

## 16. Knowledge Check

1. What are the three main 802.11 frame types and their hex type values?
2. Write a Wireshark filter using `wlan.fc.type_subtype` to show only deauthentication frames.
3. In the RSN IE, what does the AKM value `00:0f:ac:02` indicate?
4. What is the Key Information value for EAPOL Message 2, and which bits are set?
5. What is the minimum number of EAPOL messages needed for an offline WPA2 dictionary attack?
6. Explain what the CCMP Packet Number (PN) is used for and why KRACK exploits its reset.
7. Write the `airdecap-ng` command to decrypt a capture for SSID "LabNet" with password "test123".
8. Using Scapy, write a snippet to sniff probe requests and print the client MAC and SSID for each.
9. What Wireshark preference must be set to decrypt WPA2 traffic, and what information do you need to provide?
10. What does `wpa_passphrase "HomeNet" "Password1!"` produce and how is the output used?
11. Write a tshark command to extract all deauthentication reason codes from a capture file.
12. In Wireshark, how do you identify whether a deauth frame was sent by a legitimate AP vs. injected by an attacker?
13. What does the `wlan.fc.protected == 0` filter on data frames reveal in a WPA2 network capture, and why is it significant?
14. What is `airdecap-ng` and how does it differ from Wireshark's built-in decryption?

---

**Next:** [Module 05 — WEP Cracking](../module-05-wep-cracking/)
