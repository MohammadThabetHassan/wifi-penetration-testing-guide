# Module 00 — Networking & 802.11 Foundations

> **Prerequisites:** None. This is the entry point for the course.
> **Next Module:** [Module 01 — Linux Wireless Lab Setup](../module-01-linux-wireless-setup/)

---

## Table of Contents

1. [Why Foundations Matter](#1-why-foundations-matter)
2. [The OSI Model & Where Wi-Fi Lives](#2-the-osi-model--where-wi-fi-lives)
3. [Radio Frequency Basics](#3-radio-frequency-basics)
4. [The 802.11 Standard Family](#4-the-80211-standard-family)
5. [Network Identifiers: SSID, BSSID, ESSID, HESSID](#5-network-identifiers-ssid-bssid-essid-hessid)
6. [Frequency Bands & Channel Plans](#6-frequency-bands--channel-plans)
7. [802.11 Frame Architecture](#7-80211-frame-architecture)
8. [The Three Frame Types In Depth](#8-the-three-frame-types-in-depth)
9. [CSMA/CA — How the Wireless Medium Is Shared](#9-csmaca--how-the-wireless-medium-is-shared)
10. [Station State Machine — Authentication & Association](#10-station-state-machine--authentication--association)
11. [The 4-Way Handshake (Preview)](#11-the-4-way-handshake-preview)
12. [RSN Information Element — Reading Cipher Suites](#12-rsn-information-element--reading-cipher-suites)
13. [Probe Requests & the PNL — Privacy Implications](#13-probe-requests--the-pnl--privacy-implications)
14. [Wireless Security Protocol Timeline](#14-wireless-security-protocol-timeline)
15. [Attacker's Mental Model](#15-attackers-mental-model)
16. [Key Terms Glossary](#16-key-terms-glossary)
17. [Knowledge Check](#17-knowledge-check)

---

## 1. Why Foundations Matter

Every attack covered in this course exploits a specific, well-defined weakness in the 802.11 standard or its implementation. Without understanding the protocol at the frame level you cannot:

- Interpret `airodump-ng` output meaningfully
- Understand *why* a deauthentication attack works
- Diagnose why an injection attempt fails
- Distinguish a WPA2-CCMP network from a WPA2-TKIP network at a glance
- Adapt when a target network behaves unexpectedly
- Know which `hashcat` mode (`-m 22000`, `-m 2500`, `-m 16800`) to use for a given capture type

Treat this module as the map before you enter the territory. Every subsequent module references concepts introduced here.

---

## 2. The OSI Model & Where Wi-Fi Lives

The Open Systems Interconnection (OSI) model describes network communication in seven abstract layers. Wi-Fi operates across two of them:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 7 — Application   (HTTP, DNS, FTP...)            │
│  Layer 6 — Presentation  (TLS, encryption)              │
│  Layer 5 — Session       (session management)           │
│  Layer 4 — Transport     (TCP, UDP)                     │
│  Layer 3 — Network       (IP, routing)                  │
│  ─────────────────────────────────────────────────────  │
│  Layer 2 — Data Link     ◄── MAC sublayer lives here    │
│                          ◄── LLC sublayer               │
│  Layer 1 — Physical      ◄── RF signal, modulation      │
└─────────────────────────────────────────────────────────┘
```

**Layer 1 (Physical):** Governs how bits are converted to radio waves — modulation schemes (DSSS, OFDM, MIMO), signal strength (dBm), channel width, and frequency.

**Layer 2 (Data Link):** The MAC (Medium Access Control) sublayer is where 802.11 frames live. This is the primary attack surface for wireless exploitation. Frame injection, spoofing, deauthentication, and handshake capture all operate here.

**The critical insight for attackers:** 802.11 management frames (Layer 2) were designed with **no authentication and no encryption** by default. Any station can craft and transmit a valid-looking management frame impersonating any other station. This is the root cause of deauthentication attacks, Evil Twins, and beacon flooding.

---

## 3. Radio Frequency Basics

### Signal Strength (dBm)

Signal strength is measured in **dBm** (decibels relative to 1 milliwatt). The scale is logarithmic:

| dBm | Description |
|-----|-------------|
| -30 | Excellent (very close to AP) |
| -50 | Very good |
| -67 | Good (reliable connections) |
| -70 | Acceptable |
| -80 | Weak (packet loss likely) |
| -90 | Extremely weak / noise floor |

In `airodump-ng`, the `PWR` column shows signal strength in dBm. The closer to 0, the stronger the signal. **-1** is a special value meaning the driver is not reporting signal strength.

### RSSI vs. dBm

RSSI (Received Signal Strength Indicator) is a relative, vendor-defined value. dBm is an absolute measurement. Tools often display one or the other — they are related but not identical.

### Noise & SNR

**Noise floor** is the baseline radio energy present with no signal. **SNR (Signal-to-Noise Ratio)** is the difference between your signal and the noise floor. High SNR = cleaner signal = more reliable injection and capture.

### Antenna Gain (dBi)

Antennas amplify signal in specific directions. A directional Yagi antenna with 24dBi gain can receive signals from kilometers away — useful for long-range reconnaissance. Omnidirectional antennas (2–9dBi) are used for general scanning.

### Free Space Path Loss (FSPL)

Signal attenuates with distance. The formula is:

```
FSPL (dB) = 20·log₁₀(d) + 20·log₁₀(f) + 20·log₁₀(4π/c)
```

Where `d` = distance in meters, `f` = frequency in Hz. At 2.4 GHz, doubling distance costs roughly 6 dB. This directly affects how far away you can successfully inject frames.

---

## 4. The 802.11 Standard Family

The IEEE 802.11 working group has published many amendments. The ones relevant to this course:

| Amendment | Common Name | Max Speed | Frequency | Notes |
|-----------|-------------|-----------|-----------|-------|
| 802.11 (1997) | — | 2 Mbps | 2.4 GHz | Original; DSSS/FHSS modulation |
| 802.11b (1999) | Wi-Fi 1 | 11 Mbps | 2.4 GHz | WEP era; still found in embedded devices |
| 802.11a (1999) | Wi-Fi 2 | 54 Mbps | 5 GHz | OFDM; less interference |
| 802.11g (2003) | Wi-Fi 3 | 54 Mbps | 2.4 GHz | Backward compatible with 802.11b |
| 802.11n (2009) | Wi-Fi 4 | 600 Mbps | 2.4/5 GHz | MIMO; WPA2 era; HT (High Throughput) |
| 802.11ac (2013) | Wi-Fi 5 | 3.5 Gbps | 5 GHz | MU-MIMO; VHT (Very High Throughput) |
| 802.11ax (2019) | Wi-Fi 6/6E | 9.6 Gbps | 2.4/5/6 GHz | OFDMA; introduces WPA3 mandatory support |
| 802.11be (2024) | Wi-Fi 7 | 46 Gbps | 2.4/5/6 GHz | Multi-Link Operation (MLO) |

**For attackers:** The amendment determines which ciphers and security modes are available. An 802.11b-only network is almost certainly running WEP. An 802.11ax (Wi-Fi 6) network likely runs WPA3. Your attack selection must match the target's capabilities.

### Key 802.11 Sub-Standards for Security

| Standard | Function |
|----------|----------|
| **802.11i** | Defines WPA2 (RSN — Robust Security Network) |
| **802.11w** | Management Frame Protection (MFP / PMF) — protects deauth/disassoc frames |
| **802.11r** | Fast BSS Transition (FT) — affects handshake capture in roaming environments |
| **802.11s** | Mesh networking |
| **802.11u** | Interworking / Hotspot 2.0 (Passpoint) |
| **802.1X** | Port-based access control — the authentication framework for WPA-Enterprise |

---

## 5. Network Identifiers: SSID, BSSID, ESSID, HESSID

| Term | Definition | Example |
|------|-----------|---------|
| **SSID** | Service Set Identifier. The human-readable network name. Up to 32 bytes (UTF-8). | `"CoffeeShop_WiFi"` |
| **BSSID** | Basic Service Set Identifier. The MAC address of the Access Point's radio interface. Globally unique (in theory). | `AA:BB:CC:DD:EE:FF` |
| **ESSID** | Extended SSID. Same as SSID in modern usage; historically referred to a group of BSSIDs sharing the same network name. | `"CorporateWLAN"` |
| **HESSID** | Homogeneous ESSID. Used in 802.11u (Hotspot 2.0) to identify a set of APs operated by the same entity. | Enterprise campus networks |
| **IBSS** | Independent BSS — ad-hoc mode, no AP. | Peer-to-peer Wi-Fi direct |

### Why BSSIDs Matter for Attacks

The BSSID is the primary targeting identifier. When you lock `airodump-ng` to a BSSID and channel, you filter all traffic from that specific AP. When crafting deauth frames, the BSSID is the spoofed source address.

**A single SSID can have multiple BSSIDs** (multi-AP deployments, repeaters, mesh nodes). Each is a separate target. Evil Twin attacks clone the BSSID along with the SSID to maximize confusion.

### Hidden SSIDs

An AP can be configured to suppress SSID in Beacon frames (the `ESSID` field is set to zero-length or all zeros). This is **security through obscurity only** — the SSID is still transmitted in:
- **Probe Response** frames (sent when a client actively probes)
- **Association Request** frames (from connecting clients)
- **Reassociation Request** frames

`airodump-ng` displays hidden SSIDs as `<length: N>` until a client associates, at which point it captures the SSID from the association request.

### OUI — Organizational Unique Identifier

The first three bytes (24 bits) of a MAC address are the OUI, assigned by IEEE to the manufacturer. You can look up any BSSID's OUI to identify the hardware vendor:

```
AA:BB:CC:DD:EE:FF
└──────┘
  OUI — first 3 bytes → identifies manufacturer
  e.g., 00:50:F2 = Microsoft, 00:17:F2 = Apple, D8:B1:90 = TP-Link
```

Tools used: `macchanger --list`, online IEEE OUI lookup, `wireshark` OUI resolution.

---

## 6. Frequency Bands & Channel Plans

### 2.4 GHz Band

14 channels defined globally; 11 available in North America; 13 in Europe. Each channel is 22 MHz wide but spaced only 5 MHz apart — resulting in massive overlap.

**Non-overlapping channels (NA):** 1, 6, 11

```
Ch  1: |████████████|
Ch  2:   |████████████|
Ch  3:     |████████████|
Ch  6:           |████████████|
Ch 11:                     |████████████|
```

**Impact on attacks:** Channel interference degrades capture quality. Always note the channel of your target and lock to it.

### 5 GHz Band

24 non-overlapping 20 MHz channels in most regions (36, 40, 44, 48, 52...). Less congested. Some channels are **DFS (Dynamic Frequency Selection)** channels — regulated for radar avoidance, which can complicate injection.

### 6 GHz Band (Wi-Fi 6E)

59 new 20 MHz channels. Only supported by Wi-Fi 6E/7 hardware and Kali-compatible adapters (still limited as of 2025).

### Channel Width

| Mode | Width | Notes |
|------|-------|-------|
| Legacy | 20 MHz | Standard |
| HT40 | 40 MHz | 802.11n; primary + extension channel |
| VHT80 | 80 MHz | 802.11ac |
| VHT160 | 160 MHz | 802.11ac Wave 2 |

Wider channels capture more throughput but require your adapter to support the same width for effective monitoring.

---

## 7. 802.11 Frame Architecture

Every 802.11 frame shares a common MAC header structure. Understanding this is essential for reading Wireshark captures and crafting injection payloads.

```
 0       1       2       3       4       5       6       7
 ┌───────────────────────────────────────────────────────┐
 │  Frame Control (2 bytes)                              │
 ├───────────────────────────────────────────────────────┤
 │  Duration/ID (2 bytes)                                │
 ├───────────────────────────────────────────────────────┤
 │  Address 1 — Receiver / Destination (6 bytes)         │
 ├───────────────────────────────────────────────────────┤
 │  Address 2 — Transmitter / Source (6 bytes)           │
 ├───────────────────────────────────────────────────────┤
 │  Address 3 — BSSID / Filtering Address (6 bytes)      │
 ├───────────────────────────────────────────────────────┤
 │  Sequence Control (2 bytes)                           │
 ├───────────────────────────────────────────────────────┤
 │  Address 4 — WDS only (6 bytes, optional)             │
 ├───────────────────────────────────────────────────────┤
 │  QoS Control (2 bytes, optional)                      │
 ├───────────────────────────────────────────────────────┤
 │  Frame Body (variable, 0–7951 bytes)                  │
 ├───────────────────────────────────────────────────────┤
 │  FCS — Frame Check Sequence (4 bytes, CRC-32)         │
 └───────────────────────────────────────────────────────┘
```

### Frame Control Field (Expanded)

```
 Bits:  0-1    2-3     4-7      8      9     10    11    12   13  14-15
       ┌──────┬──────┬────────┬──────┬─────┬─────┬─────┬────┬───┬──────┐
       │ Ver  │ Type │Subtype │To DS │FrmDS│ More│Retry│Pwr │MD │ WEP/ │
       │ (00) │      │        │      │     │ Frg │     │Mgmt│   │Prot'd│
       └──────┴──────┴────────┴──────┴─────┴─────┴─────┴────┴───┴──────┘
```

**Type field** (2 bits) determines the frame category:
- `00` = Management frame
- `01` = Control frame
- `10` = Data frame
- `11` = Extension frame (802.11ax)

**Protected bit** (bit 14): When set, the frame body is encrypted. If a data frame has this bit **unset**, the payload is transmitted in cleartext — a classic WEP/open network capture scenario.

**ToDS / FromDS bits** (bits 8-9): Indicate direction of data frames:

| ToDS | FromDS | Meaning |
|------|--------|---------|
| 0 | 0 | IBSS (ad-hoc) or management/control |
| 1 | 0 | Client → AP (infrastructure) |
| 0 | 1 | AP → Client (infrastructure) |
| 1 | 1 | WDS bridge (AP → AP) — uses Address 4 |

### Sequence Number & Replay Protection

The **Sequence Control** field contains a 12-bit sequence number (0–4095). Receivers use this to detect and discard duplicate/replayed frames. However:

- In WEP, sequence numbers are used for replay detection but the implementation is weak
- In WPA2-CCMP, the **CCMP PN (Packet Number)** in the frame body is the primary replay counter — separate from the 802.11 sequence number
- `aireplay-ng` must spoof valid sequence numbers for successful injection; it does this automatically

---

## 8. The Three Frame Types In Depth

### 8.1 Management Frames

Management frames establish and maintain connections. They are **transmitted in cleartext by default** (unless 802.11w/PMF is enabled). This is the primary attack surface.

| Subtype | Decimal | Frame Name | Purpose |
|---------|---------|------------|---------|
| 0000 | 0 | Association Request | Client requests to join AP |
| 0001 | 1 | Association Response | AP accepts/rejects client |
| 0010 | 2 | Reassociation Request | Client moves between APs (roaming) |
| 0011 | 3 | Reassociation Response | AP response to reassoc |
| 0100 | 4 | Probe Request | Client broadcasts looking for SSIDs |
| 0101 | 5 | Probe Response | AP responds to probe |
| 1000 | 8 | Beacon | AP periodically announces presence |
| 1010 | 10 | Disassociation | Either party terminates association |
| 1011 | 11 | Authentication | 802.11 authentication exchange |
| 1100 | 12 | **Deauthentication** | **Terminates authentication — the deauth attack vector** |
| 1101 | 13 | Action | Block ACK, spectrum management |

**Beacon frames** are broadcast every ~100ms (default TIM interval). They contain:
- SSID (or blank if hidden)
- BSSID
- Supported rates
- Channel info
- Capabilities (WPA/WPA2/WPA3 IEs)
- RSN Information Element (details cipher suites)
- **TIM (Traffic Indication Map)** — which sleeping clients have buffered frames
- **Country IE** — regulatory domain (affects TX power limits)

**Probe Requests** are sent by clients scanning for known networks. They leak the **preferred network list (PNL)** of the device — a fingerprinting and social engineering goldmine. KARMA/MANA attacks exploit these (Module 09).

### 8.2 Control Frames

Control frames manage channel access and frame delivery. Less directly exploitable but important to understand:

| Subtype | Name | Purpose |
|---------|------|---------|
| 1011 | RTS | Request to Send — reserve medium |
| 1100 | CTS | Clear to Send — response to RTS |
| 1101 | ACK | Acknowledgement of received frame |
| 1110 | CF-End | End contention-free period |
| 0101 | VHT NDP Announcement | 802.11ac beamforming probe |

### 8.3 Data Frames

Data frames carry actual payload (IP packets encapsulated in LLC/SNAP). Subtypes include QoS Data, Null Function (power save signaling), and CF-ACK variants.

**For attackers:** Data frames are captured to:
- Collect IVs in WEP cracking (Module 05)
- Count `#Data` packets per AP in `airodump-ng` (Module 03)
- Identify active clients for targeted deauth (Module 08)
- Verify successful MITM position in Evil Twin attacks (Module 09)

---

## 9. CSMA/CA — How the Wireless Medium Is Shared

Understanding CSMA/CA (Carrier Sense Multiple Access with Collision Avoidance) is essential for understanding why both passive sniffing and active injection work in 802.11 networks.

### The Core Problem

Unlike Ethernet (wired), all 802.11 stations share a single half-duplex radio channel. Two stations transmitting simultaneously produce a collision — both frames are lost. CSMA/CA prevents this.

### The DCF Algorithm (Distributed Coordination Function)

```
Station wants to transmit:
  │
  ├─ Sense channel → Busy? → Wait + random backoff (contention window)
  │                          │
  │                          └─ Channel idle for DIFS duration?
  │                               → Transmit frame
  │                               → Wait for ACK within SIFS
  │                               → No ACK? → Exponential backoff + retry
  │
  └─ Channel idle for DIFS? → Transmit immediately
```

**Key timing intervals:**
- **SIFS (Short Inter-Frame Space):** ~16μs (2.4 GHz); used for ACKs, CTS responses
- **DIFS (DCF IFS):** ~34μs; minimum idle time before a new frame transmission
- **Backoff:** Random value × slot time; prevents simultaneous retransmissions

### Why This Matters for Attacks

1. **Monitor mode bypasses CSMA/CA** entirely. Your adapter captures frames regardless of their destination — it never waits for DIFS or sends ACKs.

2. **Injection via CSMA/CA:** When `aireplay-ng` injects frames, the driver still must compete for the channel using CSMA/CA. This is why injection on a heavily loaded channel is less reliable.

3. **DoS via channel saturation:** `mdk4` and `mdk3` can flood the channel with beacon frames or data frames, consuming all available airtime. Legitimate clients cannot win the CSMA/CA backoff race. This is the basis for wireless DoS attacks (Module 08).

4. **NAV (Network Allocation Vector):** The Duration/ID field in every frame tells other stations how long to defer. An attacker can transmit frames with extremely large Duration values, forcing all other stations to wait — a "virtual carrier sense" DoS.

---

## 10. Station State Machine — Authentication & Association

802.11 defines a **three-state machine** for client-AP relationships. Understanding this explains exactly what deauth and disassoc frames do.

```
     ┌──────────────────────────────────────────────────────────┐
     │                                                          │
     ▼                                                          │
 ┌─────────┐   Authenticate    ┌─────────────┐   Associate    ┌───────────┐
 │ State 1 │ ────────────────► │   State 2   │ ─────────────► │  State 3  │
 │Unauthent│                   │Authenticated│                │Assoc'd +  │
 │Unassoc'd│ ◄──────────────── │ Unassoc'd   │ ◄───────────── │Authentd   │
 └─────────┘   Deauthenticate  └─────────────┘  Disassociate  └───────────┘
      │                               │                              │
      │   Deauthenticate              │    Deauthenticate            │
      └───────────────────────────────┴──────────────────────────────┘
                         (jump back to State 1 from anywhere)
```

**State 1:** Client knows the AP exists. No authentication.
**State 2:** Client has completed 802.11 authentication (open system or shared key). Not yet associated — cannot pass data.
**State 3:** Client is fully associated and authenticated. Data traffic flows. In WPA2, the 4-way handshake occurs here to derive PTK.

### Open System Authentication (Most Common)

A two-frame exchange that always succeeds:
1. Client → AP: Authentication Request (algorithm: Open System, seq: 1)
2. AP → Client: Authentication Response (status: Success, seq: 2)

This is effectively no authentication at Layer 2 — the "real" authentication happens at Layer 3+ (captive portal) or via WPA2/WPA3 at the 4-way handshake level.

### Shared Key Authentication (WEP Only)

A four-frame challenge-response that is **cryptographically broken** and makes WEP cracking easier (Module 05):
1. Client → AP: Auth Request (Open)
2. AP → Client: Challenge text (plaintext)
3. Client → AP: Challenge text encrypted with WEP key
4. AP → Client: Success/Failure

Capturing frames 2 and 3 gives the attacker a known-plaintext/ciphertext pair — directly usable for keystream recovery.

### The Deauthentication Attack Vector

A Deauthentication frame (subtype 12) sent with **any source address** instantly drops a client back to State 1. Because management frames have no source authentication by default:
- An attacker can **forge** a deauth frame with the AP's BSSID as the source
- The client has no way to verify legitimacy
- The client immediately disconnects and begins re-association
- During re-association, it performs the WPA2 4-way handshake again — which the attacker captures

**This is the entire mechanism behind Module 06 and Module 08.**

### Management Frame Protection (802.11w / PMF)

Introduced in 2009, 802.11w encrypts and authenticates deauthentication and disassociation frames using the PTK derived during the 4-way handshake. WPA3 mandates 802.11w.

```
Without PMF:  Any frame with valid FCS → accepted as legitimate
With PMF:     Deauth/Disassoc require valid MIC from PTK → forgery detected
```

**Limitations of PMF:** Unauthenticated broadcast deauths can still cause issues in some implementations. The initial authentication phase (before a PTK is established) is still unprotected.

---

## 11. The 4-Way Handshake (Preview)

When a client (supplicant) connects to a WPA2 AP (authenticator), they perform a 4-way handshake using EAPOL (Extensible Authentication Protocol over LAN) frames. This derives the **PTK (Pairwise Transient Key)** used to encrypt the session.

```
  Client (Supplicant)                          AP (Authenticator)
        │                                              │
        │        EAPOL Message 1 (ANonce)              │
        │ ◄────────────────────────────────────────── │
        │                                              │
        │  (Client derives PTK = PRF(PMK, ANonce,     │
        │   SNonce, AP_MAC, Client_MAC))               │
        │                                              │
        │   EAPOL Message 2 (SNonce + MIC)             │
        │ ──────────────────────────────────────────► │
        │                                              │
        │        EAPOL Message 3 (GTK + MIC)           │
        │ ◄────────────────────────────────────────── │
        │                                              │
        │        EAPOL Message 4 (ACK + MIC)           │
        │ ──────────────────────────────────────────► │
        │                                              │
        │   [Encrypted data session begins]            │
```

**PMK (Pairwise Master Key):** Derived from the passphrase using PBKDF2-SHA1:
```
PMK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096 iterations, 256 bits)
```

Note: Both the **passphrase** AND the **SSID** are inputs. This is why precomputed WPA2 rainbow tables are SSID-specific — a table built for `"linksys"` is useless against `"HomeNetwork42"`.

**PTK (Pairwise Transient Key):** Derived from PMK + both nonces + both MAC addresses using a PRF:
```
PTK = PRF-X(PMK, "Pairwise key expansion", Min(AP_MAC,STA_MAC) ||
            Max(AP_MAC,STA_MAC) || Min(ANonce,SNonce) || Max(ANonce,SNonce))
```
The PTK includes the **MIC key** used to verify frame integrity.

**Why this matters for cracking:** Messages 2 and 3 contain a MIC (Message Integrity Code). An attacker who captures the handshake can:
1. Take a candidate passphrase from a wordlist
2. Derive a candidate PMK via PBKDF2-SHA1
3. Derive a candidate PTK using captured nonces and MACs
4. Compute the expected MIC
5. Compare with the captured MIC
6. If they match, the passphrase is correct

This is exactly what `aircrack-ng` and `hashcat` do in Module 07. The capture is **offline** — no interaction with the AP needed after sniffing.

### Hashcat Modes for WPA2

| Mode | Format | Description |
|------|--------|-------------|
| `-m 22000` | HCCAPX (hcxtools) | **Recommended** — covers both EAPOL handshakes and PMKID |
| `-m 2500` | `.hccapx` | Legacy EAPOL handshake format (deprecated in new hashcat) |
| `-m 16800` | `.16800` | PMKID-only attack (no handshake needed — Module 12) |
| `-m 22001` | HCCAPX | WPA2 PMKID + EAPOL combined (newer hashcat versions) |

### PMKID — The Clientless Attack (Preview)

The **PMKID** is derived from the PMK and is embedded in the first EAPOL frame (RSNIE of the Beacon/Association Response). A passive attacker can extract it **without deauthenticating any client** and without capturing a full 4-way handshake.

```
PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || STA_MAC)
```

This is the basis of the PMKID attack covered in Module 12.

---

## 12. RSN Information Element — Reading Cipher Suites

The **RSN IE (Robust Security Network Information Element)** is embedded in Beacon and Association Request frames. It advertises the security capabilities of the AP. Understanding it lets you immediately know the attack surface from `airodump-ng` output.

### RSN IE Structure

```
RSN Information Element
├── Version: 1
├── Group Cipher Suite (multicast/broadcast)
│     00-0F-AC:02 = TKIP
│     00-0F-AC:04 = CCMP-128 (AES)
│     00-0F-AC:06 = GCMP-128 (WPA3)
├── Pairwise Cipher Suite Count
├── Pairwise Cipher Suite(s) (unicast)
│     00-0F-AC:02 = TKIP
│     00-0F-AC:04 = CCMP-128 (AES)
│     00-0F-AC:06 = GCMP-128
│     00-0F-AC:08 = GCMP-256
├── AKM Suite Count
├── AKM Suite(s) (authentication)
│     00-0F-AC:01 = 802.1X (Enterprise)
│     00-0F-AC:02 = PSK (Pre-Shared Key / WPA2-Personal)
│     00-0F-AC:06 = SAE (WPA3-Personal)
│     00-0F-AC:18 = OWE (Opportunistic Wireless Encryption)
└── RSN Capabilities
      Bit 6: Management Frame Protection Required (PMF)
      Bit 7: Management Frame Protection Capable
```

### Reading airodump-ng Output

```
BSSID              PWR  Beacons  #Data   CH  MB  ENC  CIPHER AUTH  ESSID
AA:BB:CC:DD:EE:FF  -55  120      48      6   130 WPA2 CCMP   PSK   HomeNet
AA:BB:CC:11:22:33  -70  80       5       1   54  WPA  TKIP   PSK   OldRouter
AA:BB:CC:44:55:66  -80  200      0       11  54  WEP  WEP    WEP   Vulnerable
```

Column breakdown:
- `ENC` = Encryption protocol (WEP/WPA/WPA2/WPA3/OPN)
- `CIPHER` = Cipher suite (CCMP/TKIP/WEP/GCMP)
- `AUTH` = Authentication method (PSK/MGT/SAE/OWE)
- `MGT` in AUTH column = WPA-Enterprise (802.1X) — covered in Module 13

---

## 13. Probe Requests & the PNL — Privacy Implications

### What Is the PNL?

Every Wi-Fi device maintains a **Preferred Network List (PNL)** — a list of previously connected networks stored in memory. When the device is not connected to any network, it sends **Probe Request** frames to search for networks in its PNL.

### The Privacy Problem

Probe Requests containing the full SSID leak:
- The names of every private/corporate network the device has connected to
- The approximate geographic history of the device's owner
- Device fingerprinting data (supported rates, capabilities, sequence numbers)

Example passive capture showing PNL leakage:
```
Probe Request from AA:BB:CC:DD:EE:FF → SSID: "Marriott_WiFi"
Probe Request from AA:BB:CC:DD:EE:FF → SSID: "AirportFreeWifi"
Probe Request from AA:BB:CC:DD:EE:FF → SSID: "OfficeNet_Corp"
Probe Request from AA:BB:CC:DD:EE:FF → SSID: "HomeNetwork"
```

This tells an attacker: the device owner travels frequently, works for a corporation, and stays in hotels.

### The KARMA / MANA Attack

A rogue AP can respond to **every Probe Request** with a fabricated Probe Response claiming to be the requested SSID. The client automatically associates — believing it found a known trusted network.

```
Client:        "Is SSID 'HomeNetwork' here?"
Rogue AP:      "Yes! I am 'HomeNetwork'. Connect to me."
Client:        [Connects — now all traffic goes through attacker]
```

This is the mechanism behind the Evil Twin module (Module 09). Tools: `hostapd-wpe`, `bettercap` (with `wifi.recon` and `wifi.ap` modules), `mana-toolkit`.

### Modern Mitigations

- **iOS 14+, Android 10+:** Randomize Probe Request source MAC address (random local MACs)
- **iOS 15+:** Probe Requests use randomized SSIDs (no PNL disclosure)
- **802.11az:** Adds passive scanning to reduce directed Probe Requests

This does **not** eliminate the attack but reduces its effectiveness against modern devices.

---

## 14. Wireless Security Protocol Timeline

```
Year    Protocol          Cipher           Auth              Status
──────────────────────────────────────────────────────────────────────────
1999    WEP               RC4 (64/128b)    Open/Shared Key   BROKEN (never use)
2003    WPA (TKIP)        RC4+TKIP         PSK / 802.1X      DEPRECATED
2004    WPA2-CCMP         AES-CCMP         PSK / 802.1X      Vulnerable (handshake)
2004    WPA2-TKIP         RC4+TKIP         PSK / 802.1X      BROKEN (use CCMP)
2017    KRACK             —                WPA2 all modes    Patch available (CVE-2017-13077+)
2018    WPA3-SAE          AES-GCMP-256     SAE / 802.1X      Current (Dragonblood partial)
2019    Dragonblood       —                WPA3-SAE          Side-channel CVEs (CVE-2019-9494+)
2022    WPA3-R3           AES-GCMP-256     SAE / 802.1X      Best available
```

### WEP (Wired Equivalent Privacy)

Uses RC4 stream cipher with a 24-bit Initialization Vector (IV). The IV is sent in plaintext alongside each frame. With enough captured IVs (~40,000–85,000), statistical attacks (PTW method) recover the key entirely. **Completely broken. Covered in Module 05.**

### WPA-TKIP (Temporal Key Integrity Protocol)

Introduced as a firmware-upgradeable replacement for WEP. Still uses RC4 but adds per-packet key mixing, sequence counters, and Michael MIC. Michael MIC is vulnerable to a forgery attack allowing arbitrary data injection with a known MIC. TKIP itself was deprecated in 802.11-2012. **Treat as broken.**

### WPA2-CCMP (Counter Mode CBC-MAC Protocol)

Uses AES in CCM mode. Cryptographically sound — the weakness is in the **key derivation** (PSK from passphrase) and the **exposure of the 4-way handshake** over the air. Not the cipher that's broken — the pre-shared key selection is. **Primary attack target: Modules 06, 07.**

### KRACK (Key Reinstallation Attacks — 2017, CVE-2017-13077)

A critical vulnerability in the WPA2 4-way handshake state machine. By replaying EAPOL Message 3, an attacker can force **nonce reuse** in the PTK, breaking CCMP/TKIP confidentiality and allowing plaintext recovery or forgery. All WPA2 implementations were affected. Patched by most vendors by 2018. **Covered in Module 06.**

### WPA3-SAE (Simultaneous Authentication of Equals)

Replaces PSK with Dragonfly key exchange (SAE). Provides **forward secrecy** — capturing the handshake does not enable offline dictionary attacks. **Dragonblood attacks (2019)** found timing and cache-based side-channel vulnerabilities in the SAE commit phase, allowing partial offline dictionary attacks. CVEs: 2019-9494, 2019-9496. **Covered in Module 13.**

---

## 15. Attacker's Mental Model

Before touching a tool, internalize this framework:

```
1. IDENTIFY    — What encryption/auth is the target using?
                 (ENC column in airodump-ng: OPN/WEP/WPA/WPA2/WPA3)

2. MAP         — What clients are connected? What are their MACs?
                 Are they actively sending data (data frame count)?
                 Are they sending Probe Requests (PNL disclosure)?

3. SELECT      — Choose the appropriate attack for the identified protocol:
                 WEP?             → IV collection + PTW crack (Module 05)
                 WPA2-PSK?        → Handshake capture + offline crack (Modules 06–07)
                 WPA2-PSK?        → PMKID clientless capture (Module 12)
                 WPA2-Enterprise? → Rogue RADIUS + MSCHAPv2 capture (Module 13)
                 WPS enabled?     → Pixie Dust or PIN bruteforce (Module 11)
                 Open network?    → MITM / Evil Twin (Module 09–10)

4. EXECUTE     — Run the attack methodically. Verify each step.

5. VALIDATE    — Confirm success (decrypted capture, successful association).

6. DOCUMENT    — Record findings for the report (authorized testing only).
```

This loop repeats. The reconnaissance phase (Module 03) feeds directly into attack selection. Never skip recon.

### Tool Selection Reference

| Task | Primary Tool | Alternative Tool |
|------|-------------|-----------------|
| Passive scanning | `airodump-ng` | `kismet`, `bettercap wifi.recon` |
| Frame injection | `aireplay-ng` | `scapy` (Python), `mdk4` |
| Passive capture | `airodump-ng` | `hcxdumptool`, `tcpdump` |
| WPA2 cracking | `aircrack-ng` | `hashcat` (GPU-accelerated) |
| PMKID capture | `hcxdumptool` | `bettercap` |
| Packet crafting | `scapy` | `mdk4` |
| Frame analysis | `wireshark` | `tshark` |
| AP simulation | `hostapd` | `bettercap wifi.ap` |
| MITM framework | `bettercap` | `ettercap`, `mitmproxy` |

---

## 16. Key Terms Glossary

| Term | Definition |
|------|-----------|
| **AP** | Access Point — the wireless router/base station |
| **STA** | Station — any wireless client device |
| **BSS** | Basic Service Set — one AP and its clients |
| **ESS** | Extended Service Set — multiple APs sharing an SSID |
| **DS** | Distribution System — the wired backbone connecting APs |
| **IBSS** | Independent BSS — ad-hoc (peer-to-peer) mode |
| **PHY** | Physical layer |
| **MAC** | Medium Access Control — Layer 2 addressing |
| **CSMA/CA** | Carrier Sense Multiple Access / Collision Avoidance — 802.11 channel access |
| **DCF** | Distributed Coordination Function — the base CSMA/CA algorithm |
| **NAV** | Network Allocation Vector — virtual carrier sense timer (Duration/ID field) |
| **OFDM** | Orthogonal Frequency Division Multiplexing — modulation scheme (802.11a/g/n/ac/ax) |
| **DSSS** | Direct Sequence Spread Spectrum — modulation used by 802.11b |
| **MIMO** | Multiple Input Multiple Output — multiple antennas (802.11n+) |
| **MCS** | Modulation and Coding Scheme — index defining speed |
| **PMK** | Pairwise Master Key — root key derived from passphrase |
| **PTK** | Pairwise Transient Key — session key derived from PMK |
| **GTK** | Group Temporal Key — key used for broadcast/multicast |
| **MIC** | Message Integrity Code — HMAC protecting frame integrity |
| **EAPOL** | EAP over LAN — protocol carrying 4-way handshake frames |
| **RSN** | Robust Security Network — the WPA2 framework (802.11i) |
| **RSNIE** | RSN Information Element — beacon field advertising cipher suites |
| **PMF/MFP** | Protected Management Frames (802.11w) — encrypts deauth/disassoc |
| **SAE** | Simultaneous Authentication of Equals — WPA3 key exchange |
| **IV** | Initialization Vector — per-packet random value in WEP |
| **KDF** | Key Derivation Function — e.g., PBKDF2, PRF |
| **PBKDF2** | Password-Based Key Derivation Function 2 — used to derive WPA2 PMK |
| **FCS** | Frame Check Sequence — CRC-32 integrity check on each frame |
| **OUI** | Organizationally Unique Identifier — first 3 bytes of MAC (vendor ID) |
| **PNL** | Preferred Network List — stored list of previously connected SSIDs |
| **KARMA** | Attack exploiting Probe Requests to serve a fake AP to all probing clients |
| **PMKID** | Pairwise Master Key Identifier — cached key identifier enabling clientless WPA2 attacks |
| **KRACK** | Key Reinstallation Attack — nonce-reuse attack on WPA2 4-way handshake (2017) |
| **Dragonblood** | Side-channel attacks on WPA3-SAE commit phase (2019) |
| **SIFS** | Short Inter-Frame Space — minimum gap between frames (ACKs, CTS) |
| **DIFS** | DCF IFS — minimum idle time before new frame transmission |
| **DFS** | Dynamic Frequency Selection — radar avoidance on 5 GHz channels |

---

## 17. Knowledge Check

Before proceeding to Module 01, you should be able to answer:

1. At which OSI layers does 802.11 operate, and what is the significance of each for an attacker?
2. What is the difference between a BSSID and an SSID? How does this affect targeting?
3. Why are management frames vulnerable by default? What standard addresses this?
4. Describe the three states in the 802.11 station state machine. What does a deauth frame do to a client in State 3?
5. What is the PMK and how is it derived from a WPA2 passphrase? Why does the SSID matter?
6. Why does capturing the 4-way handshake enable offline cracking?
7. What is the difference between WPA2-TKIP and WPA2-CCMP? Which is more secure and why?
8. Explain why a hidden SSID provides no real security.
9. What channels are non-overlapping in the 2.4 GHz band?
10. What is the PTW attack, and what does it exploit?
11. What is CSMA/CA and why does it matter for wireless injection attacks?
12. Explain what the RSN IE advertises and identify each component in the string `WPA2 CCMP PSK`.
13. What is the PNL and how does it enable KARMA attacks?
14. What are the two `hashcat` modes relevant to WPA2 and what file format does each use?
15. What is the PMKID and what advantage does it give an attacker over traditional handshake capture?

---

**Next:** [Module 01 — Linux Wireless Lab Setup](../module-01-linux-wireless-setup/)
