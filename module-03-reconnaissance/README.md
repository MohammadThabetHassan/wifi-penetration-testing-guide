# Module 03 — Wireless Reconnaissance

> **Prerequisites:** [Module 02 — Monitor Mode & Packet Injection](../module-02-monitor-mode/)
> **Next Module:** [Module 04 — Packet Analysis with Wireshark & Scapy](../module-04-packet-analysis/)

---

## Table of Contents

1. [Reconnaissance in Wireless Pentesting](#1-reconnaissance-in-wireless-pentesting)
2. [Introduction to airodump-ng](#2-introduction-to-airodump-ng)
3. [Full airodump-ng Flag Reference](#3-full-airodump-ng-flag-reference)
4. [Understanding airodump-ng Output](#4-understanding-airodump-ng-output)
5. [Basic Reconnaissance Scan](#5-basic-reconnaissance-scan)
6. [Targeted Capture — Locking to a Specific AP](#6-targeted-capture--locking-to-a-specific-ap)
7. [Writing & Managing Capture Files](#7-writing--managing-capture-files)
8. [Client (Station) Enumeration](#8-client-station-enumeration)
9. [WPS Detection](#9-wps-detection)
10. [Hidden SSID Detection](#10-hidden-ssid-detection)
11. [OUI Vendor Identification](#11-oui-vendor-identification)
12. [MAC Randomization — Modern Evasion](#12-mac-randomization--modern-evasion)
13. [Alternative Recon Tools](#13-alternative-recon-tools)
14. [Extracting Recon Data with tshark](#14-extracting-recon-data-with-tshark)
15. [airgraph-ng Visualization](#15-airgraph-ng-visualization)
16. [Common Issues & Troubleshooting](#16-common-issues--troubleshooting)
17. [Knowledge Check](#17-knowledge-check)

---

## 1. Reconnaissance in Wireless Pentesting

Wireless reconnaissance is the **passive intelligence-gathering phase** — discovering and cataloging all wireless networks and clients without transmitting any frames yourself. Monitor mode makes every frame on the air visible to you.

### The Reconnaissance Goal

Before any attack, answer these questions:

| Question | Source |
|----------|--------|
| What networks exist? | BSSID, SSID, Channel columns |
| What encryption? | ENC / CIPHER / AUTH columns |
| WPS enabled? | `--wps` flag or beacon IE parsing |
| Who is connected? | STATION section, client MACs |
| How much traffic? | #Data column (higher = more crackable) |
| What is each client looking for? | Probes column (PNL leakage) |
| What hardware is the AP? | OUI of BSSID |

### Recon Feeds Directly into Attack Selection

```
ENC = OPN           → Immediate MITM / Evil Twin (Module 09)
ENC = WEP           → IV collection + PTW crack (Module 05)
ENC = WPA2, AUTH = PSK → Handshake capture (Module 06) or PMKID (Module 12)
ENC = WPA2, AUTH = MGT → Rogue RADIUS (Module 13)
WPS = enabled       → Pixie Dust / PIN brute (Module 11)
ENC = WPA3          → Dragonblood side-channel (Module 13)
```

---

## 2. Introduction to airodump-ng

`airodump-ng` is the aircrack-ng suite's primary packet capture and AP discovery tool. It provides:

- **AP discovery** — Lists all access points in range with full metadata
- **Client detection** — Shows connected and probing stations
- **Capture file writing** — Saves raw 802.11 frames for offline analysis
- **WPA/WPA2 handshake detection** — Alerts when a handshake is captured
- **WPS detection** — Flags WPS-enabled APs

### Basic Syntax

```bash
airodump-ng [options] <interface>
```

---

## 3. Full airodump-ng Flag Reference

This is the complete reference for all flags used in this course. Every flag has a line-by-line explanation.

```bash
sudo airodump-ng [flags] wlan0mon
```

| Flag | Argument | Description |
|------|----------|-------------|
| `-c` / `--channel` | `<ch>` or `<ch1,ch2>` | Lock to channel(s). Comma-separate for multiple: `-c 1,6,11` |
| `--band` | `a`, `b`, `g`, `abg` | Frequency band. `a`=5GHz, `b`/`g`=2.4GHz, `abg`=both |
| `--bssid` | `<MAC>` | Filter output to one specific AP. Essential for targeted capture |
| `--essid` | `<name>` | Filter output to a specific SSID name |
| `-w` / `--write` | `<prefix>` | Write capture files. Creates `prefix-01.cap`, `prefix-01.csv`, etc. |
| `--output-format` | `pcap,ivs,csv,gps,kismet,netxml` | Capture file formats (comma-separate for multiple) |
| `--wps` | — | Show WPS information column for each AP |
| `--manufacturer` | — | Show AP manufacturer (from OUI lookup) |
| `--uptime` | — | Show estimated AP uptime (calculated from beacon sequence numbers) |
| `--berlin` | `<secs>` | Time (s) before removing an AP not heard recently (default: 120) |
| `--gpsd` | — | Connect to `gpsd` for GPS coordinate tagging in capture files |
| `-f` / `--ivs` | — | Only capture IVs (WEP cracking legacy mode) |
| `-t` | `<time>` | Stop capture after N seconds |
| `--beacons` | — | Record all beacon frames (not just first per AP) |
| `--update` | `<msecs>` | Screen refresh interval in milliseconds |
| `-r` / `--read` | `<file>` | Read from a capture file instead of interface |

### Critical Flag Combinations by Task

```bash
# General recon (all bands)
sudo airodump-ng --band abg --wps --manufacturer wlan0mon

# Targeted WPA2 handshake capture
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w handshake --output-format pcap wlan0mon

# WEP IV collection (legacy)
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 1 -w wep --output-format ivs wlan0mon

# GPS-tagged wardriving
sudo airodump-ng --band abg --gpsd -w wardrive --output-format pcap,gps,netxml wlan0mon
```

---

## 4. Understanding airodump-ng Output

### Top Section: Access Points

```
 CH  6 ][ Elapsed: 18 s ][ 2024-06-15 12:00

 BSSID              PWR  Beacons  #Data  #/s  CH   MB   ENC   CIPHER  AUTH  WPS  ESSID
 AA:BB:CC:DD:EE:FF  -45      142     28    4   6   130  WPA2  CCMP    PSK   2.0  HomeNet
 00:11:22:33:44:55  -52       89     12    1   1   130  WPA2  CCMP    PSK   1.0  Office
 11:22:33:44:55:66  -67       45      0    0  11    54  WEP   WEP     N/A    --  OldAP
 22:33:44:55:66:77  -71       23      0    0   6   130  WPA2  CCMP    MGT    --  CorpWifi
 33:44:55:66:77:88  -58       34      8    2  44   270  WPA3  CCMP    SAE    --  NewAP
 FF:EE:DD:CC:BB:AA  -62       31      0    0   8   130  WPA2  CCMP    PSK    --  <length: 0>
```

### Column-by-Column Breakdown

| Column | Description | Attack Relevance |
|--------|-------------|-----------------|
| **BSSID** | AP MAC address — unique target identifier | Primary key for `--bssid` filter |
| **PWR** | Signal in dBm. -1 = driver not reporting. Closer to 0 = stronger | Lower PWR = need to move closer for reliable injection |
| **Beacons** | Beacon frames received. Increments ~10/sec | Confirms AP is broadcasting and you're on the right channel |
| **#Data** | Total data frames captured | High count = active network = better for WEP IV collection |
| **#/s** | Data frames per second | Current traffic rate — useful for timing attacks |
| **CH** | AP's operating channel | Must lock here before attacking |
| **MB** | Max link speed. 54=802.11g, 130+=802.11n, 270+=802.11ac | Indicates 802.11 generation |
| **ENC** | Encryption: OPN/WEP/WPA/WPA2/WPA3 | Determines which attack module to use |
| **CIPHER** | Cipher: WEP/TKIP/CCMP/GCMP | CCMP=AES (strong cipher), TKIP=RC4 (weak, injectable) |
| **AUTH** | Authentication: PSK/MGT/SAE/OWE | PSK=Personal, MGT=Enterprise (802.1X), SAE=WPA3 |
| **WPS** | WPS version if enabled (1.0/2.0/--) | If present → Pixie Dust / PIN attack (Module 11) |
| **ESSID** | Network name. `<length: N>` = hidden SSID of N chars | Blank = hidden SSID — target for Section 10 |

### Bottom Section: Clients (Stations)

```
 BSSID              STATION            PWR    Rate   Lost  Frames  Notes       Probes
 AA:BB:CC:DD:EE:FF  11:22:33:44:55:66  -50   54e-1e    0      48              
 AA:BB:CC:DD:EE:FF  22:33:44:55:66:77  -60   54e-1e    0      12  EAPOL       
 (not associated)   33:44:55:66:77:88  -55   54e- 0    0      25  PROBING     HomeWiFi,OfficeNet
```

| Column | Description | Attack Relevance |
|--------|-------------|-----------------|
| **BSSID** | AP the client is associated with. `(not associated)` = probing only | Match with AP section to build network map |
| **STATION** | Client MAC address | Target MAC for directed deauth attacks |
| **PWR** | Client signal strength | Close enough for injection? |
| **Rate** | `TX-RX` rates. `54e` = 54 Mbps extended. `1e` = 1 Mbps | Shows link quality |
| **Lost** | Frames lost from this client | High = interference or distance issues |
| **Frames** | Total frames captured from client | Higher = more traffic to analyze |
| **Notes** | `EAPOL` = handshake captured; `WPA` = WPA1 handshake | **EAPOL here = handshake captured — stop capture, start cracking** |
| **Probes** | SSIDs this client probed for (PNL disclosure) | Evil Twin targets — clone these SSIDs (Module 09) |

---

## 5. Basic Reconnaissance Scan

### Step 1: General Survey

```bash
# Full channel-hopping survey — sees everything in range
sudo airodump-ng wlan0mon

# With WPS and manufacturer info (recommended for full recon)
sudo airodump-ng --wps --manufacturer wlan0mon
```

### Step 2: Band-Specific Scan

```bash
# 2.4 GHz only (channels 1–13)
sudo airodump-ng --band g wlan0mon

# 5 GHz only (channels 36–165)
sudo airodump-ng --band a wlan0mon

# Both bands (requires dual-band adapter)
sudo airodump-ng --band abg wlan0mon
```

### Step 3: Save Raw Recon Data

```bash
# Write all recon to CSV for later analysis
sudo airodump-ng --wps --manufacturer -w recon --output-format csv,pcap wlan0mon

# The CSV file (recon-01.csv) contains all AP and client data in a
# machine-readable format — parseable with Python/awk/grep for large assessments
```

### Reading the CSV Output

```bash
# Extract all WPA2 APs from the CSV
grep "WPA2" recon-01.csv | awk -F',' '{print $1,$14}'
# Field 1 = BSSID, Field 14 = ESSID

# Find all WPS-enabled APs
grep -i "wps" recon-01.csv | awk -F',' '{print $1,$14}'
```

---

## 6. Targeted Capture — Locking to a Specific AP

Once you've identified a target from the general scan, lock to it:

```bash
sudo airodump-ng \
  --bssid AA:BB:CC:DD:EE:FF \   # Target AP MAC — filter all other APs
  -c 6 \                        # Lock to channel 6 — never miss a frame
  -w capture \                  # Write to capture-01.cap, capture-01.csv
  --output-format pcap \        # PCAP for Wireshark and aircrack-ng
  wlan0mon                      # Monitor interface
```

### Flag-by-Flag Breakdown

```
--bssid AA:BB:CC:DD:EE:FF
    Filters display AND capture to this AP only.
    Without this, capture files contain frames from ALL APs — harder to process.

-c 6
    Locks the interface to channel 6. CRITICAL.
    Without channel lock, you hop and miss ~95% of frames on channel 6.
    This means no handshake capture, incomplete IV collection.

-w capture
    Writes to files: capture-01.cap (raw frames), capture-01.csv (metadata),
    capture-01.netxml (Kismet XML), capture-01.gps (if --gpsd used).
    The -01 suffix increments if the file already exists (capture-02.cap, etc.)

--output-format pcap
    Writes standard PCAP format readable by:
    - Wireshark (drag and drop)
    - aircrack-ng (WPA2 cracking, handshake verification)
    - hashcat (after conversion with hcxtools)
    - tshark (command-line analysis)

wlan0mon
    The monitor-mode interface. Must already be in monitor mode.
```

### Confirming Handshake Capture

When airodump-ng captures a WPA2 handshake, it shows in the top-right corner:

```
 CH  6 ][ Elapsed: 1 min ][ WPA handshake: AA:BB:CC:DD:EE:FF
```

And in the Notes column of the station:

```
 BSSID              STATION            Notes
 AA:BB:CC:DD:EE:FF  11:22:33:44:55:66  EAPOL   ← handshake captured
```

**When you see this → press Ctrl+C to stop the capture.** The handshake is in the `.cap` file.

---

## 7. Writing & Managing Capture Files

### Output File Types

| Extension | Content | Use Case |
|-----------|---------|----------|
| `.cap` / `.pcap` | Raw 802.11 frames | Wireshark analysis, aircrack-ng, hashcat (after conversion) |
| `-01.csv` | AP/client metadata (BSSID, ESSID, signal, etc.) | Parsing with grep/awk/Python, airgraph-ng input |
| `.netxml` | Kismet XML format | Importing into Kismet, network mapping tools |
| `.gps` | GPS coordinates per packet | Wardriving mapping, GeoKismet |
| `.ivs` | WEP IVs only (legacy) | Faster WEP cracking with aircrack-ng |

### Verifying Capture File Contents

```bash
# Count frames and check for WPA handshake
aircrack-ng capture-01.cap

# Output:
# Opening capture-01.cap
# Read 1524 packets.
# #  BSSID              ESSID                    Encryption
# 1  AA:BB:CC:DD:EE:FF  HomeNet                  WPA (1 handshake)
#                                           ^^^^^
#                              (1 handshake) = usable for cracking

# View first 20 frames with tcpdump
tcpdump -r capture-01.cap -n -e | head -20

# Count EAPOL frames specifically (4-way handshake frames)
tshark -r capture-01.cap -Y "eapol" -T fields -e frame.number -e wlan.sa -e wlan.da
```

### Cleaning Capture Files with wpaclean

Large capture files can contain thousands of irrelevant frames. `wpaclean` strips everything except the handshake:

```bash
# Install
sudo apt install aircrack-ng  # wpaclean is included

# Strip capture to handshake only
wpaclean clean-capture.cap capture-01.cap

# clean-capture.cap:
#   - Original: 50,000 frames → Cleaned: ~100 EAPOL frames
#   - Faster to process with hashcat/aircrack-ng
#   - Smaller file for transfer/storage
```

### Converting for hashcat

```bash
# Convert .cap to .hc22000 format (hashcat -m 22000)
hcxpcapngtool -o output.hc22000 capture-01.cap

# Verify the conversion
hcxpcapngtool --info capture-01.cap
# Shows: number of EAPOL M1/M2/M3/M4 pairs, PMKIDs found
```

---

## 8. Client (Station) Enumeration

### Identifying High-Value Clients

```bash
# Watch clients associated with target AP
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 wlan0mon

# Look for clients with:
# - High Frames count (active → more traffic = better target)
# - Probes column populated (reveals PNL)
# - Notes = EAPOL (performed a handshake recently)
```

### Extracting Client MACs from Capture

```bash
# Extract all client MACs associated with target AP
tshark -r capture-01.cap \
  -Y "wlan.bssid == aa:bb:cc:dd:ee:ff && wlan.fc.type_subtype == 0" \
  -T fields -e wlan.sa | sort -u

# All probe requests and what SSIDs clients want
tshark -r capture-01.cap \
  -Y "wlan.fc.type_subtype == 4" \
  -T fields -e wlan.sa -e wlan_mgt.ssid | sort -u
```

### Detecting Active vs. Idle Clients

```bash
# Monitor client frame rate in real time
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 wlan0mon
# Watch the Frames column — increment rate shows activity level
# A client with rapidly incrementing frames = streaming/browsing = active target
```

---

## 9. WPS Detection

WPS (Wi-Fi Protected Setup) is enabled on a large percentage of consumer routers. When detected, it enables the Pixie Dust or PIN brute force attacks in Module 11.

### Detecting WPS with airodump-ng

```bash
# The --wps flag adds a WPS column to output
sudo airodump-ng --wps --manufacturer wlan0mon

# WPS column shows:
# 2.0  → WPS version 2.0 (less vulnerable but still testable)
# 1.0  → WPS version 1.0 (more vulnerable, original Pixie Dust target)
# --   → WPS not detected / disabled
```

### Detecting WPS with wash

`wash` is a dedicated WPS scanner included with `reaver`:

```bash
# Scan for WPS-enabled APs
sudo wash -i wlan0mon

# Output:
# BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
# AA:BB:CC:DD:EE:FF    6  -45  2.0  No   TP-LINK   HomeNet   ← WPS 2.0, unlocked
# 00:11:22:33:44:55    1  -52  1.0  No   Netgear   OldAP     ← WPS 1.0, unlocked (Pixie Dust!)
# 11:22:33:44:55:66   11  -67  2.0  Yes  ASUS      Office    ← WPS locked (brute-force triggered lockout)
```

**Key columns:**
- `WPS` — Version (1.0 = older, more vulnerable to Pixie Dust)
- `Lck` — Locked = WPS lockout active (too many failed PINs)
- `Vendor` — AP manufacturer from OUI

```bash
# Flags for wash:
# -i wlan0mon   Interface in monitor mode
# -C            Ignore FCS errors (useful for weak signal)
# -s            Scan mode (continuous)
# -j            Output in JSON format
sudo wash -i wlan0mon -C -s
```

---

## 10. Hidden SSID Detection

### What airodump-ng Shows

When an SSID is hidden, the ESSID column shows:
- Blank field, OR
- `<length: N>` — where N is the actual SSID length in characters

```
BSSID              PWR  Beacons  #Data  CH  ENC   ESSID
AA:BB:CC:DD:EE:FF  -45      120     15   6  WPA2  <length: 8>
```

The SSID has 8 characters — the AP is visible, you just don't know the name yet.

### Method 1: Passive Wait (No Transmission)

```bash
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 wlan0mon
# Wait for any client to connect or roam — ESSID column populates automatically
```

### Method 2: Deauth + Wait (Forces Re-Association)

```bash
# Force existing clients to reconnect (reveals SSID in Association Request)
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# Then immediately watch airodump-ng — ESSID fills in when client reassociates
```

### Method 3: Wireshark Filter

```bash
# Open capture file, filter for Association Requests
# Display filter: wlan.fc.type_subtype == 0
# Look at the SSID field — it's in cleartext
tshark -r capture-01.cap -Y "wlan.fc.type_subtype == 0" \
  -T fields -e wlan.sa -e wlan_mgt.ssid
```

---

## 11. OUI Vendor Identification

The first 3 bytes (6 hex digits) of every MAC address are the **OUI (Organizationally Unique Identifier)** — assigned by IEEE to the manufacturer.

```
AA:BB:CC:DD:EE:FF
└──────┘
  OUI = AA:BB:CC → IEEE manufacturer lookup
```

### Why OUI Matters in Recon

- Identifies AP hardware → informs expected vulnerabilities (e.g., certain Netgear models have known Pixie Dust seeds)
- Identifies client device type (Apple, Samsung, Intel = laptop/phone)
- Detects spoofed MACs (random/locally-administered MACs have bit 1 of first octet set)

### OUI Lookup Methods

```bash
# Method 1: macchanger built-in lookup
macchanger --list | grep -i "tp-link"
# or look up a specific OUI
echo "D8:B1:90" | xargs -I {} sh -c 'grep -i {} /usr/share/misc/manuf 2>/dev/null || echo "not found"'

# Method 2: Wireshark OUI database (more complete)
# When you open a .cap in Wireshark, it automatically resolves OUIs
# View → Name Resolution → Resolve Network Addresses

# Method 3: airodump-ng built-in (--manufacturer flag)
sudo airodump-ng --manufacturer wlan0mon
# Adds a MANUF column with vendor names pulled from /usr/share/misc/manuf

# Method 4: iw output already resolves OUI for common chipsets
dmesg | grep "usb.*new" | grep -oP 'idVendor=\K[0-9a-f]+'
```

### Detecting MAC Randomization

Modern devices (iOS 14+, Android 10+) use **randomized MAC addresses** in probe requests. Indicators:

```bash
# Locally-administered MAC: bit 1 of first octet is SET
# First octet (hex) with bit 1 set: 02, 06, 0A, 0E, 12... (even hex + 2)
# Example: 2a:bb:cc:dd:ee:ff → '2a' = 0b00101010 → bit 1 (LSB of first octet) = 1 → randomized

# Detect randomized MACs in a capture
tshark -r capture-01.cap -Y "wlan.fc.type_subtype == 4" \
  -T fields -e wlan.sa | \
  awk -F: '{if (and(strtonum("0x"$1), 2)) print "RANDOM: "$0; else print "REAL:   "$0}'
```

---

## 12. MAC Randomization — Modern Evasion

Modern clients randomize both their probe request MAC and (since iOS 15 / Android 12) their probe SSID requests. This breaks PNL-based KARMA attacks and makes client tracking harder.

### Detection Strategy

Despite randomization, clients still leak fingerprinting data:

```bash
# Information Elements in Probe Requests fingerprint device type even with random MAC
# Look for: Supported rates, HT capabilities, Extended capabilities, Interworking
tshark -r capture-01.cap -Y "wlan.fc.type_subtype == 4" \
  -T fields -e wlan.sa -e wlan_mgt.ssid -e wlan.supported_rates -e wlan.ht.capabilities

# Different devices have distinctive combinations of supported rates and capabilities
# A specific combination uniquely identifies device model/OS even with random MAC
```

### When a Client Connects

Once a client actually associates (not just probing), many devices **stop randomizing** and use their real MAC for the association frame:

```bash
# Association Requests (subtype 0) often contain real MAC
tshark -r capture-01.cap \
  -Y "wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 2" \
  -T fields -e wlan.sa -e wlan_mgt.ssid
```

---

## 13. Alternative Recon Tools

### kismet — Passive Multi-Channel Monitor

```bash
# Start kismet with web interface
sudo kismet -c wlan0mon

# Web UI: http://localhost:2501 (default password: kismet)
# Features:
# - Real-time AP/client map
# - Automatic device fingerprinting
# - Hidden SSID detection
# - WPS detection
# - GPS integration
# - Long-term logging (.kismet database files)

# Run headless (no GUI)
sudo kismet --no-console-wrapper -c wlan0mon

# Parse kismet log with kismetdb
kismetdb_dump_devices --in kismet.kismet --out devices.json
```

### hcxdumptool — Advanced Passive Capture

```bash
# Best tool for PMKID capture (Module 12) and EAPOL capture
# Also excellent for recon — captures more frame types than airodump-ng

sudo hcxdumptool \
  -i wlan0mon \                      # Monitor interface
  -o recon.pcapng \                  # Output file (pcapng format required)
  --enable_status=1 \               # Show status output (required in v6+)
  --filtermode=2 \                  # Capture from all APs (not just targeted)
  --rcascan=active                   # Active: send probe requests to reveal more APs

# Convert output to viewable format
hcxpcapngtool --info recon.pcapng   # Summary of what was captured
```

### Comparison: airodump-ng vs. kismet vs. hcxdumptool

| Feature | `airodump-ng` | `kismet` | `hcxdumptool` |
|---------|--------------|---------|---------------|
| AP discovery | ✓ | ✓ | ✓ |
| Client detection | ✓ | ✓ | ✓ |
| WPS detection | ✓ (--wps) | ✓ | ✓ |
| PMKID capture | ✗ | ✗ | ✓ |
| Multi-channel simultaneous | ✗ | ✓ | ✗ |
| Long-term logging | CSV only | Full DB | pcapng |
| Web interface | ✗ | ✓ | ✗ |
| GPS integration | ✓ (--gpsd) | ✓ | ✗ |
| Output format | .cap / .csv | .kismet DB | .pcapng |

---

## 14. Extracting Recon Data with tshark

`tshark` (command-line Wireshark) enables powerful filtering and extraction from capture files.

```bash
# Extract all unique SSIDs from beacons
tshark -r capture-01.cap \
  -Y "wlan.fc.type_subtype == 8" \
  -T fields -e wlan_mgt.ssid | sort -u

# Extract all APs with their channel and ENC (from beacon RSN IE)
tshark -r capture-01.cap \
  -Y "wlan.fc.type_subtype == 8" \
  -T fields -e wlan.bssid -e wlan_mgt.ssid -e wlan.ds.current_channel \
  -e wlan_mgt.rsn.version | sort -u

# Extract all clients and their probe SSIDs (PNL leakage)
tshark -r capture-01.cap \
  -Y "wlan.fc.type_subtype == 4 && wlan_mgt.ssid" \
  -T fields -e wlan.sa -e wlan_mgt.ssid | sort -u

# Find EAPOL handshake frames (4-way handshake)
tshark -r capture-01.cap \
  -Y "eapol" \
  -T fields -e frame.number -e wlan.sa -e wlan.da -e eapol.keydes.msgnr

# Count data frames per AP (traffic volume)
tshark -r capture-01.cap \
  -Y "wlan.fc.type == 2" \
  -T fields -e wlan.bssid | sort | uniq -c | sort -rn
```

---

## 15. airgraph-ng Visualization

`airgraph-ng` generates visual graphs from `airodump-ng` CSV files.

```bash
# Install
sudo apt install airgraph-ng

# AP-Client Relationship Graph (CAPR)
airgraph-ng -i capture-01.csv -o capr.png -g CAPR
# Shows: lines between APs and their connected clients

# Client Probe Graph (CPG)
airgraph-ng -i capture-01.csv -o cpg.png -g CPG
# Shows: which SSIDs clients are probing for

# Open the generated PNG
eog capr.png
# or: xdg-open capr.png
```

**Use cases for reports:**
- Network topology visualization for pentest deliverables
- Identifying rogue APs (APs not in approved inventory)
- Finding isolated/unmanaged devices

---

## 16. Common Issues & Troubleshooting

### Issue: No APs appear in output

```bash
# 1. Confirm monitor mode
iwconfig wlan0mon | grep Mode  # Must say Monitor

# 2. Kill interfering processes
sudo airmon-ng check kill

# 3. Try both bands
sudo airodump-ng --band abg wlan0mon

# 4. Increase TX power for better receive sensitivity
sudo iw reg set BO && sudo iw dev wlan0mon set txpower fixed 3000
```

### Issue: AP appears but #Data stays at 0

This is normal for idle networks. Strategies:
```bash
# Wait — data counter only increases when clients are actively transmitting
# Or generate traffic artificially in your lab:
# Connect a phone to the AP and start streaming video
# This generates data frames that increment the counter
```

### Issue: Capture file shows "No valid WPA handshakes found"

```bash
# Verify with tshark
tshark -r capture-01.cap -Y "eapol" | wc -l
# Should be > 0 for a captured handshake

# Need all 4 EAPOL messages? Check which ones were captured:
tshark -r capture-01.cap -Y "eapol" -T fields \
  -e eapol.keydes.msgnr -e wlan.sa -e wlan.da
# Message 1 (AP→Client) + Message 2 (Client→AP) = minimum for cracking
```

### Issue: ESSID shows `<length: 0>` and never fills in

```bash
# No clients have connected during your capture window
# Option 1: Wait longer (hours if needed for sparse network)
# Option 2: Send deauth frames to force client reconnection
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon
# Option 3: The network may genuinely have no clients
```

---

## 17. Knowledge Check

Before proceeding to Module 04:

1. What does the `AUTH` column value `MGT` indicate in airodump-ng output, and which attack module targets it?
2. Write the complete airodump-ng command to perform a targeted capture: BSSID `AA:BB:CC:DD:EE:FF`, channel 11, write to `/tmp/target`, PCAP format, with WPS information shown.
3. What does the `#/s` column measure and how do you use it to select a target?
4. Explain why `#Data = 0` does not necessarily mean the network has no encryption.
5. What is the `wpaclean` tool and why should you use it before running hashcat?
6. You see `WPS: 1.0` in airodump-ng output. What attack does this enable and in which module?
7. What does `<length: 8>` in the ESSID column tell you about a hidden network?
8. Describe two ways to extract client probe requests (PNL) from a capture file — one using airodump-ng live and one using tshark offline.
9. What is an OUI and how does the `--manufacturer` flag in airodump-ng use it?
10. A client's MAC address starts with `2a:`. What does this indicate and how does it affect KARMA-style attacks?
11. What is the difference between `hcxdumptool` and `airodump-ng` for reconnaissance purposes? Name one capability hcxdumptool has that airodump-ng lacks.
12. Write the tshark command to extract all unique SSIDs from beacon frames in a capture file.
13. What does the `Notes: EAPOL` entry in the airodump-ng station section mean, and what should you do when you see it?
14. What flag do you add to `airodump-ng` to enable GPS coordinate tagging in the capture file?

---

**Next:** [Module 04 — Packet Analysis with Wireshark & Scapy](../module-04-packet-analysis/)
