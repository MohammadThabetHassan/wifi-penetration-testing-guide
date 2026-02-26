# Module 03 — Wireless Reconnaissance with airodump-ng

> **Prerequisites:** [Module 02 — Monitor Mode & Packet Injection](../module-02-monitor-mode/)
> **Next Module:** [Module 04 — Packet Analysis with Wireshark & Scapy](../module-04-packet-analysis/)

---

## Table of Contents

1. [Reconnaissance in Wireless Pentesting](#1-reconnaissance-in-wireless-pentesting)
2. [Introduction to airodump-ng](#2-introduction-to-airodump-ng)
3. [Understanding airodump-ng Output](#3-understanding-airodump-ng-output)
4. [Basic Reconnaissance Scan](#4-basic-reconnaissance-scan)
5. [Targeted Capture — Locking to a Specific AP](#5-targeted-capture--locking-to-a-specific-ap)
6. [Writing Capture Files](#6-writing-capture-files)
7. [Client (Station) Enumeration](#7-client-station-enumeration)
8. [Hidden SSID Detection](#8-hidden-ssid-detection)
9. [Advanced: airgraph-ng Visualization](#9-advanced-airgraph-ng-visualization)
10. [Common Issues & Troubleshooting](#10-common-issues--troubleshooting)
11. [Knowledge Check](#11-knowledge-check)

---

## 1. Reconnaissance in Wireless Pentesting

Wireless reconnaissance is the **passive intelligence-gathering phase** where you discover and catalog wireless networks and clients in range. Unlike active scanning (which involves transmitting probe requests), monitor mode allows you to **capture everything** already being transmitted over the air.

### The Reconnaissance Goal

Before attempting any attack, you need to answer:

- **What networks exist?** (SSIDs, BSSIDs, channels)
- **What encryption do they use?** (Open, WEP, WPA, WPA2, WPA3)
- **Who is connected?** (Client MAC addresses, signal strengths)
- **What's the traffic volume?** (Active vs. idle networks)
- **Are there vulnerabilities?** (WPS enabled? WEP? Hidden SSID?)

This module focuses on `airodump-ng` — the aircrack-ng suite's reconnaissance tool.

---

## 2. Introduction to airodump-ng

`airodump-ng` is the primary tool for wireless discovery and packet capture. It provides:

- **AP discovery** — Lists all access points in range with metadata
- **Channel monitoring** — Can lock to specific channels or hop
- **Client detection** — Shows connected stations/clients
- **Capture file writing** — Saves raw 802.11 frames to files
- **WPA/WPA2 handshake capture** — Extracts authentication handshakes

### Syntax

```bash
airodump-ng <options> <interface>

Common options:
  -c <channel>        : Lock to specific channel
  --band <abg>        : Band (a=5GHz, b=2.4GHz, g=2.4GHz)
  -w <prefix>         : Write capture files with prefix
  --bssid <mac>      : Filter by AP MAC address
  --essid <name>     : Filter by SSID
  --output-format    : Format (pcap, ivs, csv, gps, kismet)
```

---

## 3. Understanding airodump-ng Output

When you run `airodump-ng wlan0mon`, the output is divided into two sections:

### Top Section: Access Points (BSSIDs)

```
 CH  6 ][ Elapsed: 4 s ][ 2024-01-15 12:00
 BSSID              PWR  Beacons  #Data  CH  MB   ENC  CIPHER AUTH ESSID
 AA:BB:CC:DD:EE:FF  -45     120     15   6  130  WPA2 CCMP   PSK linksys
 00:11:22:33:44:55  -67      45      0  11  130  WPA2 CCMP   PSK MyNetwork
 FF:EE:DD:CC:BB:AA  -78      30      0   1   54  WEP  WEP   N/A  SecretNet
```

| Column | Description |
|--------|-------------|
| **BSSID** | Access Point MAC address (also called AP MAC) |
| **PWR** | Signal power (closer to 0 = stronger signal) |
| **Beacons** | Beacon frames received from this AP |
| **#Data** | Data frames captured (indicator of activity) |
| **CH** | Channel number |
| **MB** | Maximum speed (54 = 802.11g, 130+ = 802.11n) |
| **ENC** | Encryption: OPN, WEP, WPA, WPA2, WPA3 |
| **CIPHER** | Cipher: WEP, TKIP, CCMP, unknown |
| **AUTH** | Authentication: PSK, MGT (enterprise), OPN |
| **ESSID** | Network name (may be hidden = blank) |

### Bottom Section: Clients (Stations)

```
 BSSID              STATION            PWR   Rate    Lost  Frames  Notes  Probes
 AA:BB:CC:DD:EE:FF  11:22:33:44:55:66  -50   54e-1e    0      15         client1
 AA:BB:CC:DD:EE:FF  22:33:44:55:66:77  -60   54e-1e    0       8         (not associated)
 00:00:00:00:00:00  33:44:55:66:77:88  -55   54e- 0    0      25  PREN   HomeWiFi
```

| Column | Description |
|--------|-------------|
| **BSSID** | AP the client is associated with (or "not associated") |
| **STATION** | Client MAC address |
| **PWR** | Signal strength of client |
| **Rate** | TX/RX data rates (e.g., 54e = 54 Mbps TX, 1e = 1 Mbps RX) |
| **Lost** | Frames lost (can indicate distance/issues) |
| **Frames** | Frames captured from this client |
| **Notes** | WPA handshake captured, etc. |
| **Probes** | SSIDs this client has probed for |

---

## 4. Basic Reconnaissance Scan

### Starting a General Scan

```bash
sudo airodump-ng wlan0mon
```

This command:
- Enables automatic channel hopping (default behavior)
- Shows all APs in range in the top section
- Shows all detected clients in the bottom section
- Updates in real-time every second

### Scanning a Specific Band

```bash
# 2.4 GHz only
sudo airodump-ng --band g wlan0mon

# 5 GHz only  
sudo airodump-ng --band a wlan0mon

# Both bands
sudo airodump-ng --band abg wlan0mon
```

### Scanning a Specific Channel

```bash
# Lock to channel 6
sudo airodump-ng -c 6 wlan0mon
```

### Filtering by Encryption Type

While `airodump-ng` doesn't have a built-in encryption filter, you can pipe output:

```bash
# Show only WPA networks
sudo airodump-ng wlan0mon | grep "WPA"
```

---

## 5. Targeted Capture — Locking to a Specific AP

When you've identified a target, lock your capture to that specific AP:

```bash
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon
```

**Flags explained:**
```
--bssid AA:BB:CC:DD:EE:FF   # Target AP's MAC address
-c 6                         # Lock to channel 6
-w capture                   # Write to files: capture-01.cap, etc.
wlan0mon                     # Monitor interface
```

### Why Lock to a Channel?

When channel hopping, you miss ~95% of frames on any given channel (you're only there 5% of the time). To capture a WPA handshake or significant traffic, **always lock to the target's channel**.

---

## 6. Writing Capture Files

### Basic File Writing

```bash
# Creates capture-01.cap, capture-01.csv, etc.
sudo airodump-ng -w capture wlan0mon
```

### Output Formats

```bash
# PCAP (standard capture - use this)
sudo airodump-ng --output-format pcap -w capture wlan0mon

# IVS (aircrack-ng format - legacy WEP only)
sudo airodump-ng --output-format ivs -w capture wlan0mon

# Kismet (for Kismet integration)
sudo airodump-ng --output-format kismet -w capture wlan0mon
```

### Important Capture File Notes

- `airodump-ng` creates multiple files: `.cap` (packets), `.csv` (data), `.gps` (GPS coordinates if --gpsd specified), `.netxml` (Kismet XML)
- **Always use `-w`** when you need to capture a handshake or traffic for later analysis
- The file increments: `capture-01.cap`, `capture-02.cap`, etc.

### Checking Capture File Contents

```bash
# View captured packets
tcpdump -r capture-01.cap

# Count packets and check for handshake
aircrack-ng capture-01.cap
```

---

## 7. Client (Station) Enumeration

Clients are critical targets because:

1. **They reveal the network** — Even if SSID is hidden, clients probe for it
2. **They enable attacks** — Deauth attacks require a client to target
3. **They leak information** — Device names, operating systems in probe requests

### Identifying Connected Clients

```bash
# Targeted capture showing clients
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 wlan0mon
```

Look for clients in the bottom section with a matching BSSID.

### Detecting Probe Requests (Active Clients)

Clients actively searching for networks send **probe requests**:

```
 STATION            PWR  Probes
 11:22:33:44:55:66  -50  HomeWiFi, OfficeNet, Starbucks
```

This reveals networks the client has previously connected to — valuable for:
- **Evil Twin attacks** — Clone their known networks
- **Social engineering** — Use familiar network names
- **Post-exploitation** — Understand client behavior

### Deauthentication Consideration

For WPA/WPA2 attacks (Module 06-08), you typically need to **target a specific client** rather than just the AP. The client's MAC is needed for:
- Forcing re-authentication (to capture handshake)
- Performing targeted deauth attacks
- Associating traffic with a specific user

---

## 8. Hidden SSID Detection

### What Are Hidden Networks?

Some APs do not broadcast their SSID in beacon frames. These are called:
- **Hidden networks** (non-broadcasting SSID)
- **Closed networks**
- **SSID not broadcast**

### How to Detect Hidden Networks

When an SSID is hidden, `airodump-ng` shows it as blank or "<length: 0>":

```
BSSID              PWR  Beacons  #Data  CH  MB   ENC  CIPHER AUTH ESSID
AA:BB:CC:DD:EE:FF  -45     120     15   6  130  WPA2 CCMP   PSK
```

The AP **is still visible** — you have the BSSID, channel, encryption. The SSID is simply not being announced.

### Revealing the Hidden SSID

**Method 1: Wait for a client to connect**

When a client authenticates or re-associates, the SSID is transmitted in cleartext. Monitor the target channel:

```bash
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 wlan0mon
```

Wait for a client to reconnect — the ESSID column will populate.

**Method 2: Deauth attack to force re-authentication**

If no clients are currently connected, you can force them to reconnect (Module 08):

```bash
# Force deauth to trigger re-auth
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon
```

**Method 3: Use a passive tool**

```bash
# mdk4 beacon flooding can sometimes reveal hidden SSIDs
# when clients attempt to connect
```

### Limitations

- If the network has **no clients** and **never authenticates** while you're listening, you cannot determine the SSID
- Some enterprise hidden networks use 802.1X — the SSID may not appear even during authentication

---

## 9. Advanced: airgraph-ng Visualization

`airgraph-ng` creates visual graphs of your capture data.

### Installation

```bash
sudo apt install airgraph-ng
```

### Generating Graphs

```bash
# AP Client Relationship Graph
airgraph-ng -i capture-01.csv -o graph.png -g CAPR

# Client Probe Graph  
airgraph-ng -i capture-01.csv -o probes.png -g CPG
```

### Graph Types

| Flag | Graph Type | Shows |
|------|------------|-------|
| `CAPR` | Client to AP Relationship | Which clients are connected to which APs |
| `CPG` | Common Probe Graph | SSIDs clients are probing for |

### Use Cases

- **Visualizing large networks** — See network topology at a glance
- **Identifying patterns** — Client movement between APs
- **Reporting** — Professional visual output for penetration test reports

---

## 10. Common Issues & Troubleshooting

### Issue: No APs appear in output

```bash
# Cause 1: Not in monitor mode
# Verify:
iwconfig wlan0mon | grep Mode
# Should say: Mode:Monitor

# Cause 2: Wrong channel
# If target is on channel 6 but you're on channel 1, you'll see nothing
sudo iw dev wlan0mon set channel 6
```

### Issue: Clients appear but no APs

```bash
# This can happen if scanning with --essid filter
# and no matching APs are broadcasting that ESSID
# Remove filters and rescan:
sudo airodump-ng wlan0mon
```

### Issue: High packet loss (Lost column)

```bash
# High Lost values indicate:
# - Client too far away
# - Interference
# - Driver issues

# Fix: Get closer to the target, try different adapter, check driver
```

### Issue: Can't write capture files

```bash
# Check write permissions in current directory
ls -la . | grep .
# Ensure you have write permission

# Or specify full path:
sudo airodump-ng -w /tmp/capture wlan0mon
```

### Issue: Hidden SSID won't reveal

```bash
# The network may genuinely have no clients
# Or no client is connecting during your capture window
# Try:
# 1. Longer capture time
# 2. Different time of day (more users)
# 3. Targeting busier locations
```

---

## 11. Knowledge Check

Before proceeding to Module 04, you should be able to:

1. What information does the "PWR" column in airodump-ng represent, and what does a value closer to 0 indicate?
2. Write the exact command to capture only traffic from a specific BSSID on channel 11, saving to a file named "target".
3. Explain the difference between the "#Data" column and the "Beacons" column in airodump-ng output.
4. What does a blank ESSID in the airodump-ng output indicate, and how can you potentially reveal it?
5. What is the purpose of the "Probes" column in the station section of airodump-ng output?
6. Why should you lock your interface to a specific channel when targeting a particular AP, rather than using channel hopping?
7. Write the command to capture all traffic in the 5 GHz band.
8. What file formats does airodump-ng support with the --output-format flag? Which should you use for WPA2 handshake capture?
9. How can you differentiate between a WPA2-Personal network and a WPA2-Enterprise network using airodump-ng output?
10. What does the "Rate" column indicate in the stations section, and what does something like "54e-1e" mean?

---

**Next:** [Module 04 — Packet Analysis with Wireshark & Scapy](../module-04-packet-analysis/)
