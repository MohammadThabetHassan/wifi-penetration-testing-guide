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
7. [Testing Injection with aireplay-ng](#7-testing-injection-with-aireplay-ng)
8. [RFMON vs. Promiscuous Mode](#8-rfmon-vs-promiscuous-mode)
9. [Channel Hopping](#9-channel-hopping)
10. [Verifying Capture Quality](#10-verifying-capture-quality)
11. [Returning to Managed Mode](#11-returning-to-managed-mode)
12. [Advanced: Virtual Monitor Interfaces](#12-advanced-virtual-monitor-interfaces)
13. [Common Failures & Fixes](#13-common-failures--fixes)
14. [Knowledge Check](#14-knowledge-check)

---

## 1. What Is Monitor Mode?

In its default **managed mode**, a wireless network interface card (NIC) filters all incoming 802.11 frames at the hardware level. It only passes frames up the stack that are:
- Addressed to its own MAC (unicast)
- Broadcast (destination `FF:FF:FF:FF:FF:FF`)
- Multicast (specific group addresses)

Everything else — beacon frames from other APs, probe requests from other clients, data frames between other stations — is **silently discarded by the hardware**.

**Monitor mode** (also called RFMON — Radio Frequency MONitoring mode) bypasses this hardware filter. The card passes **every single 802.11 frame it hears** up the stack, regardless of destination address. This includes:

- Beacon frames from every AP in range
- Probe requests from every client in range
- Authentication/Association frames
- Data frames (encrypted or otherwise)
- Control frames (ACKs, RTS, CTS)
- EAPOL frames (WPA2 handshake)
- Deauthentication frames
- Everything on the selected channel

This is the foundational capability for **every offensive and defensive wireless technique** in this course.

### Why This Matters

Without monitor mode:
- `airodump-ng` shows nothing
- You cannot capture a WPA2 handshake
- You cannot inject deauthentication frames
- You cannot observe hidden SSIDs

With monitor mode: every frame on the air becomes visible.

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
   Managed Mode:                Monitor Mode:
   
   AP ──frames──► NIC           AP ──all frames──► NIC
                   │                                │
              [Hardware filter]              [No filter]
                   │                                │
          Only: to_my_MAC                   Every frame
          +broadcast                        on channel
                   │                                │
               [Driver]                         [Driver]
                   │                                │
         Normal TCP/IP stack              Raw 802.11 frames
                                          (radiotap header)
```

---

## 3. The Linux Wireless Subsystem: cfg80211 & mac80211

Understanding this stack helps you diagnose driver failures and understand why certain tools require specific kernel versions.

```
┌─────────────────────────────────────────┐
│        Userspace Tools                  │
│  aircrack-ng, iw, hostapd, wpa_supplicant│
└─────────────────┬───────────────────────┘
                  │ netlink (nl80211)
┌─────────────────▼───────────────────────┐
│              cfg80211                   │
│  (Wireless configuration API — kernel) │
│  Handles: mode changes, scan results,  │
│  regulatory domain, power management   │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│              mac80211                   │
│  (Shared 802.11 protocol stack)        │
│  Handles: frame aggregation, QoS,      │
│  rate control, fragment reassembly     │
│  Used by: ath9k, ath10k, iwlwifi...    │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│           Hardware Driver               │
│  (e.g., ath9k_htc, 88XXau, mt76x2u)   │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│          Physical Hardware              │
│       (Wi-Fi chipset + antenna)         │
└─────────────────────────────────────────┘
```

**The `nl80211` interface** is the modern netlink-based API used by `iw`, `hostapd`, and `wpa_supplicant` to communicate with `cfg80211`. When `airmon-ng` enables monitor mode, it uses `nl80211` commands under the hood.

**Why some drivers don't support injection:** The RTL8812AU driver (and most USB adapters) implements a custom driver that bypasses `mac80211` — it communicates directly with `cfg80211`. This is why some features work on some adapters and not others.

---

## 4. Enabling Monitor Mode — Three Methods

There are three approaches, each with specific use cases.

### Method 1: airmon-ng (Recommended for Beginners)

`airmon-ng` is the easiest approach. It kills interfering processes, creates a new monitor interface, and names it predictably.

```bash
# Step 1: Kill anything that might interfere
sudo airmon-ng check kill

# Expected output:
# Killing these processes...
#   PID  Name
#   743  NetworkManager
#   891  wpa_supplicant

# Step 2: Enable monitor mode
sudo airmon-ng start wlan0

# Expected output:
# PHY     Interface   Driver          Chipset
# phy1    wlan0       88XXau          Realtek RTL8812AU
#
#                 (mac80211 monitor mode vif enabled for [phy1]wlan0 on [phy1]wlan0mon)
#                 (mac80211 station mode vif disabled for [phy1]wlan0)

# Step 3: Verify
iwconfig wlan0mon
# Mode must say: Monitor
```

**Flag reference for `airmon-ng start`:**
```
airmon-ng start <interface> [channel]

  start          Enable monitor mode
  <interface>    The wireless interface to put into monitor mode (e.g. wlan0)
  [channel]      Optional: lock to a specific channel immediately (1-14 for 2.4GHz)

Example: sudo airmon-ng start wlan0 6
  → Enables monitor mode AND locks to channel 6
```

### Method 2: iw (Modern, Manual)

More surgical than airmon-ng — no process killing, no interface renaming.

```bash
# Bring interface down (required before mode change)
sudo ip link set wlan0 down

# Set monitor mode via iw
sudo iw dev wlan0 set type monitor

# Bring interface back up
sudo ip link set wlan0 up

# Confirm
iw dev wlan0 info
# type: monitor  ← success
```

**Optionally add flags for injection:**
```bash
# Some chipsets need 'control' flag to pass control frames
sudo iw dev wlan0 set monitor control

# 'other_bss' flag allows receiving frames from other BSSes
sudo iw dev wlan0 set monitor other_bss
```

### Method 3: iwconfig (Legacy, Still Works)

```bash
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
iwconfig wlan0
# Mode:Monitor ← confirmed
```

### Comparison Table

| Method | Auto kills processes | Renames interface | Preferred for |
|--------|---------------------|-------------------|---------------|
| `airmon-ng start` | Yes | Yes (wlan0 → wlan0mon) | Most attack workflows |
| `iw set type monitor` | No | No | Scripting, precise control |
| `iwconfig mode monitor` | No | No | Legacy compatibility |

---

## 5. Channel Selection & Locking

When in monitor mode, your adapter must be on the **same channel as your target** to capture its traffic. This is one of the most common mistakes beginners make.

### Finding the Target Channel

```bash
# Quick scan — will hop channels automatically
sudo airodump-ng wlan0mon

# The CH column shows each AP's channel
# BSSID              PWR  Beacons  #Data  CH  MB  ENC  CIPHER AUTH  ESSID
# AA:BB:CC:DD:EE:FF  -45      124      0   6  130  WPA2 CCMP   PSK  TargetNet
#                                           ^
#                                           Channel 6
```

### Locking to a Specific Channel

```bash
# Method 1: During airmon-ng start
sudo airmon-ng start wlan0 6

# Method 2: After monitor mode is already enabled
sudo iwconfig wlan0mon channel 6

# Method 3: Using iw (preferred, more options)
sudo iw dev wlan0mon set channel 6

# For 5GHz channels
sudo iw dev wlan0mon set channel 36

# With specific channel width (HT40+)
sudo iw dev wlan0mon set channel 36 HT40+
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

### 5 GHz Channel Reference (Common)

```
UNII-1 (Indoor): 36, 40, 44, 48
UNII-2 (DFS):    52, 56, 60, 64
UNII-2e (DFS):   100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140
UNII-3 (Outdoor): 149, 153, 157, 161, 165
```

**DFS channels** require radar detection — your adapter may not be able to inject on them due to regulatory restrictions.

### Verifying Current Channel

```bash
iw dev wlan0mon info
# channel 6 (2437 MHz), width: 20 MHz ← confirmed

iwconfig wlan0mon | grep Frequency
# Frequency:2.437 GHz  ← channel 6
```

---

## 6. Packet Injection — Theory & Mechanics

Packet injection is the ability to **transmit arbitrary, crafted 802.11 frames** into the wireless medium. This is distinct from normal transmission — injection bypasses the normal MAC layer association state machine.

### Why Injection Is Possible

A wireless NIC in monitor mode can transmit frames with:
- Any source MAC address (Address 2)
- Any destination MAC address (Address 1)
- Any BSSID (Address 3)
- Any frame type and subtype
- The FCS recalculated by the driver automatically

This is how `aireplay-ng` spoofs deauthentication frames from an AP it has never authenticated to.

### How the Kernel Passes Injected Frames

```
User tool (aireplay-ng)
    │
    │ Creates raw 802.11 frame
    │ (with radiotap header specifying channel, rate, TX power)
    │
    ▼
Raw socket (AF_PACKET / PF_PACKET)
    │
    ▼
Driver's TX path
    │
    │ Driver recalculates FCS
    │ Prepends preamble
    │
    ▼
RF transmission (over the air)
```

### Radiotap Header

When injecting, tools prepend a **radiotap header** — a standardized metadata structure that instructs the driver about transmission parameters:

```
Radiotap Header Fields (relevant to injection):
  Rate:       TX data rate in 0.5 Mbps units (e.g., 2 = 1 Mbps, 12 = 6 Mbps)
  Channel:    Frequency + channel flags
  TX Flags:   Disable ACK waiting, frame sequence override
  MCS:        For 802.11n HT rates
  Antenna:    Which antenna to use
```

`aireplay-ng` handles the radiotap header automatically. When writing custom injection scripts with Scapy (Module 04), you construct it manually.

---

## 7. Testing Injection with aireplay-ng

Always test injection before attempting any attack. A failed injection test means no attack will work.

### Basic Injection Test

```bash
sudo aireplay-ng --test wlan0mon
# Long form: sudo aireplay-ng -9 wlan0mon

# -9 / --test  Run injection test
# wlan0mon     Monitor mode interface
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

# -b <BSSID>   Target a specific AP's BSSID
# Reports per-AP injection success rate (percentage)
# < 80% = unreliable; investigate driver, channel, distance
```

### What to Do If Injection Fails

```bash
# 1. Confirm you're on the correct channel
sudo iw dev wlan0mon set channel 6
sudo aireplay-ng -9 wlan0mon

# 2. Check TX power
iwconfig wlan0mon | grep Tx-Power
# If very low, try: sudo iw dev wlan0mon set txpower fixed 2000

# 3. Verify monitor mode is actually set
iwconfig wlan0mon | grep Mode
# Must say: Mode:Monitor

# 4. Try reinstalling with monitor flags
sudo ip link set wlan0mon down
sudo iw dev wlan0mon set monitor control
sudo ip link set wlan0mon up
sudo aireplay-ng -9 wlan0mon
```

---

## 8. RFMON vs. Promiscuous Mode

These are frequently confused. They are different at the hardware level and serve different purposes.

| Feature | Monitor Mode (RFMON) | Promiscuous Mode |
|---------|---------------------|-----------------|
| **Layer** | PHY + MAC (Layer 1+2) | MAC (Layer 2) |
| **Captures** | All 802.11 frames incl. management/control | Only data frames you're associated to |
| **Requires association** | No | Yes (must be connected to the network) |
| **Frame format** | Raw 802.11 with radiotap | Ethernet (802.3) |
| **Injection** | Yes | No |
| **Use case** | Wireless attacks, passive recon | Wired/post-association sniffing |
| **Tool** | `airodump-ng`, `tcpdump -i wlan0mon` | `tcpdump -i eth0 -p`, Wireshark |

**Key point:** Enabling promiscuous mode on a wireless adapter in managed mode does NOT give you monitor mode. You still only see frames on your associated network. You must use RFMON for any of the attacks in this course.

---

## 9. Channel Hopping

When performing general reconnaissance (Module 03), you want to see APs on all channels — not just one. This is called **channel hopping**.

`airodump-ng` handles channel hopping automatically by default. However, there are times when you need to control it manually.

### Default Behavior

```bash
# Without locking to a channel, airodump-ng hops every ~0.25 seconds
sudo airodump-ng wlan0mon
# Cycles through: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 (2.4GHz)
# The CH column in output shows current channel being monitored
```

### Manual Channel Hopping Script

For situations where you need custom hop sequences:

```bash
#!/bin/bash
# channel-hop.sh — Manual channel hopper for wlan0mon
# Usage: ./channel-hop.sh wlan0mon

IFACE=${1:-wlan0mon}
CHANNELS=(1 2 3 4 5 6 7 8 9 10 11 36 40 44 48 149 153 157 161)
DWELL=0.25  # seconds per channel

while true; do
  for CH in "${CHANNELS[@]}"; do
    sudo iw dev "$IFACE" set channel "$CH" 2>/dev/null
    sleep "$DWELL"
  done
done
```

### Hopping on Both Bands

```bash
# airodump-ng --band flag
sudo airodump-ng --band abg wlan0mon
# a = 5 GHz (802.11a)
# b = 2.4 GHz (802.11b)
# g = 2.4 GHz (802.11g)
# Combined: abg = scan both bands

# Note: requires an adapter that supports both bands (e.g., RTL8812AU)
```

### The Channel Hopping Trade-off

When channel hopping:
- You get **broad coverage** (see many networks)
- But you **miss frames** on any single channel during the dwell time on other channels

When locked to a channel:
- You **never miss a frame** on that channel
- But you're **blind to all other channels**

**Rule of thumb:**
- Recon phase → channel hop to find targets
- Attack phase → lock to target's channel

---

## 10. Verifying Capture Quality

After enabling monitor mode, verify you're capturing useful frames before proceeding to any attack.

### Quick Verification with tcpdump

```bash
# Capture 10 frames and print their type/subtype
sudo tcpdump -i wlan0mon -c 10 -e 2>&1 | head -30

# Expected: see management frames (Probe Request, Beacon), control frames
# 12:00:01 AA:BB:CC (oui Unknown) > Broadcast, BSSID:DD:EE:FF (oui Unknown),
#          Probe Request (0) [1.0* 2.0* 5.5* 11.0* 6.0 9.0 12.0 18.0 Mbit]
```

### Using airodump-ng as a Quick Check

```bash
sudo airodump-ng wlan0mon

# Within 5-10 seconds you should see:
# - Beacon count climbing in the 'Beacons' column
# - Multiple SSIDs appearing
# - Signal strengths in the 'PWR' column

# If the output is blank/empty after 30 seconds:
# → Monitor mode didn't actually enable
# → Wrong channel (nothing broadcasting on current channel)
# → Driver issue
```

### Wireshark Verification

```bash
# Open Wireshark on the monitor interface
sudo wireshark -i wlan0mon -k

# Apply display filter: wlan.fc.type == 0
# (shows management frames only)
# You should immediately see Beacon frames and Probe Requests
```

---

## 11. Returning to Managed Mode

Always clean up after your session.

### Using airmon-ng

```bash
# Stop monitor mode
sudo airmon-ng stop wlan0mon

# Expected output:
# PHY     Interface   Driver          Chipset
# phy1    wlan0mon    88XXau          Realtek RTL8812AU
#         (mac80211 station mode vif enabled on [phy1]wlan0)
#         (mac80211 monitor mode vif disabled for [phy1]wlan0mon)

# Restart networking
sudo systemctl start NetworkManager
```

### Manual Cleanup

```bash
sudo ip link set wlan0mon down
sudo iw dev wlan0mon set type managed
sudo ip link set wlan0mon up

# Or if airmon-ng renamed the interface:
# Need to rename back (iw doesn't do this automatically)
sudo ip link set wlan0mon name wlan0
```

### Full Reset (Nuclear Option)

```bash
# Reload the driver entirely
sudo rmmod 88XXau
sudo modprobe 88XXau
sudo systemctl restart NetworkManager
```

---

## 12. Advanced: Virtual Monitor Interfaces

You can create a second virtual interface in monitor mode while keeping the original in managed mode. This is useful when you need both internet access and monitoring simultaneously.

```bash
# Create a virtual monitor interface on the same physical radio
sudo iw phy phy0 interface add wlan0mon type monitor

# wlan0     → still in managed mode (internet access)
# wlan0mon  → new virtual interface in monitor mode

# Bring the virtual interface up
sudo ip link set wlan0mon up

# Verify both exist
iw dev
# phy#0
#   Interface wlan0      → type: managed
#   Interface wlan0mon   → type: monitor

# Delete the virtual interface when done
sudo iw dev wlan0mon del
```

**Caveat:** Both interfaces share the same physical radio. If `wlan0` is connected to a channel-6 AP, `wlan0mon` will also be locked to channel 6. You cannot independently control channels on virtual interfaces sharing one radio. For independent channel control, use a second physical adapter.

---

## 13. Common Failures & Fixes

### Issue: `wlan0mon` disappears immediately after creation

```bash
# Cause: NetworkManager restarts and takes the interface back
# Fix:
sudo systemctl stop NetworkManager
sudo airmon-ng start wlan0

# Or prevent NetworkManager from managing USB adapters by
# adding to /etc/NetworkManager/NetworkManager.conf:
# [device]
# wifi.scan-rand-mac-address=no
```

### Issue: Monitor mode shows no frames even though APs are visible

```bash
# Cause 1: Wrong channel
sudo iw dev wlan0mon set channel 6

# Cause 2: TX power too low to receive anything
sudo iw dev wlan0 set txpower fixed 3000  # 30dBm

# Cause 3: Adapter is in 5GHz mode but targets are 2.4GHz
sudo iw dev wlan0mon set freq 2412  # Force 2.4GHz

# Cause 4: check radiotap header support
sudo tcpdump -i wlan0mon -n -e 2>&1 | head -5
# Should show 802.11 frames, NOT ethernet frames
# If you see ethernet frames, adapter is NOT in monitor mode
```

### Issue: Injection works on some APs but not others

This is expected. Factors that affect injection success:
- **Distance:** Must be close enough for the AP to receive your injected frames
- **Rate:** Some APs ignore frames at certain data rates
- **Channel:** Must be on the AP's channel
- **Band:** 5GHz injection often needs 5GHz adapter

```bash
# Try forcing a lower, more compatible data rate
sudo iwconfig wlan0mon rate 1M  # 1 Mbps — maximum compatibility
sudo aireplay-ng -9 -b AA:BB:CC:DD:EE:FF wlan0mon
```

### Issue: `ERROR: Failed to set wlan0 to monitor mode: Device or resource busy`

```bash
# Something is still holding the interface
sudo fuser /dev/rfkill
sudo airmon-ng check kill
sudo lsof | grep wlan0
# Kill any process using the interface
sudo kill -9 <PID>
sudo airmon-ng start wlan0
```

---

## 14. Knowledge Check

Before proceeding to Module 03, you should be able to:

1. Explain in precise technical terms what monitor mode does at the hardware level that managed mode does not.
2. What is the difference between `cfg80211` and `mac80211`? Which one does `iw` communicate with?
3. Write the exact command sequence to enable monitor mode using `iw` (without airmon-ng), lock to channel 11, then return to managed mode.
4. What is a radiotap header and what purpose does it serve during packet injection?
5. Explain the difference between RFMON (monitor mode) and promiscuous mode. Why doesn't promiscuous mode work for wireless attacks?
6. What does a 100% injection success rate on `aireplay-ng -9` confirm?
7. When should you channel-hop vs. lock to a specific channel? Name one scenario for each.
8. How do you create a virtual monitor interface while keeping the original interface in managed mode? What is the limitation?
9. What command verifies the channel your monitor interface is currently locked to?
10. A target AP is on channel 36. What command locks your monitor interface to that channel?

---

**Next:** [Module 03 — Wireless Reconnaissance with airodump-ng](../module-03-reconnaissance/)
