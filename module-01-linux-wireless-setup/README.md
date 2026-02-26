# Module 01 — Linux Wireless Lab Setup

> **Prerequisites:** [Module 00 — Networking & 802.11 Foundations](../module-00-foundations/)
> **Next Module:** [Module 02 — Monitor Mode & Packet Injection](../module-02-monitor-mode/)

---

## Table of Contents

1. [Lab Philosophy & Safety](#1-lab-philosophy--safety)
2. [Hardware Selection — Choosing Your Wireless Adapter](#2-hardware-selection--choosing-your-wireless-adapter)
3. [Operating System Setup — Kali Linux](#3-operating-system-setup--kali-linux)
4. [VM vs. Bare Metal vs. Live Boot](#4-vm-vs-bare-metal-vs-live-boot)
5. [Driver Installation](#5-driver-installation)
6. [Core Linux Wireless Tools](#6-core-linux-wireless-tools)
7. [TX Power & Regulatory Domains](#7-tx-power--regulatory-domains)
8. [Identifying & Managing Interfaces](#8-identifying--managing-interfaces)
9. [Killing Interfering Processes](#9-killing-interfering-processes)
10. [Verifying Your Setup](#10-verifying-your-setup)
11. [Dual-Adapter Setup](#11-dual-adapter-setup)
12. [Lab Network Topology](#12-lab-network-topology)
13. [Essential Toolchain Installation](#13-essential-toolchain-installation)
14. [Troubleshooting Common Issues](#14-troubleshooting-common-issues)
15. [Knowledge Check](#15-knowledge-check)

---

## 1. Lab Philosophy & Safety

Before touching hardware, establish these non-negotiable principles:

### Isolation Is Mandatory
Every technique in this course must be practiced on a **network you own and control** in an environment isolated from production infrastructure. A dedicated wireless lab router (a cheap TP-Link or ASUS running stock firmware) costs under $30 and eliminates all legal risk.

**Never test against:**
- Public Wi-Fi (airports, cafés, hotels)
- Neighbors' networks
- Your employer's network without a signed penetration test agreement
- Any network not physically owned by you or your client

### Lab Topology (Minimum)
```
[Attacker Machine]     [Lab Router (Target)]     [Victim Client]
  Kali Linux           192.168.100.1              Any device
  External USB adapter WPA2-PSK configured        Phone/laptop
  Monitor mode capable Isolated VLAN/subnet       For generating traffic
```

### Documentation Discipline
In real engagements you will always write up your findings. Start this habit now. Keep a lab notebook (markdown file or physical) with:
- Commands run
- Output observed
- Timestamps
- What worked and what failed

---

## 2. Hardware Selection — Choosing Your Wireless Adapter

Not all Wi-Fi adapters support monitor mode and packet injection. This is the most common point of failure for beginners.

### What to Look For
An adapter must support:
1. **Monitor mode** — ability to capture all 802.11 frames in range, not just frames addressed to you
2. **Packet injection** — ability to transmit arbitrary 802.11 frames
3. **Linux driver** with active support

These capabilities depend on the **chipset**, not the brand name on the box.

### Recommended Adapters (Tested & Confirmed)

| Adapter | Chipset | Band | Injection | Notes |
|---------|---------|------|-----------|-------|
| **Alfa AWUS036ACH** | RTL8812AU | 2.4/5 GHz | Yes | Best all-rounder; dual-band; high power; USB 3.0 |
| **Alfa AWUS036ACM** | MT7612U | 2.4/5 GHz | Yes | Excellent Linux support; mainline kernel driver |
| **Alfa AWUS036NHA** | AR9271 | 2.4 GHz | Yes | Native kernel support; most stable |
| **Alfa AWUS036NH** | RT3070 | 2.4 GHz | Yes | Budget option; reliable |
| **Panda PAU09** | RT5572 | 2.4/5 GHz | Yes | Good value dual-band |
| **TP-Link TL-WN722N v1** | AR9271 | 2.4 GHz | Yes | **v1 only** — v2/v3 use Realtek (no injection) |
| **Hak5 WiFi Coconut** | 14× MT7612U | 2.4 GHz | Partial | 14-channel simultaneous capture |

### Chipsets to Avoid
- Broadcom (BCM series) — poor Linux support, no injection
- Intel (iwlwifi) — built-in laptop adapters, limited monitor mode
- MediaTek MT7921 — injection unreliable as of kernel 6.x

### Checking Your Chipset
```bash
# If adapter is already plugged in:
lsusb

# Example output:
Bus 001 Device 004: ID 0bda:8812 Realtek Semiconductor Corp. RTL8812AU 802.11a/b/g/n/ac

# Cross-reference the USB ID (0bda:8812) against chipset databases
# 0bda = Realtek Vendor ID
# 8812 = RTL8812AU product ID

# For PCI/PCIe adapters:
lspci | grep -i wireless
```

---

## 3. Operating System Setup — Kali Linux

### Why Kali Linux?
Kali Linux (maintained by Offensive Security) ships with:
- The full aircrack-ng suite pre-installed
- Pre-built drivers for common wireless chipsets
- hashcat, hcxdumptool, wireshark, hostapd, dnsmasq, and more
- A kernel patched for wireless research

### Alternatives
| OS | Notes |
|----|-------|
| **Parrot OS Security** | Good alternative; lighter than Kali |
| **BlackArch** | Arch-based; more advanced setup required |
| **Ubuntu + manual tools** | Works but requires manual driver and tool installation |
| **Windows** | Not recommended — most tools are Linux-only or severely limited |

### Kali Installation (Overview)
1. Download the latest Kali ISO from `https://www.kali.org/get-kali/`
2. Verify the SHA256 checksum
3. Flash to USB with `dd` or Balena Etcher
4. Boot and install (or run live)

```bash
# Verify ISO integrity (example)
sha256sum kali-linux-2024.4-installer-amd64.iso
# Compare against the hash published on kali.org
```

### Post-Install First Steps
```bash
# Update all packages
sudo apt update && sudo apt full-upgrade -y

# Install any missing wireless tools
sudo apt install -y aircrack-ng hashcat hcxdumptool hcxtools \
    wireshark-qt tshark hostapd dnsmasq reaver bully mdk4 \
    macchanger iw wireless-tools net-tools wifite kismet

# Verify aircrack-ng version
aircrack-ng --version
```

---

## 4. VM vs. Bare Metal vs. Live Boot

This is a critical decision that affects every tool in this course.

### Virtual Machine (VirtualBox / VMware)

**Pros:** Easy snapshots, disposable, no risk to host OS.
**Cons:** USB passthrough is required for external adapters and is unreliable with packet injection. Internal adapters are completely inaccessible.

**USB Passthrough Setup (VirtualBox):**
1. Install VirtualBox Extension Pack
2. In VM Settings → USB → Enable USB 3.0 Controller
3. Add a USB filter for your adapter's Vendor/Product ID
4. Plug in adapter **after** VM starts, then attach via Devices → USB

```bash
# Inside VM, verify adapter is visible
lsusb
dmesg | tail -20   # look for USB device attach messages
```

**Known Issues with VMs:**
- Packet injection may drop or fail intermittently
- Monitor mode sometimes fails silently
- Channel hopping is less reliable
- **Recommendation: Use bare metal or live boot for injection-heavy modules (05–14)**

### Bare Metal Installation

Best option for this course. Full hardware access, no USB passthrough, native kernel driver loading.

### Live USB Boot

Boot Kali from a USB drive without installing. Loses state on reboot (unless persistence is configured). Good for testing before full installation.

**Creating a Persistent Live USB:**
```bash
# On Linux host — flash Kali live ISO
sudo dd if=kali-linux-2024.4-live-amd64.iso of=/dev/sdX bs=4M status=progress
sync
# /dev/sdX = your USB drive (find with lsblk — do NOT overwrite your system drive)
```

---

## 5. Driver Installation

### Checking If Your Adapter's Driver Is Already Loaded

```bash
# List loaded kernel modules
lsmod | grep -E '8812|8814|ath9k|rt2800|mt76'

# Check kernel messages after plugging in adapter
dmesg | tail -30

# Look for lines like:
# [  123.456] usb 1-1.4: new high-speed USB device
# [  123.890] rtl8812au: USB device detected
```

### RTL8812AU Driver (Alfa AWUS036ACH — Most Common)

The RTL8812AU chipset requires an out-of-tree driver. Kali includes it but may need rebuilding after kernel updates.

```bash
# Method 1: Kali package (recommended)
sudo apt install -y realtek-rtl88xxau-dkms
# DKMS (Dynamic Kernel Module Support) auto-rebuilds the module
# when the kernel updates

# Verify module loaded
modinfo 88XXau | grep -E 'filename|version'

# If it fails to load automatically:
sudo modprobe 88XXau

# Verify it's up
lsmod | grep 88XXau
```

### AR9271 Driver (Alfa AWUS036NHA — Native Kernel)

AR9271 uses the `ath9k_htc` driver which is built into the mainline Linux kernel. No installation needed.

```bash
# Verify after plugging in
dmesg | grep ath9k
# Expected: ath9k_htc: Firmware ath9k_htc/htc_9271-1.4.0.fw loaded successfully

lsmod | grep ath9k_htc
```

### MT7612U Driver (Alfa AWUS036ACM)

Uses the `mt76x2u` driver in mainline kernel since 4.19.

```bash
lsmod | grep mt76
# Expected: mt76x2u, mt76x2_common, mt76_usb, mt76
```

### Building Drivers from Source (Advanced)

When the packaged version is outdated:

```bash
# Example: RTL8812AU from GitHub
sudo apt install -y dkms git build-essential linux-headers-$(uname -r)
# linux-headers-$(uname -r)  ← installs headers matching your RUNNING kernel version

git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au

# Install via DKMS (persists across kernel upgrades)
sudo make dkms_install
# make dkms_install  ← registers the module with DKMS framework;
#                       auto-rebuilds when 'apt upgrade' updates the kernel

# Or manual (does not persist):
make
sudo make install
sudo modprobe 88XXau
# modprobe 88XXau  ← loads the compiled .ko module into the running kernel
```

---

## 6. Core Linux Wireless Tools

These are the foundational tools you will use in every module.

### `iw` — Modern Wireless Configuration Tool

`iw` is the replacement for the deprecated `iwconfig`. It communicates directly with the Linux kernel's `cfg80211` wireless subsystem.

```bash
# List all wireless interfaces and their capabilities
iw dev

# Sample output:
# phy#0
#     Interface wlan0
#         ifindex 3
#         wdev 0x1
#         addr aa:bb:cc:dd:ee:ff
#         type managed
#         channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
#         txpower 20.00 dBm

# Show detailed capabilities of a physical radio (phy#0)
iw phy phy0 info
# Shows: supported bands, frequencies, monitor mode support, injection,
#        antenna count, supported interface modes, max TX power

# Show information about a specific interface
iw dev wlan0 info

# Scan for nearby networks (requires interface in managed mode)
sudo iw dev wlan0 scan | grep -E 'SSID|signal|freq'
```

### `iwconfig` — Legacy Tool (Still Useful)

```bash
# Show all wireless interfaces
iwconfig

# Sample output:
# wlan0     IEEE 802.11  ESSID:off/any
#           Mode:Managed  Frequency:2.412 GHz  Access Point: Not-Associated
#           Tx-Power=20 dBm
#           Retry short limit:7   RTS thr:off   Fragment thr:off
#           Encryption key:off
#           Power Management:on
```

**Key fields:**
- `Mode:Managed` — normal client mode
- `Mode:Monitor` — monitor mode (capture all frames)
- `Mode:Master` — AP mode
- `Tx-Power` — transmit power in dBm; higher = greater range
- `Frequency` — current operating channel

### `ip link` — Interface Management

```bash
# List all network interfaces
ip link show

# Bring an interface up
sudo ip link set wlan0 up

# Bring an interface down (required before changing mode)
sudo ip link set wlan0 down

# Rename an interface
sudo ip link set wlan0 name wlan0mon
```

### `rfkill` — RF Kill Switch Manager

Many systems have hardware or software RF kill switches that disable wireless radios.

```bash
# List all RF-killable devices
rfkill list

# Sample output:
# 0: phy0: Wireless LAN
#    Soft blocked: no
#    Hard blocked: no
# 1: phy1: Wireless LAN
#    Soft blocked: yes    ← Software disabled!
#    Hard blocked: no

# Unblock a specific device
sudo rfkill unblock 1

# Unblock ALL wireless devices
sudo rfkill unblock wifi
sudo rfkill unblock all
```

**Hard blocked** = physical hardware switch on the laptop. Must be toggled physically.
**Soft blocked** = software-controlled via kernel. Fixed with `rfkill unblock`.

---

## 7. TX Power & Regulatory Domains

### Why This Matters

Your adapter's maximum transmit power (TX power) is governed by:
1. **Hardware capability** — the chipset's physical maximum (typically 20–30 dBm)
2. **Regulatory domain** — the legal limit for your country (enforced by `CRDA` and `iw`)

Higher TX power = better signal range for injection and capture. Many adapters ship with conservative defaults.

### Checking Your Regulatory Domain

```bash
# See current regulatory domain
iw reg get

# Sample output:
# global
# country US: DFS-FCC
#     (2400 - 2483.5 @ 40), (N/A, 30), (N/A)
#     (5150 - 5250 @ 80), (N/A, 23), (N/A), NO-OUTDOOR, AUTO-BW
#     (5250 - 5350 @ 80), (N/A, 24), (0), DFS, AUTO-BW

# country US → limited to 30 dBm on 2.4 GHz
# country BO (Bolivia) → unconstrained in older kernels (common pentesting trick)
```

### Changing Regulatory Domain

```bash
# Set to a region with higher allowed TX power
# WARNING: Only do this in your isolated lab; illegal on public spectrum
sudo iw reg set BO
# BO = Bolivia — historically unrestricted domain in many driver implementations

# Verify change took effect
iw reg get
```

### Setting TX Power

```bash
# Check current TX power
iwconfig wlan0 | grep Tx-Power
# or
iw dev wlan0 info | grep txpower

# Set TX power manually (interface must be up, monitor mode preferred)
sudo iw dev wlan0mon set txpower fixed 3000
# 3000 = 30 dBm (value is in mBm = dBm × 100)
# Fixed means do not let the driver override this

# Alternative via iwconfig (deprecated but still works on some drivers)
sudo iwconfig wlan0mon txpower 30

# Verify
iwconfig wlan0mon | grep Tx-Power
# Tx-Power=30 dBm
```

### CRDA and the cfg80211 Subsystem

The **Central Regulatory Domain Agent (CRDA)** enforces country-specific power limits at the kernel level. Even with `iw reg set`, some drivers (especially mainline ones like `ath9k`) strictly enforce these limits. Out-of-tree drivers like RTL8812AU are generally less strict.

```bash
# Check if CRDA is installed and functional
which crda
iw reg get | head -3

# If regulatory enforcement is causing issues:
# Some operators set 'regdomain 00' in /etc/default/crda for unrestricted lab use
# This is for isolated lab environments ONLY
```

---

## 8. Identifying & Managing Interfaces

### Finding Interface Names

```bash
# Modern approach
ip link show

# List only wireless interfaces
iw dev

# List physical wireless devices (phys)
ls /sys/class/ieee80211/

# Map phy to interface
iw phy phy0 info | grep -A 5 "Interface"
```

### Interface Naming Conventions

Linux uses predictable interface names. Common patterns:

| Name | Meaning |
|------|---------|
| `wlan0` | First wireless interface (legacy naming) |
| `wlp3s0` | Wireless, PCI bus 3, slot 0 (predictable names) |
| `wlx00c0caa1b2c3` | Wireless, USB, named by MAC address |
| `wlan0mon` | Interface in monitor mode (airmon-ng convention) |

```bash
# If you prefer legacy wlan0 naming, add to kernel parameters:
# net.ifnames=0 biosdevname=0
# (edit /etc/default/grub — not required for this course)
```

### Checking MAC Address

```bash
# Current MAC address
ip link show wlan0 | grep link/ether
# or
cat /sys/class/net/wlan0/address

# Physical hardware MAC (won't change even if software MAC is spoofed)
iw dev wlan0 info | grep addr
```

### MAC Address Spoofing

Spoofing your MAC address is standard practice in pen tests to avoid appearing in AP client tables.

```bash
# Using macchanger
sudo ip link set wlan0 down
sudo macchanger -r wlan0    # -r = random MAC
sudo ip link set wlan0 up

# Set a specific MAC (useful for impersonating a legitimate client)
sudo macchanger -m AA:BB:CC:DD:EE:FF wlan0

# Reset to hardware MAC
sudo macchanger -p wlan0

# Using ip command directly (no macchanger needed)
sudo ip link set wlan0 down
sudo ip link set wlan0 address AA:BB:CC:DD:EE:FF
sudo ip link set wlan0 up

# Verify the change
ip link show wlan0 | grep ether
```

**Why spoof MAC?**
- Prevents your real hardware ID from appearing in target AP's association logs
- Bypass MAC-based access control lists
- Impersonate a legitimate client during deauth + reconnect attacks
- Anonymity during reconnaissance

---

## 9. Killing Interfering Processes

The most common reason `airmon-ng` fails is that NetworkManager, wpa_supplicant, or DHCP clients are actively managing the interface — preventing monitor mode from working correctly.

### Identifying Interfering Processes

```bash
# airmon-ng has a built-in check
sudo airmon-ng check

# Sample output:
#   PID Name
#   743 NetworkManager
#   891 wpa_supplicant
#
# 2 processes can cause issues. Use 'airmon-ng check kill' to kill them.
```

### Killing Them

```bash
# Kill all interfering processes at once
sudo airmon-ng check kill

# Manual approach (more surgical)
sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant
sudo killall dhclient 2>/dev/null
sudo killall dhcpcd 2>/dev/null

# Verify nothing is holding the interface
sudo fuser -v /dev/rfkill

# Confirm processes are gone
ps aux | grep -E 'NetworkManager|wpa_supplicant'
```

### Restarting After Your Session

```bash
# Bring wireless back to normal after your work
sudo systemctl start NetworkManager
# NetworkManager will automatically restart wpa_supplicant
```

### Why These Processes Interfere

**NetworkManager:** Continuously scans for networks and will switch channels on your interface, destroying your targeted capture. It also reconfigures the interface mode when it detects a mode change.

**wpa_supplicant:** Handles WPA authentication for client connections. While in monitor mode you don't want a running wpa_supplicant taking control of the adapter and sending association frames.

**dhclient/dhcpcd:** DHCP clients will attempt to obtain an IP address when they detect link state changes, generating management frames that corrupt your captures.

---

## 10. Verifying Your Setup

A complete pre-flight checklist before starting any attack module.

### Step 1: Confirm Adapter Is Visible

```bash
lsusb | grep -E '0bda|148f|0cf3|2357'
# 0bda = Realtek, 148f = Ralink/MediaTek, 0cf3 = Atheros, 2357 = TP-Link

dmesg | grep -E 'wlan|ieee80211|usb.*wireless' | tail -10
```

### Step 2: Confirm Interface Exists

```bash
iw dev
# Should show at least one wireless interface
```

### Step 3: Confirm Monitor Mode Support

```bash
iw phy phy0 info | grep -A 10 "Supported interface modes"
# Must include: * monitor
```

### Step 4: Confirm Injection Support

```bash
# First put interface in monitor mode (covered in Module 02)
sudo airmon-ng start wlan0

# Run injection test
sudo aireplay-ng --test wlan0mon
# or the shorthand:
sudo aireplay-ng -9 wlan0mon

# Successful output:
# 12:00:00  Trying broadcast probe requests...
# 12:00:01  Injection is working!
# 12:00:01  Found 3 APs
```

### Step 5: Full airmon-ng Check

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
iwconfig wlan0mon
# Mode must show: Monitor
```

### Step 6: Verify hcxdumptool (newer API)

```bash
# hcxdumptool >= 6.x requires explicit status flags
sudo hcxdumptool --help | grep enable_status
# If present, you need: --enable_status=1 in capture commands

# Quick capability check
sudo hcxdumptool -i wlan0mon --do_rcascan
# Lists nearby APs — confirms interface is working in monitor mode
```

---

## 11. Dual-Adapter Setup

Several attack scenarios require **two wireless interfaces simultaneously**:

| Attack | Interface 1 | Interface 2 |
|--------|-------------|-------------|
| Evil Twin (Module 09) | Monitor mode — deauth clients | AP mode (hostapd) — fake AP |
| Captive Portal (Module 10) | Monitor mode — recon | AP mode — rogue AP |
| MITM with internet relay | AP mode — client connects | Managed mode — upstream relay |

### Setting Up Two Adapters

```bash
# Plug in both adapters
lsusb   # confirm both are visible

# List both interfaces
iw dev
# phy#0  Interface wlan0  (built-in or first adapter)
# phy#1  Interface wlan1  (second USB adapter)

# Put one in monitor mode
sudo airmon-ng start wlan1
# → creates wlan1mon

# Leave the other in managed/AP mode
iw dev wlan0 info   # should still show type: managed

# Verify both are available simultaneously
iw dev
# phy#0  Interface wlan0     type managed
# phy#1  Interface wlan1mon  type monitor
```

### Which Adapter for Which Role

- **Monitor mode:** Use the adapter with higher TX power (Alfa AWUS036ACH) for better range
- **AP mode (hostapd):** Either adapter works; must support AP mode (`iw phy info | grep AP`)
- **Never put the same physical adapter (`phy`) in both roles simultaneously**

---

## 12. Lab Network Topology

A well-designed lab protects both legality and learning quality. Here is the recommended setup:

```
                    ┌─────────────────────────────────────────┐
                    │           ISOLATED LAB SEGMENT           │
                    │                                          │
  ┌─────────────┐  │  ┌──────────────┐    ┌───────────────┐  │
  │   Attacker  │  │  │  Lab Router  │    │ Victim Client │  │
  │  Kali Linux │──┼──│ 192.168.100.1│    │ Phone/Laptop  │  │
  │             │  │  │ SSID: TestNet│    │ connected to  │  │
  │  wlan0      │  │  │ WPA2-PSK     │    │ TestNet       │  │
  │  (external  │  │  │ passwd:      │    └───────────────┘  │
  │   USB NIC)  │  │  │ "Password1!" │                        │
  └─────────────┘  │  └──────────────┘                        │
                   │                                           │
                   └───────────────────────────────────────────┘
                          NO INTERNET / NO WAN connectivity
```

### Lab Router Configuration Checklist

| Setting | Value | Purpose |
|---------|-------|---------|
| SSID | `TestNet` (or anything) | Target for scanning practice |
| Password | Weak (in wordlist, e.g. `password123`) | Enables successful WPA2 cracking practice |
| Security | WPA2-PSK CCMP | Primary attack protocol |
| WPS | Enabled | For Module 11 practice |
| WEP mode | Enable on old router | For Module 05 practice |
| Internet | Disconnected/blocked | Safety |
| DHCP | Enabled | Victim client needs IP |

### Multiple Router Setup (Advanced)

For complete coverage of all modules, maintain:
- **Router A:** WEP only (old router or DD-WRT with WEP forced)
- **Router B:** WPA2-PSK with WPS enabled
- **Router C:** WPA2-Enterprise (requires FreeRADIUS setup — Module 13)
- **Router D:** WPA3-SAE (Wi-Fi 6 router)

### Setting Up WEP on DD-WRT

```
DD-WRT Admin Panel → Wireless → Wireless Security
  Security Mode: WEP
  Default Transmission Key: 1
  WEP Encryption: 64-bit or 128-bit
  Passphrase: (leave blank)
  Key 1: 1234567890 (64-bit) or 12345678901234567890123456 (128-bit hex)
```

---

## 13. Essential Toolchain Installation

Complete installation script for all tools used in this course:

```bash
#!/bin/bash
# wifi-course-tools-install.sh
# Run on Kali Linux — installs all tools needed for Modules 00-14

set -e   # exit on error

echo "[*] Updating package lists..."
sudo apt update

echo "[*] Installing aircrack-ng suite..."
sudo apt install -y aircrack-ng
# aircrack-ng   ← meta-package: installs airmon-ng, airodump-ng,
#                 aireplay-ng, airdecap-ng, airbase-ng, etc.

echo "[*] Installing cracking tools..."
sudo apt install -y hashcat john
# hashcat       ← GPU-accelerated hash cracker (-m 22000 for WPA2)
# john          ← CPU-based cracker; useful for rule-based attacks

echo "[*] Installing capture tools..."
sudo apt install -y hcxdumptool hcxtools
# hcxdumptool   ← Advanced capture tool: PMKID + EAPOL frames passively
# hcxtools       ← Converts .pcapng captures to hashcat formats (.hc22000)

echo "[*] Installing packet analysis..."
sudo apt install -y wireshark-qt tshark python3-scapy
# wireshark-qt  ← GUI packet analyzer; open .cap files from airodump-ng
# tshark        ← Command-line Wireshark; scriptable analysis
# python3-scapy ← Python framework for crafting/sending arbitrary 802.11 frames

echo "[*] Installing AP/DHCP tools..."
sudo apt install -y hostapd hostapd-wpe dnsmasq
# hostapd       ← Creates rogue APs; used in Evil Twin (Module 09)
# hostapd-wpe   ← WPE fork: captures MSCHAPv2 credentials from Enterprise clients
# dnsmasq       ← Lightweight DHCP+DNS; serves IPs to clients on rogue AP

echo "[*] Installing WPS attack tools..."
sudo apt install -y reaver bully pixiewps
# reaver        ← WPS PIN brute force (online attack)
# bully         ← Alternative WPS PIN attack tool
# pixiewps      ← Offline Pixie Dust attack (exploits weak E-S1/E-S2 nonces)

echo "[*] Installing DoS tools..."
sudo apt install -y mdk3 mdk4
# mdk4          ← Wireless DoS: beacon flooding, deauth storms, EAPOL flooding
# mdk3          ← Older version; still useful for some attacks

echo "[*] Installing MITM framework..."
sudo apt install -y bettercap
# bettercap     ← Full network MITM framework with Wi-Fi modules:
#                 wifi.recon, wifi.deauth, wifi.ap, wifi.probe

echo "[*] Installing automated attack tool..."
sudo apt install -y wifite
# wifite        ← Automated wireless auditing: scans, deauths, captures,
#                 and cracks in sequence; good for quick assessments

echo "[*] Installing passive scanner..."
sudo apt install -y kismet
# kismet        ← Passive wireless IDS/scanner; detects hidden SSIDs,
#                 rogue APs, and anomalous frames without transmitting

echo "[*] Installing wordlist tools..."
sudo apt install -y crunch wordlists
# crunch        ← Generates custom wordlists by charset/pattern
# wordlists     ← Installs rockyou.txt and other standard wordlists

echo "[*] Installing network tools..."
sudo apt install -y nmap netdiscover macchanger net-tools wireless-tools rfkill \
    iw curl wget git build-essential python3-pip python3-venv
# nmap          ← Network scanner; enumerate hosts after gaining AP access
# netdiscover   ← ARP-based host discovery on the local network
# macchanger    ← MAC address spoofing utility
# python3-pip   ← For installing Python-based tools (impacket, etc.)

echo "[*] Installing RTL8812AU driver..."
sudo apt install -y realtek-rtl88xxau-dkms
# DKMS driver for RTL8812AU; auto-rebuilds on kernel upgrade

echo "[*] Extracting rockyou wordlist..."
sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
# rockyou.txt   ← 14.3M common passwords; primary wordlist for WPA2 attacks

echo ""
echo "[+] Installation complete!"
echo "[+] Verify aircrack-ng:    $(aircrack-ng --version 2>&1 | head -1)"
echo "[+] Verify hashcat:        $(hashcat --version)"
echo "[+] Verify hcxdumptool:   $(hcxdumptool --version 2>&1 | head -1)"
echo "[+] Verify wifite:         $(wifite --version 2>&1 | head -1)"
echo "[+] Verify bettercap:      $(bettercap --version 2>&1 | head -1)"
```

### Tool Reference Table

| Tool | Module(s) | Primary Use |
|------|-----------|-------------|
| `airmon-ng` | 02+ | Enable/disable monitor mode |
| `airodump-ng` | 03+ | Passive packet capture and AP listing |
| `aireplay-ng` | 05–08 | Frame injection: deauth, fake auth, ARP replay |
| `aircrack-ng` | 05, 07 | WEP key cracking and WPA2 handshake cracking |
| `hashcat` | 07, 12 | GPU-accelerated WPA2/PMKID cracking |
| `hcxdumptool` | 12 | Clientless PMKID capture |
| `hcxtools` | 12 | Convert captures to hashcat format |
| `wireshark` / `tshark` | 04+ | Frame-level packet analysis |
| `hostapd` | 09, 10, 13 | Rogue AP creation |
| `hostapd-wpe` | 13 | Enterprise rogue AP with credential capture |
| `dnsmasq` | 09, 10 | DHCP + DNS for rogue AP clients |
| `reaver` | 11 | WPS PIN brute force |
| `pixiewps` | 11 | Offline Pixie Dust WPS attack |
| `bully` | 11 | Alternative WPS attack tool |
| `mdk4` | 08 | Wireless DoS attacks |
| `bettercap` | 09, 10 | MITM framework, KARMA attacks |
| `wifite` | — | Automated multi-attack auditing |
| `kismet` | 03 | Passive monitoring, hidden SSID discovery |
| `scapy` | Advanced | Custom frame crafting in Python |
| `macchanger` | 01+ | MAC address spoofing |
| `crunch` | 07 | Custom wordlist generation |

---

## 14. Troubleshooting Common Issues

### Issue: Interface Not Appearing After Plugging In Adapter

```bash
# Check if kernel recognized the USB device
dmesg | tail -20
lsusb

# Check if driver is loaded
lsmod | grep -E '8812|ath9|mt76|rt28'

# If driver not loaded, try loading manually:
sudo modprobe 88XXau      # RTL8812AU
sudo modprobe ath9k_htc   # AR9271
sudo modprobe mt76x2u     # MT7612U

# If still nothing, try a different USB port (USB 3.0 vs 2.0)
# RTL8812AU is USB 3.0; using USB 2.0 port can cause issues

# Force kernel to re-scan USB bus
echo "1" | sudo tee /sys/bus/usb/devices/usb1/authorized
```

### Issue: `airmon-ng start wlan0` Shows No Monitor Interface

```bash
# Verify interfering processes are killed
sudo airmon-ng check kill

# Try setting monitor mode manually
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
iwconfig wlan0 | grep Mode  # should say Monitor

# Alternative using iwconfig
sudo iwconfig wlan0 mode monitor
```

### Issue: Injection Test Fails

```bash
# Test injection explicitly
sudo aireplay-ng -9 wlan0mon

# If "No answer" from all APs:
# 1. Check you're on the right channel
sudo iw dev wlan0mon set channel 6

# 2. Verify adapter supports injection
iw phy phy0 info | grep "Supported interface modes" -A 20

# 3. Try a different USB port or powered USB hub
# 4. Increase TX power
sudo iw reg set BO
sudo iw dev wlan0mon set txpower fixed 3000
```

### Issue: `ERROR: Failed to set wlan0 to monitor mode`

Usually caused by NetworkManager still running:
```bash
sudo systemctl stop NetworkManager wpa_supplicant
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

### Issue: Low Signal / Missing Networks

```bash
# Check TX power
iwconfig wlan0mon | grep Tx-Power

# Increase TX power (lab use only)
sudo iw reg set BO
sudo iw dev wlan0mon set txpower fixed 3000

# Make sure you're scanning all channels
sudo airodump-ng --band abg wlan0mon   # scan both 2.4 and 5 GHz
```

### Issue: `hcxdumptool` Permission Denied on `/dev/rfkill`

```bash
# Add your user to the netdev group or run as root
sudo hcxdumptool ...
# OR
sudo usermod -aG netdev $USER
# Then log out and back in
```

### Issue: `hcxdumptool` Immediately Exits / No Output

```bash
# hcxdumptool >= 6.x requires --enable_status flag
sudo hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# Flags breakdown:
# -i wlan0mon         ← interface in monitor mode
# -o capture.pcapng   ← output file (pcapng format required)
# --enable_status=1   ← enable status output (REQUIRED in new versions)
```

### Issue: `/etc/network/interfaces` Conflict with NetworkManager

```bash
# If you have entries for wlan0 in /etc/network/interfaces,
# NetworkManager ignores them by default but can conflict:
sudo nano /etc/NetworkManager/NetworkManager.conf
# Add under [main]:
# plugins=ifupdown,keyfile
# [ifupdown]
# managed=false   ← set to true to let NM manage interfaces defined in /etc/network/interfaces
```

---

## 15. Knowledge Check

Before proceeding to Module 02, you should be able to:

1. Name three wireless adapter chipsets confirmed to support monitor mode and packet injection, and explain why chipset matters more than brand name.
2. What does DKMS do and why is it important when installing out-of-tree kernel drivers?
3. Why does VirtualBox's USB passthrough cause injection issues? What is the recommended alternative?
4. Explain the difference between `iw` and `iwconfig`. Which is preferred and why?
5. What does `rfkill list` reveal, and how do you fix a soft-blocked adapter?
6. Name the three processes `airmon-ng check kill` terminates and explain why each interferes with wireless monitoring.
7. What command verifies that your adapter supports monitor mode before you start any attack?
8. What is MAC address spoofing and how do you perform it with `macchanger`?
9. Why should your lab router have no internet connectivity?
10. What flag does `aireplay-ng` use to test packet injection, and what does a successful test look like?
11. What is a regulatory domain and how does it affect your adapter's TX power? Which command sets it?
12. What is the difference between `hcxdumptool` and `airodump-ng` for packet capture?
13. Name two scenarios that require two wireless adapters simultaneously and explain which mode each adapter needs.
14. What tool provides automated wireless auditing (scanning + deauth + capture + crack in sequence)?
15. What does `wifite` do that `aircrack-ng` alone cannot?

---

**Next:** [Module 02 — Monitor Mode & Packet Injection](../module-02-monitor-mode/)
