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
7. [Identifying & Managing Interfaces](#7-identifying--managing-interfaces)
8. [Killing Interfering Processes](#8-killing-interfering-processes)
9. [Verifying Your Setup](#9-verifying-your-setup)
10. [Lab Network Topology](#10-lab-network-topology)
11. [Essential Toolchain Installation](#11-essential-toolchain-installation)
12. [Troubleshooting Common Issues](#12-troubleshooting-common-issues)
13. [Knowledge Check](#13-knowledge-check)

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
| **Alfa AWUS036ACH** | RTL8812AU | 2.4/5 GHz | Yes | Best all-rounder; dual-band; high power |
| **Alfa AWUS036ACM** | MT7612U | 2.4/5 GHz | Yes | Excellent Linux support; stable |
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
    macchanger iw wireless-tools net-tools

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

git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au

# Install via DKMS (persists across kernel upgrades)
sudo make dkms_install

# Or manual (does not persist):
make
sudo make install
sudo modprobe 88XXau
```

**Line-by-line explanation:**
- `sudo apt install dkms git build-essential linux-headers-$(uname -r)` — installs DKMS framework, git, C compiler, and current kernel headers
- `git clone` — downloads the driver source from the aircrack-ng maintained fork
- `sudo make dkms_install` — registers module with DKMS; automatically rebuilds after `apt upgrade` kernel updates
- `sudo modprobe 88XXau` — loads the compiled module into the running kernel

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

# This shows: supported bands, supported frequencies, monitor mode capability,
# injection capability, antenna count, max TX power

# Show information about a specific interface
iw dev wlan0 info

# Scan for nearby networks (requires interface in managed mode)
sudo iw dev wlan0 scan | grep -E 'SSID|signal|freq'
```

### `iwconfig` — Legacy Tool (Still Useful)

```bash
# Show all wireless interfaces
iwconfig

# Show a specific interface
iwconfig wlan0

# Sample output:
# wlan0     IEEE 802.11  ESSID:off/any
#           Mode:Managed  Frequency:2.412 GHz  Access Point: Not-Associated
#           Tx-Power=20 dBm
#           Retry short limit:7   RTS thr:off   Fragment thr:off
#           Encryption key:off
#           Power Management:on
```

**Key fields to understand:**
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

## 7. Identifying & Managing Interfaces

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

# Set a specific MAC
sudo macchanger -m AA:BB:CC:DD:EE:FF wlan0

# Reset to hardware MAC
sudo macchanger -p wlan0

# Using ip command directly (no macchanger needed)
sudo ip link set wlan0 down
sudo ip link set wlan0 address AA:BB:CC:DD:EE:FF
sudo ip link set wlan0 up
```

**Why spoof MAC?**
- Prevents your real hardware ID from appearing in target AP's association logs
- Bypass MAC-based access control lists
- Impersonate a legitimate client during certain attacks

---

## 8. Killing Interfering Processes

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

# Verify nothing is holding the interface
sudo fuser -v /dev/rfkill
```

### Restarting After Your Session

```bash
# Bring wireless back to normal after your work
sudo systemctl start NetworkManager
# NetworkManager will automatically restart wpa_supplicant
```

### Why These Processes Interfere

**NetworkManager:** Continuously scans for networks and will switch channels on your interface, destroying your targeted capture. It also reconfigures the interface mode.

**wpa_supplicant:** Handles WPA authentication for client connections. While in monitor mode you don't want a running wpa_supplicant taking control of the adapter.

**dhclient/dhcpcd:** DHCP clients will attempt to obtain an IP address, generating management frames that can corrupt your captures.

---

## 9. Verifying Your Setup

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

---

## 10. Lab Network Topology

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
| Password | Weak (in wordlist) | Enables successful WPA2 cracking practice |
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

---

## 11. Essential Toolchain Installation

Complete installation command for all tools used in this course:

```bash
#!/bin/bash
# wifi-course-tools-install.sh
# Run on Kali Linux — installs all tools needed for Modules 00-14

set -e   # exit on error

echo "[*] Updating package lists..."
sudo apt update

echo "[*] Installing aircrack-ng suite..."
sudo apt install -y aircrack-ng

echo "[*] Installing cracking tools..."
sudo apt install -y hashcat john

echo "[*] Installing capture tools..."
sudo apt install -y hcxdumptool hcxtools

echo "[*] Installing packet analysis..."
sudo apt install -y wireshark-qt tshark scapy

echo "[*] Installing AP/DHCP tools..."
sudo apt install -y hostapd hostapd-wpe dnsmasq

echo "[*] Installing WPS attack tools..."
sudo apt install -y reaver bully pixiewps

echo "[*] Installing DoS tools..."
sudo apt install -y mdk3 mdk4

echo "[*] Installing MITM framework..."
sudo apt install -y bettercap

echo "[*] Installing wordlist tools..."
sudo apt install -y crunch wordlists

echo "[*] Installing misc tools..."
sudo apt install -y macchanger net-tools wireless-tools rfkill \
    iw curl wget git build-essential python3-pip

echo "[*] Installing RTL8812AU driver..."
sudo apt install -y realtek-rtl88xxau-dkms

echo "[*] Extracting rockyou wordlist..."
sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

echo ""
echo "[+] Installation complete!"
echo "[+] Verify aircrack-ng: $(aircrack-ng --version | head -1)"
echo "[+] Verify hashcat: $(hashcat --version)"
echo "[+] Verify hcxdumptool: $(hcxdumptool --version 2>&1 | head -1)"
```

**Line-by-line explanations for key packages:**

| Package | Purpose |
|---------|---------|
| `aircrack-ng` | Meta-package installing the full aircrack-ng suite |
| `hashcat` | GPU-accelerated hash cracker; faster than aircrack-ng for WPA2 |
| `hcxdumptool` | Advanced passive capture tool; captures PMKID and EAPOL frames |
| `hcxtools` | Converts capture files to hashcat-compatible formats |
| `hostapd-wpe` | Wireless Profile Editor fork — creates rogue WPA-Enterprise AP |
| `reaver` | WPS PIN brute force tool |
| `pixiewps` | Offline Pixie Dust WPS attack tool |
| `mdk4` | Wireless denial-of-service and fuzzing tool |
| `bettercap` | Network MITM framework with Wi-Fi capabilities |
| `crunch` | Wordlist generator with pattern/charset rules |
| `macchanger` | MAC address spoofing utility |
| `realtek-rtl88xxau-dkms` | RTL8812AU driver with DKMS auto-rebuild |

---

## 12. Troubleshooting Common Issues

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
# 4. RTL8812AU may need: sudo ifconfig wlan0mon txpower 30
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

# Increase TX power (use with caution — respect local regulations)
sudo iw dev wlan0 set txpower fixed 3000   # 30 dBm = max for most adapters
# Note: mW value = dBm * 100 in this command

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

---

## 13. Knowledge Check

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

---

**Next:** [Module 02 — Monitor Mode & Packet Injection](../module-02-monitor-mode/)
