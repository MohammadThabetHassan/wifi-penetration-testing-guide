# Wireless Network Exploitation — A Progressive Course

> **Legal Disclaimer:** This course is provided strictly for **educational purposes** and **authorized penetration testing** only. Performing any of the techniques described against networks you do not own or do not have **explicit written permission** to test is **illegal** under laws including (but not limited to) the U.S. Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation worldwide. The authors accept no liability for misuse. Always operate in a controlled lab environment or with written authorization.

---

## Overview

This repository is a complete, stair-stepped web course on wireless security and Wi-Fi penetration testing. Each module contains:

- A **Markdown textbook** (`README.md`) — deep theory, exact CLI commands with flag-by-flag explanations, and advanced chaining notes.
- An **interactive web page** (`index.html`) — styled UI with embedded diagrams, terminal simulators, and knowledge-check widgets.

The curriculum mirrors real-world offensive security certifications (OffSec PEN-210/OSWP, SANS SEC617) while going further into advanced attack chaining and enterprise bypass techniques.

---

## Repository Structure

```
wifi-hacking-course/
│
├── README.md                          ← This file (curriculum map)
├── assets/
│   ├── css/                           ← Shared stylesheet for all web pages
│   ├── js/                            ← Shared JavaScript (terminal sim, quiz engine)
│   └── images/                        ← Shared placeholder images and diagrams
│
├── module-00-foundations/
│   ├── README.md
│   └── index.html
│
├── module-01-linux-wireless-setup/
│   ├── README.md
│   └── index.html
│
├── module-02-monitor-mode/
│   ├── README.md
│   └── index.html
│
├── module-03-reconnaissance/
│   ├── README.md
│   └── index.html
│
├── module-04-packet-analysis/
│   ├── README.md
│   └── index.html
│
├── module-05-wep-cracking/
│   ├── README.md
│   └── index.html
│
├── module-06-wpa2-handshake/
│   ├── README.md
│   └── index.html
│
├── module-07-wpa2-cracking/
│   ├── README.md
│   └── index.html
│
├── module-08-deauth-dos/
│   ├── README.md
│   └── index.html
│
├── module-09-evil-twin/
│   ├── README.md
│   └── index.html
│
├── module-10-captive-portal/
│   ├── README.md
│   └── index.html
│
├── module-11-wps-attacks/
│   ├── README.md
│   └── index.html
│
├── module-12-pmkid-attack/
│   ├── README.md
│   └── index.html
│
├── module-13-enterprise-wpa/
│   ├── README.md
│   └── index.html
│
└── module-14-attack-chaining/
    ├── README.md
    └── index.html
```

---

## Curriculum Outline

### Tier 1 — Foundations (Pre-Requisite Knowledge)

| Module | Title | Key Concepts |
|--------|-------|--------------|
| **00** | [Networking & 802.11 Foundations](./module-00-foundations/) | OSI model, RF basics, 802.11 a/b/g/n/ac/ax, SSID/BSSID/ESSID, 2.4GHz vs 5GHz channels, frame types (Management / Control / Data), authentication states, association handshakes |
| **01** | [Linux Wireless Lab Setup](./module-01-linux-wireless-setup/) | Compatible hardware (Alfa AWUS036ACH etc.), Kali/Parrot Linux, driver installation (rtl8812au), `iwconfig`, `iw`, `ip link`, `rfkill`, `NetworkManager` conflicts, lab topology design |
| **02** | [Monitor Mode & Packet Injection](./module-02-monitor-mode/) | Managed vs. monitor mode, `airmon-ng`, `iwconfig`, injection testing with `aireplay-ng -9`, RFMON, channel hopping, understanding PHY vs MAC layer |

---

### Tier 2 — Reconnaissance & Intelligence Gathering

| Module | Title | Key Concepts |
|--------|-------|--------------|
| **03** | [Wireless Reconnaissance with airodump-ng](./module-03-reconnaissance/) | `airodump-ng` output fields (BSSID, PWR, Beacons, #Data, CH, ENC, CIPHER, AUTH, ESSID), targeted capture, client enumeration, channel locking, writing capture files, `airgraph-ng`, hidden SSID detection |
| **04** | [Packet Analysis with Wireshark & Scapy](./module-04-packet-analysis/) | Opening `.cap` files, 802.11 display filters, beacon frame dissection, probe requests/responses, 4-way handshake anatomy, Scapy for custom frame crafting |

---

### Tier 3 — Legacy Protocol Attacks

| Module | Title | Key Concepts |
|--------|-------|--------------|
| **05** | [WEP Cracking](./module-05-wep-cracking/) | RC4 stream cipher, IV (Initialization Vector) weaknesses, FMS/KoreK/PTW statistical attacks, ARP replay attack (`aireplay-ng -3`), Chop-Chop attack (`aireplay-ng -4`), Fragmentation attack (`aireplay-ng -5`), `aircrack-ng` PTW cracking, fake authentication (`aireplay-ng -1`), café-latte attack |

---

### Tier 4 — WPA/WPA2-Personal Attacks

| Module | Title | Key Concepts |
|--------|-------|--------------|
| **06** | [Capturing the WPA2 4-Way Handshake](./module-06-wpa2-handshake/) | EAPOL frame sequence (ANonce, SNonce, MIC), `airodump-ng` targeted capture, deauth to force re-authentication, handshake verification with `aircrack-ng`, `hcxdumptool` passive capture, writing to `.hccapx` |
| **07** | [WPA2-PSK Cracking — Dictionary, Rule & Brute Force](./module-07-wpa2-cracking/) | `aircrack-ng -w`, `hashcat` mode 2500/22000, rule-based attacks (`-r`), mask attacks (`-a 3`), `hcxtools` conversion, `john` with wordlists, `crunch` wordlist generation, rainbow tables, GPU acceleration |

---

### Tier 5 — Active Attacks & Denial of Service

| Module | Title | Key Concepts |
|--------|-------|--------------|
| **08** | [Deauthentication & Wireless DoS](./module-08-deauth-dos/) | 802.11 management frame vulnerabilities, `aireplay-ng -0`, targeted vs. broadcast deauth, `mdk3`/`mdk4` beacon flooding, SSID flooding, Michael MIC failure (TKIP DoS), 802.11w Management Frame Protection (MFP/PMF) and its limitations |

---

### Tier 6 — Rogue AP & Social Engineering

| Module | Title | Key Concepts |
|--------|-------|--------------|
| **09** | [Evil Twin Access Points](./module-09-evil-twin/) | `hostapd`, `airbase-ng`, `hostapd-wpe`, creating a rogue AP with matching SSID/BSSID, `dnsmasq` for DHCP, signal strength manipulation, KARMA attacks, `bettercap` AP mode |
| **10** | [Captive Portals & Credential Harvesting](./module-10-captive-portal/) | `nodogsplash`, `nginx` + PHP credential capture page, DNS hijacking with `dnsmasq`, SSL stripping, `bettercap` + Modlishka, WPA2-Enterprise phishing (EAP credential theft) |

---

### Tier 7 — WPS Vulnerabilities

| Module | Title | Key Concepts |
|--------|-------|--------------|
| **11** | [WPS Attacks — PIN Bruteforce & Pixie Dust](./module-11-wps-attacks/) | WPS protocol flow (M1–M8), PIN design flaw (split halves → 11,000 guesses), `reaver`, `bully`, Pixie Dust attack (weak nonce generation), `pixiewps`, offline WPS PIN cracking, detecting WPS-enabled targets with `wash` |

---

### Tier 8 — Modern WPA2/WPA3 Attack Vectors

| Module | Title | Key Concepts |
|--------|-------|--------------|
| **12** | [PMKID Attack (Clientless WPA2 Cracking)](./module-12-pmkid-attack/) | PMKID derivation (`PMKID = HMAC-SHA1(PMK, "PMK Name" \|\| AP_MAC \|\| Client_MAC)`), `hcxdumptool` targeted capture, `hcxtools` conversion to hashcat 22000 format, offline cracking without a client |
| **13** | [WPA2/WPA3-Enterprise Attacks](./module-13-enterprise-wpa/) | EAP types (PEAP, EAP-TLS, EAP-TTLS, EAP-FAST), `hostapd-wpe` rogue RADIUS server, capturing MSCHAPv2 hashes, `asleap` / `hashcat` NTLM cracking, PEAP relay, WPA3-SAE Dragonblood side-channel attacks, `dragonslayer` |

---

### Tier 9 — Advanced Attack Chaining

| Module | Title | Key Concepts |
|--------|-------|--------------|
| **14** | [Full Attack Chains & Automation](./module-14-attack-chaining/) | Recon → deauth → handshake → crack pipeline, Evil Twin + captive portal chain, PMKID + offline crack + Evil Twin pivot, `wifiphisher` automated framework, post-exploitation on wireless clients, building a Bash automation harness, reporting and remediation guidance |

---

## Tools Reference Index

| Tool | Purpose | Modules |
|------|---------|---------|
| `airmon-ng` | Enable/disable monitor mode | 02 |
| `airodump-ng` | Packet capture & AP/client recon | 03, 06, 11 |
| `aireplay-ng` | Packet injection (deauth, replay, fakeauth) | 02, 05, 06, 08 |
| `aircrack-ng` | WEP/WPA key cracking | 05, 06, 07 |
| `airdecap-ng` | Decrypt capture files | 05, 07 |
| `airbase-ng` | Rogue AP / Evil Twin | 09 |
| `wash` | Scan for WPS-enabled APs | 11 |
| `reaver` | WPS PIN brute force | 11 |
| `bully` | WPS PIN brute force (alternative) | 11 |
| `pixiewps` | Offline Pixie Dust WPS crack | 11 |
| `hcxdumptool` | Advanced passive capture (PMKID, EAPOL) | 06, 12 |
| `hcxtools` | Convert capture files to hashcat format | 07, 12 |
| `hashcat` | GPU-accelerated hash cracking | 07, 12, 13 |
| `hostapd` | Software AP daemon | 09, 10, 13 |
| `hostapd-wpe` | Rogue WPA-Enterprise / RADIUS | 13 |
| `dnsmasq` | DHCP + DNS for rogue AP | 09, 10 |
| `bettercap` | MITM framework (includes AP mode) | 09, 10 |
| `wifiphisher` | Automated phishing framework | 09, 14 |
| `mdk3` / `mdk4` | DoS / beacon flooding | 08 |
| `Wireshark` | Packet analysis | 04, 06 |
| `Scapy` | Custom frame crafting (Python) | 04, 14 |
| `asleap` | EAP-LEAP / MSCHAPv2 cracking | 13 |
| `crunch` | Wordlist generation | 07 |

---

## Prerequisites

- Basic Linux command-line proficiency
- Understanding of TCP/IP networking (OSI model, subnetting)
- A dedicated wireless adapter capable of **monitor mode** and **packet injection** (e.g., Alfa AWUS036ACH, AWUS036NH, or Panda PAU09)
- Kali Linux 2024+ or Parrot OS Security Edition (bare metal or VM with USB passthrough)
- A lab environment: isolated wireless router(s) you own and control

---

## How to Use This Course

1. Work through modules **in order** — each builds on the last.
2. Read the `README.md` textbook first for theory, then open `index.html` for interactive practice.
3. Reproduce every command in your own lab before moving on.
4. The final module (14) ties every technique into complete, real-world attack chains.

---

## Status

| Module | Textbook | Web Page |
|--------|----------|----------|
| 00 — Foundations | Completed | Completed |
| 01 — Linux Wireless Setup | Completed | Completed |
| 02 — Monitor Mode | Completed | Completed |
| 03 — Reconnaissance | Completed | Completed |
| 04 — Packet Analysis | Completed | Completed |
| 05 — WEP Cracking | Completed | Completed |
| 06 — WPA2 Handshake | Completed | Completed |
| 07 — WPA2 Cracking | Completed | Completed |
| 08 — Deauth & DoS | Completed | Completed |
| 09 — Evil Twin | Completed | Completed |
| 10 — Captive Portal | Completed | Completed |
| 11 — WPS Attacks | Completed | Completed |
| 12 — PMKID Attack | Completed | Completed |
| 13 — Enterprise WPA | Completed | Completed |
| 14 — Attack Chaining | Completed | Completed |
