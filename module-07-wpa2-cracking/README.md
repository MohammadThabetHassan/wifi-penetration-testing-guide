# Module 07 — WPA2 Cracking: Dictionary, Rule & Brute Force

> **Prerequisites:** [Module 06 — Capturing the WPA2 4-Way Handshake](../module-06-wpa2-handshake/)
> **Next Module:** [Module 08 — Deauthentication & Wireless DoS](../module-08-deauth-dos/)

---

## Table of Contents

1. [WPA2 Cracking Fundamentals](#1-wpa2-cracking-fundamentals)
2. [Hash Formats & Conversion](#2-hash-formats--conversion)
3. [hashcat — Full Flag Reference](#3-hashcat--full-flag-reference)
4. [hashcat Attack Modes](#4-hashcat-attack-modes)
5. [Dictionary Attacks](#5-dictionary-attacks)
6. [Rule-Based Attacks](#6-rule-based-attacks)
7. [Mask Attacks](#7-mask-attacks)
8. [Hybrid Attacks](#8-hybrid-attacks)
9. [Session Management & Restore](#9-session-management--restore)
10. [aircrack-ng — CPU Cracking Reference](#10-aircrack-ng--cpu-cracking-reference)
11. [John the Ripper — Alternative CPU Cracker](#11-john-the-ripper--alternative-cpu-cracker)
12. [Wordlist Generation & Curation](#12-wordlist-generation--curation)
13. [CUPP — Target-Profiled Wordlists](#13-cupp--target-profiled-wordlists)
14. [Performance Optimization](#14-performance-optimization)
15. [GPU Speed Reference & Benchmarking](#15-gpu-speed-reference--benchmarking)
16. [End-to-End Cracking Workflow](#16-end-to-end-cracking-workflow)
17. [Knowledge Check](#17-knowledge-check)

---

## 1. WPA2 Cracking Fundamentals

### Why WPA2 Is Computationally Expensive to Crack

Each password candidate requires PBKDF2-SHA1 with **4096 iterations**:

```
Cost per candidate = 4096 × SHA1 operations
                   ≈ 1.5 ms on modern CPU
                   ≈ 0.5 µs on modern GPU

CPU throughput: ~650 candidates/second/core
GPU throughput: ~1,900,000 candidates/second (RTX 4090)
```

This means:
- `rockyou.txt` (14.3M passwords) takes ~6 hours on CPU, ~8 seconds on GPU
- A truly random 12-character password would take centuries even on GPU

### The Cracking Pipeline

```
1. Capture 4-way handshake (Module 06) → .cap or .pcapng
2. Convert to hashcat format → .hc22000
3. Feed candidate passwords through PBKDF2 + PRF
4. Compare computed MIC vs. captured MIC
5. Match = password found
```

### What Makes a Password Crackable

| Factor | Crackable | Hard |
|--------|-----------|------|
| Source | In rockyou.txt | Not in any wordlist |
| Length | < 10 chars | ≥ 16 chars |
| Charset | lowercase only | mixed case + digits + symbols |
| Pattern | dictionary word + numbers | random |
| SSID | Common ("linksys") | Unique (defeats rainbow tables) |

---

## 2. Hash Formats & Conversion

### Format Overview

| Format | Extension | Mode | Description |
|--------|-----------|------|-------------|
| **HCCAPX** | `.hccapx` | `2500` (deprecated) | Legacy binary format |
| **22000** | `.hc22000` | `22000` | **Recommended** — EAPOL + PMKID combined |
| **16800** | `.16800` | `16800` | PMKID-only (no handshake needed) |
| **aircrack-ng** | `.cap` | — | Used directly by aircrack-ng |

### Converting with hcxpcapngtool

```bash
# Basic conversion (produces hashcat 22000 format)
hcxpcapngtool \
  -o hashes.hc22000 \           # Output file
  capture.pcapng                # Input (from hcxdumptool or airodump-ng)

# Full featured conversion
hcxpcapngtool \
  -o hashes.hc22000 \           # Hashcat 22000 format
  -E essids.txt \               # Export ESSID list (useful for targeted cracking)
  -I macs.txt \                 # Export client MAC list
  --all \                       # Include all hash types (PMKID + EAPOL)
  --csv=report.csv \            # Summary CSV
  --json=report.json \          # JSON summary
  capture.pcapng

# Verify the output:
wc -l hashes.hc22000           # Number of crackable hashes
head -1 hashes.hc22000         # Preview hash format

# Check info without converting:
hcxpcapngtool --info capture.pcapng
```

### Converting .cap to hashcat format

```bash
# airodump-ng .cap → hashcat 22000
hcxpcapngtool -o hashes.hc22000 handshake-01.cap

# Alternative: cap2hccapx (legacy)
cap2hccapx handshake-01.cap handshake.hccapx
hashcat -m 2500 handshake.hccapx wordlist.txt  # legacy mode
```

---

## 3. hashcat — Full Flag Reference

```bash
hashcat [options] hash [wordlist/mask]
```

### Essential Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-m 22000` | Hash-type: WPA2 EAPOL+PMKID (recommended) | `-m 22000` |
| `-m 2500` | Hash-type: WPA2 legacy hccapx (deprecated) | `-m 2500` |
| `-a 0` | Attack mode: Straight (dictionary) | `-a 0` |
| `-a 1` | Attack mode: Combination | `-a 1` |
| `-a 3` | Attack mode: Brute-force/Mask | `-a 3` |
| `-a 6` | Attack mode: Hybrid wordlist + mask | `-a 6` |
| `-a 7` | Attack mode: Hybrid mask + wordlist | `-a 7` |
| `-r <rule>` | Apply rule file | `-r rules/best64.rule` |
| `-j '<rule>'` | Apply inline rule (left word) | `-j 'c'` |
| `-k '<rule>'` | Apply inline rule (right word) | `-k '$1'` |
| `-O` | Optimized kernel (max len 31; faster) | `-O` |
| `-w 3` | Workload profile (1=low, 2=default, 3=high, 4=nightmare) | `-w 3` |
| `--increment` | Enable incremental length for mask | `--increment --increment-min=8` |
| `--status` | Enable periodic status updates | `--status --status-timer=60` |
| `--restore` | Resume an interrupted session | `--restore` |
| `--session <name>` | Name the session (for restore) | `--session wpa2_crack` |
| `--show` | Show already-cracked passwords from potfile | `--show` |
| `--potfile-disable` | Don't save results to potfile | `--potfile-disable` |
| `--potfile-path <f>` | Custom potfile location | `--potfile-path /tmp/crack.pot` |
| `-D 1` | Use CPU device (when no GPU) | `-D 1` |
| `-D 2` | Use GPU device | `-D 2` |
| `-I` | Show device information | `-I` |
| `-b` | Benchmark mode | `-b -m 22000` |
| `--username` | Hash file has username:hash format | `--username` |
| `--keep-guessing` | Continue after hash is cracked | `--keep-guessing` |

---

## 4. hashcat Attack Modes

| Mode | `-a` | Name | Description |
|------|------|------|-------------|
| **Straight** | `0` | Dictionary | Try each word from wordlist verbatim (+ rules) |
| **Combination** | `1` | Combo | Combine every word from list1 with every word from list2 |
| **Brute-force** | `3` | Mask | Try all combinations matching a mask pattern |
| **Hybrid W+M** | `6` | Wordlist+Mask | Append a mask to every wordlist word |
| **Hybrid M+W** | `7` | Mask+Wordlist | Prepend a mask to every wordlist word |

### Quick Mode Selection Guide

```
Known password pattern (e.g., "company2024!") → -a 3 with mask
In rockyou.txt probably → -a 0 (dictionary)
Common word + numbers → -a 6 wordlist ?d?d?d?d
Unknown, short (< 9 chars) → -a 3 incremental
Completely unknown → -a 0 with best64.rule first, then mask
```

---

## 5. Dictionary Attacks

### Using hashcat

```bash
# Basic dictionary attack
hashcat \
  -m 22000 \                   # WPA2 hash mode
  hashes.hc22000 \             # Hash file
  /usr/share/wordlists/rockyou.txt  # Wordlist
  -O                           # Optimized kernel (max 31 chars; faster)

# With multiple wordlists
hashcat -m 22000 hashes.hc22000 rockyou.txt custom.txt -O

# Suppress progress (just print when found)
hashcat -m 22000 hashes.hc22000 rockyou.txt -O --quiet

# After run: show found passwords
hashcat -m 22000 hashes.hc22000 --show
```

### Using aircrack-ng

```bash
# Basic dictionary attack
aircrack-ng \
  -w /usr/share/wordlists/rockyou.txt \   # -w = wordlist file
  -b AA:BB:CC:DD:EE:FF \                  # -b = target BSSID
  -e "MyNetwork" \                         # -e = ESSID (if multiple in file)
  handshake-01.cap

# Flag breakdown:
# -w <file>   → wordlist (single file; use - for stdin)
# -b <BSSID>  → filter by BSSID when multiple APs in capture
# -e <ESSID>  → filter by network name
# -q          → quiet mode (suppress status, only print result)
# -p N        → use N CPU cores (default: auto)

# Pipe from crunch (no intermediate file)
crunch 8 8 0123456789 | aircrack-ng -w - -b AA:BB:CC:DD:EE:FF handshake.cap
```

### Essential Wordlists

```bash
# rockyou.txt (14.3M passwords) — already on Kali
ls -lh /usr/share/wordlists/rockyou.txt.gz
sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz   # Decompress

# Sort wordlist by frequency for faster cracking
# (most common passwords first = faster average crack time)
sort wordlist.txt | uniq > wordlist_unique.txt

# SecLists collection
sudo apt install seclists
ls /usr/share/seclists/Passwords/

# Combined and deduplicated
cat rockyou.txt custom.txt | sort | uniq > combined.txt
```

---

## 6. Rule-Based Attacks

Rules transform each wordlist entry to produce variations without storing them. Applied at attack time by the engine.

### How Rules Work

```
Word in:    "password"
Rule: c     → "Password"       (capitalize first letter)
Rule: u     → "PASSWORD"       (uppercase all)
Rule: $1    → "password1"      (append "1")
Rule: $1$2$3 → "password123"   (append "123")
Rule: sa@   → "p@ssword"       (substitute a→@)
Rule: se3   → "passw0rd"       (substitute e→3... wait, wrong: se3 = s→3 for 'e')

# Full rule syntax: https://hashcat.net/wiki/doku.php?id=rule_based_attack
```

### Built-in Rule Files (in hashcat)

```bash
ls /usr/share/hashcat/rules/

# Most useful for WPA2:
# best64.rule      → 64 transformations covering most real-world variations
# rockyou-30000.rule → 30,000 rules derived from rockyou cracking patterns
# d3ad0ne.rule     → aggressive, large ruleset
# dive.rule        → very large (millions of combinations)
# OneRuleToRuleThemAll.rule → community favorite
```

### Rule Attack Examples

```bash
# Best64: capitalizations, number appending, leet speak
hashcat -m 22000 hashes.hc22000 rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -O

# Inline rules (fast single transformation)
hashcat -m 22000 hashes.hc22000 rockyou.txt -j 'c'    # Capitalize
hashcat -m 22000 hashes.hc22000 rockyou.txt -j 'u'    # Uppercase all
hashcat -m 22000 hashes.hc22000 rockyou.txt -j '$1$2$3'  # Append 123
hashcat -m 22000 hashes.hc22000 rockyou.txt -j '^C^a^p'  # Prepend "paC" (reversed)

# Custom rule file
cat > my.rule << 'EOF'
c         # Capitalize
$1
$123
sa@       # a→@
se3       # e→3
ss$       # s→$
EOF

hashcat -m 22000 hashes.hc22000 rockyou.txt -r my.rule -O
```

### Rule Generation with hashcat --stdout

```bash
# Preview what rules produce (before actually cracking)
hashcat --stdout -r rules/best64.rule rockyou.txt | head -20
# Shows the actual modified words the rules generate
# Useful for verifying your custom rules produce expected output
```

---

## 7. Mask Attacks

### Character Set Reference

```
?l  = abcdefghijklmnopqrstuvwxyz          (26 chars)
?u  = ABCDEFGHIJKLMNOPQRSTUVWXYZ          (26 chars)
?d  = 0123456789                           (10 chars)
?s  = !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~   (33 chars)
?a  = ?l?u?d?s (all of the above)         (95 chars)
?h  = 0-9 + a-f (hex lowercase)           (16 chars)
?H  = 0-9 + A-F (hex uppercase)           (16 chars)
?b  = 0x00 - 0xFF (binary)                (256 chars)

# Custom charset: define your own with -1, -2, -3, -4
# -1 'abcd0123' -2 'ABCD' → use ?1 and ?2 in mask
```

### Mask Examples

```bash
# 8-digit PIN (phone / simple numeric)
hashcat -m 22000 hashes.hc22000 -a 3 ?d?d?d?d?d?d?d?d -O

# WPA2 minimum length (8 chars, lowercase only)
hashcat -m 22000 hashes.hc22000 -a 3 ?l?l?l?l?l?l?l?l -O

# Known prefix: "admin" + 4 digits
hashcat -m 22000 hashes.hc22000 -a 3 admin?d?d?d?d -O

# Custom charset: only hex chars (WiFi default passwords)
hashcat -m 22000 hashes.hc22000 -a 3 -1 '0123456789abcdef' \
  ?1?1?1?1?1?1?1?1?1?1 -O

# Incremental mask (try 8, 9, 10... chars automatically)
hashcat -m 22000 hashes.hc22000 -a 3 ?a?a?a?a?a?a?a?a?a?a \
  --increment --increment-min=8 -O
```

### Mask File (.hcmask) for Multiple Patterns

```bash
# Create a mask file
cat > wpa2.hcmask << 'EOF'
?d?d?d?d?d?d?d?d
?u?l?l?l?l?l?d?d?d
?l?l?l?l?l?l?l?l?d?d
admin?d?d?d?d
Pass?d?d?d?d
EOF

# Run all masks in sequence
hashcat -m 22000 hashes.hc22000 -a 3 wpa2.hcmask -O
```

---

## 8. Hybrid Attacks

Hybrid attacks combine a wordlist with a mask — either appending or prepending.

```bash
# Attack mode 6: wordlist + mask (append mask to each word)
# Example: "password" + "2024" → "password2024"
hashcat \
  -m 22000 hashes.hc22000 \
  -a 6 \                     # Hybrid: word + mask
  rockyou.txt \              # Wordlist
  ?d?d?d?d \                 # Mask appended to each word
  -O

# Attack mode 7: mask + wordlist (prepend mask to each word)
# Example: "123" + "password" → "123password"
hashcat \
  -m 22000 hashes.hc22000 \
  -a 7 \
  ?d?d?d \                   # Mask prepended
  rockyou.txt \
  -O

# Common hybrid patterns:
# Word + year:  -a 6 words.txt ?d?d?d?d
# Word + bang:  -a 6 words.txt ?s           (appends special char)
# Capital + word + digit: -j 'c' -a 6 words.txt ?d
```

---

## 9. Session Management & Restore

Long cracking sessions can be interrupted. hashcat's session system lets you resume exactly where you left off.

```bash
# Start a named session
hashcat \
  -m 22000 hashes.hc22000 rockyou.txt \
  --session wpa2_home \      # Session name (creates .restore file)
  --status \                 # Print status every N seconds
  --status-timer 60 \        # Status every 60 seconds
  -O

# If interrupted (Ctrl+C or power failure):
# Session state saved to: ~/.hashcat/sessions/wpa2_home.restore

# Restore the session:
hashcat --restore --session wpa2_home

# Check cracked passwords from potfile:
hashcat -m 22000 hashes.hc22000 --show

# Show with username format:
hashcat -m 22000 hashes.hc22000 --show --username

# Disable potfile (don't save results — useful in isolated test environments):
hashcat -m 22000 hashes.hc22000 rockyou.txt --potfile-disable

# Custom potfile location:
hashcat -m 22000 hashes.hc22000 rockyou.txt \
  --potfile-path /tmp/testcrack.pot
```

---

## 10. aircrack-ng — CPU Cracking Reference

```bash
# Full aircrack-ng flag reference for WPA2:
aircrack-ng [options] capture.cap

# Core flags:
# -w <file>      → wordlist file (use - for stdin)
# -b <BSSID>     → target AP MAC (filter when multiple APs in file)
# -e <ESSID>     → target network name (filter by SSID)
# -q             → quiet mode (suppress progress, print only result)
# -p <N>         → number of CPU threads to use
# -S             → speed test (benchmark CPU speed without cracking)

# With rockyou.txt (most common approach):
aircrack-ng \
  -w /usr/share/wordlists/rockyou.txt \
  -b AA:BB:CC:DD:EE:FF \
  handshake-01.cap

# Using stdin pipe from crunch:
crunch 8 8 0123456789 | aircrack-ng -w - -b AA:BB:CC:DD:EE:FF handshake.cap

# Using stdin from hashcat rule output:
hashcat --stdout -r rules/best64.rule rockyou.txt | \
  aircrack-ng -w - -b AA:BB:CC:DD:EE:FF handshake.cap

# Benchmark CPU speed (no actual cracking):
aircrack-ng -S

# Crack and immediately quit after finding password (-q mode):
aircrack-ng -w rockyou.txt -q handshake.cap
```

---

## 11. John the Ripper — Alternative CPU Cracker

John the Ripper is a mature password cracker with excellent rule generation for CPU-only environments.

```bash
# Convert .cap to john format
hccap2john handshake-01.hccapx > handshake.john
# or
python3 /usr/share/john/wpapcap2john handshake-01.cap > handshake.john

# Basic wordlist attack
john \
  --wordlist=/usr/share/wordlists/rockyou.txt \
  --format=wpapsk \
  handshake.john

# Rule-based attack (john has its own ruleset)
john \
  --wordlist=rockyou.txt \
  --rules=best64 \        # John's built-in best64 rules
  --format=wpapsk \
  handshake.john

# Incremental brute force
john --incremental --format=wpapsk handshake.john

# Show cracked passwords
john --show --format=wpapsk handshake.john

# List available rules
john --list=rules

# Use john's Jumbo rules (very effective):
john --wordlist=rockyou.txt --rules=jumbo --format=wpapsk handshake.john
```

---

## 12. Wordlist Generation & Curation

### crunch — Pattern-Based Generation

```bash
# All 8-character lowercase combinations
crunch 8 8 -f /usr/share/crunch/charset.lst lalpha -o list8.txt

# Pattern-based (@ = lowercase, , = uppercase, % = digit, ^ = special)
crunch 10 10 -t @@@@@@%%%% -o out.txt   # 6 lowercase + 4 digits

# Specific character set
crunch 8 12 abcdefghijklmnopqrstuvwxyz0123456789 -o alphanum.txt

# Pipe directly to hashcat
crunch 8 8 0123456789 | hashcat -m 22000 hash.hc22000 --stdin

# crunch pattern characters:
# @  = lowercase (a-z)
# ,  = uppercase (A-Z)
# %  = digits (0-9)
# ^  = special (!@#$...)
# [chars] = literal chars at that position
```

### cewl — Website-Based Wordlist

```bash
# Generate wordlist from target company website (OSINT)
cewl \
  https://targetcompany.com \     # Target URL
  -m 8 \                          # Minimum word length
  -d 3 \                          # Crawl depth
  -w company_words.txt            # Output file

# Include email addresses found on site
cewl https://target.com -m 8 -d 2 --email -w cewl_out.txt

# Useful for corporate WPA2 where password may relate to company name/terms
```

### Wordlist Optimization

```bash
# Remove duplicates and sort
sort wordlist.txt | uniq > sorted.txt

# Sort by probability (most likely first) using password frequency data
# hashcat can sort:
hashcat --stdout -m 22000 hash.hc22000 wordlist.txt | head -1000 > likely.txt

# Extract only minimum WPA2 length (8+ chars)
awk 'length >= 8' rockyou.txt > rockyou_wpa.txt

# Combine and deduplicate multiple lists:
cat rockyou.txt cewl_out.txt custom.txt | sort -u > combined.txt
```

---

## 13. CUPP — Target-Profiled Wordlists

CUPP (Common User Passwords Profiler) generates a personalized wordlist based on target OSINT.

```bash
# Install
sudo apt install cupp

# Interactive mode (fill in target info)
cupp -i
# Prompts for:
# First name, Last name, Nickname
# Birthdate, Partner info, Children
# Pet names, Company, Keywords
# → Generates a targeted wordlist with common combinations

# Automated from file
cupp -l    # Download password lists
cupp -a    # Parse default Alecto database

# Example output entries from "John Smith" born 1990:
# john1990
# John1990!
# jsmith90
# johnsmith
# J0hn$m1th
# ...

# Combine CUPP output with best64 rules:
hashcat -m 22000 hash.hc22000 cupp_output.txt \
  -r /usr/share/hashcat/rules/best64.rule -O
```

---

## 14. Performance Optimization

### hashcat Optimization Flags

```bash
# Optimized kernel: faster but caps max password length at 31 chars
hashcat -m 22000 hash.hc22000 wordlist.txt -O
# Warning: -O will NOT crack passwords longer than 31 characters

# Workload profiles:
# -w 1 = Low (laptop battery-friendly, slow)
# -w 2 = Default (balanced)
# -w 3 = High (aggressive; may cause screen lag)
# -w 4 = Nightmare (maximum; system may become unresponsive)
hashcat -m 22000 hash.hc22000 wordlist.txt -w 3 -O

# CPU mode (no GPU / AMD incompatibility):
hashcat -m 22000 hash.hc22000 wordlist.txt -D 1 -O

# Multiple GPUs:
hashcat -m 22000 hash.hc22000 wordlist.txt -d 1,2 -O
```

### GPU Temperature Monitoring

```bash
# NVIDIA — real-time monitoring
nvidia-smi -l 1
# -l 1 = refresh every 1 second

# Monitor specific metrics
nvidia-smi --query-gpu=temperature.gpu,utilization.gpu,power.draw \
  --format=csv -l 1

# Stop hashcat if temperature exceeds 85°C
# Most gaming GPUs throttle at 83-87°C; damage risk above 95°C

# AMD
rocm-smi --showtemp
```

### Benchmark Before Long Runs

```bash
# Benchmark all hash modes
hashcat -b

# Benchmark WPA2 specifically
hashcat -b -m 22000

# Example output:
# Speed.#1.........: 1,988.1 kH/s (1.99 MH/s)
# This means 1.99 million WPA2 candidates/second on this GPU
```

---

## 15. GPU Speed Reference & Benchmarking

### WPA2 Cracking Speed by GPU (approximate)

| GPU | WPA2 H/s | rockyou.txt time | Notes |
|-----|----------|-----------------|-------|
| RTX 4090 | ~1,900,000 | ~8 seconds | Current fastest consumer |
| RTX 3090 | ~1,250,000 | ~12 seconds | |
| RTX 3080 | ~900,000 | ~16 seconds | |
| RTX 2080 Ti | ~650,000 | ~22 seconds | |
| RTX 2080 | ~490,000 | ~30 seconds | |
| GTX 1080 Ti | ~320,000 | ~45 seconds | |
| GTX 1080 | ~250,000 | ~57 seconds | |
| CPU (8-core) | ~5,000 | ~48 minutes | Via `-D 1` |

### Online Cracking Services (for note)

Several public services will crack WPA2 hashes for a fee or free (in CTF contexts):
- `https://www.onlinehashcrack.com`
- `https://hashkiller.io`

**Ethical consideration:** Only submit hashes from networks you own. Never upload client captures without consent.

---

## 16. End-to-End Cracking Workflow

The complete pipeline from capture to cracked password:

```bash
#!/bin/bash
# wpa2-crack.sh — Full WPA2 cracking workflow

CAPTURE="handshake-01.cap"      # From airodump-ng
HASH="hashes.hc22000"
WORDLIST="/usr/share/wordlists/rockyou.txt"
SESSION="wpa2_crack_$(date +%s)"

# Step 1: Verify handshake exists
echo "[*] Checking capture..."
aircrack-ng "$CAPTURE"
# Confirm: WPA2 (N) handshake — N > 0

# Step 2: Convert to hashcat format
echo "[*] Converting capture..."
hcxpcapngtool -o "$HASH" "$CAPTURE"
echo "[*] Hashes in file: $(wc -l < "$HASH")"

# Step 3: Dictionary attack with best64 rules
echo "[*] Phase 1: Dictionary + best64 rules..."
hashcat -m 22000 "$HASH" "$WORDLIST" \
  -r /usr/share/hashcat/rules/best64.rule \
  -O -w 3 \
  --session "$SESSION"

# Step 4: Check if cracked
RESULT=$(hashcat -m 22000 "$HASH" --show)
if [ -n "$RESULT" ]; then
  echo "[+] PASSWORD FOUND: $RESULT"
  exit 0
fi

# Step 5: Mask attack (8-12 chars, common patterns)
echo "[*] Phase 2: Mask attack..."
hashcat -m 22000 "$HASH" -a 3 \
  ?l?l?l?l?l?l?l?l \
  --increment --increment-max=12 \
  -O -w 3

# Step 6: Show results
hashcat -m 22000 "$HASH" --show
```

---

## 17. Knowledge Check

1. What does the `-O` flag do in hashcat and what is its critical limitation?
2. What is the difference between hashcat attack modes `-a 0`, `-a 3`, `-a 6`, and `-a 7`?
3. Explain what a hashcat rule does. Write a rule file that capitalizes, appends "123", and substitutes `a` with `@`.
4. Write the complete hashcat command to crack a WPA2 hash with rockyou.txt, best64 rules, GPU optimizations, and a named session.
5. How do you resume an interrupted hashcat session?
6. What does `hashcat -m 22000 hashes.hc22000 --show` display?
7. Write the crunch command to generate all 8-character passwords using only digits and pipe it to hashcat.
8. What is the purpose of CUPP and when would you use it over rockyou.txt?
9. What does `cewl` generate and in what scenario is it particularly useful for WPA2 cracking?
10. Write the `hcxpcapngtool` command to convert a pcapng file to hashcat format and generate an ESSID list.
11. What is `--potfile-disable` used for in hashcat and why would you enable it in a test environment?
12. Write the John the Ripper command to crack a WPA2 hash file using the `jumbo` ruleset.
13. What GPU speed (H/s) can a modern RTX 4090 achieve on WPA2 (-m 22000)?
14. What is the `--increment` flag in hashcat's mask mode and when is it useful?

---

**Next:** [Module 08 — Deauthentication & Wireless DoS](../module-08-deauth-dos/)
