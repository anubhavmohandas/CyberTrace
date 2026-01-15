# CYBERTRACE - FINAL COMPLETE BLUEPRINT
## Multi-Layer OSINT Investigation Tool

```
Status: BLUEPRINT ONLY - NO CODE IMPLEMENTED YET
Version: 2.0 (Final)
Date: December 2024
Author: Anubhav Mohandas
GitHub: github.com/anubhavmohandas
Purpose: Personal OSINT Research & Investigation Tool
```

---

# TABLE OF CONTENTS

1. [Project Overview](#1-project-overview)
2. [Implementation Status](#2-implementation-status)
3. [Architecture](#3-architecture)
4. [Input Detection System](#4-input-detection-system)
5. [Complete Module List](#5-complete-module-list)
6. [Phone Investigation Module (27 Sources)](#6-phone-investigation-module)
7. [Email Module (15 Sources)](#7-email-module)
8. [Username Module (2500+ Sites)](#8-username-module)
9. [Domain Module (20 Sources)](#9-domain-module)
10. [Bitcoin/Crypto Module (10 Sources)](#10-bitcoincrypto-module)
11. [Indian OSINT Module (Detailed)](#11-indian-osint-module)
12. [Dark Web Module (20 Sources)](#12-dark-web-module)
13. [Social Media Module (15 Platforms)](#13-social-media-module)
14. [GEOINT Module (25 Sources)](#14-geoint-module)
15. [Search Engines & Operators](#15-search-engines--operators)
16. [Dark Web Tools Reference (82 Tools)](#16-dark-web-tools-reference)
17. [Source Access Methods](#17-source-access-methods)
18. [Realistic Expectations](#18-realistic-expectations)
19. [What Works vs What Doesn't](#19-what-works-vs-what-doesnt)
20. [Configuration](#20-configuration)
21. [Program Flow](#21-program-flow)
22. [CLI Structure](#22-cli-structure)
23. [Code Templates](#23-code-templates)
24. [Legal Considerations](#24-legal-considerations)
25. [Project Timeline](#25-project-timeline)
26. [File Structure](#26-file-structure)
27. [Installation Guide](#27-installation-guide)
28. [Build Order Priority](#28-build-order-priority)

---

# 1. PROJECT OVERVIEW

## 1.1 What is CyberTrace?

```
CyberTrace is a unified OSINT (Open Source Intelligence) investigation 
tool that searches across Surface Web, Deep Web, and Dark Web 
simultaneously to build comprehensive profiles from minimal input.

ONE INPUT → ALL LAYERS SEARCHED → COMPLETE PROFILE
```

## 1.2 Core Concept

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INPUT                               │
│            (email, phone, username, BTC, domain, etc.)          │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AUTO-DETECT TYPE                            │
│                   (regex pattern matching)                       │
└─────────────────────────────┬───────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   SURFACE WEB   │ │    DEEP WEB     │ │    DARK WEB     │
│   (50+ sources) │ │  (25+ sources)  │ │  (20+ sources)  │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AGGREGATE & CORRELATE                         │
│              (Link findings, build relationships)                │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      UNIFIED PROFILE                             │
│                (Complete intelligence report)                    │
└─────────────────────────────────────────────────────────────────┘
```

## 1.3 Key Features

```
✅ Auto-detection of input type
✅ Searches ALL layers automatically (surface + deep + dark)
✅ 200+ sources across all categories
✅ Indian-specific databases (Vahan, MCA, GST, eCourts)
✅ Blockchain tracing (Bitcoin, Ethereum)
✅ Dark web search (via clearnet + Tor)
✅ Correlation engine (links findings across platforms)
✅ Multiple output formats (JSON, Table, PDF)
✅ 100% legal (public data only)
✅ Zero cost (free tools and APIs)
```

## 1.4 Project Details

```
Project Name:     CyberTrace
Developer:        Anubhav Mohandas
GitHub:           github.com/anubhavmohandas
Type:             Personal OSINT Research Tool
Budget:           Zero (Free tools only)
```

---

# 2. IMPLEMENTATION STATUS

## 2.1 Current Status

```
┌─────────────────────────────────────────────────────────────────┐
│                    ⚠️  IMPORTANT NOTICE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   THIS IS A BLUEPRINT/PLANNING DOCUMENT ONLY                    │
│                                                                  │
│   NO CODE HAS BEEN IMPLEMENTED YET                              │
│                                                                  │
│   This document contains:                                        │
│   ✅ Architecture design                                         │
│   ✅ Source lists and URLs                                       │
│   ✅ Code templates/examples                                     │
│   ✅ Implementation guides                                       │
│                                                                  │
│   This document does NOT contain:                                │
│   ❌ Working code                                                │
│   ❌ Tested modules                                              │
│   ❌ Functional tool                                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 2.2 What Needs To Be Built

```
ESTIMATED LINES OF CODE:

Component                    Lines        Status
─────────────────────────────────────────────────
CLI Framework                200-300      ❌ Not started
Input Detector               100-150      ❌ Not started
Email Module                 400-500      ❌ Not started
Phone Module                 500-700      ❌ Not started
Username Module              300-400      ❌ Not started
Domain Module                400-500      ❌ Not started
Bitcoin Module               300-400      ❌ Not started
Indian Module                600-800      ❌ Not started
Dark Web Module              400-500      ❌ Not started
Social Media Module          400-500      ❌ Not started
Image Module                 300-400      ❌ Not started
GEOINT Module                300-400      ❌ Not started
Forum Module                 300-400      ❌ Not started
Breach Module                200-300      ❌ Not started
Telegram Module              200-300      ❌ Not started
Correlation Engine           400-500      ❌ Not started
Utilities (HTTP, Cache)      500-600      ❌ Not started
Output Formatter             200-300      ❌ Not started
─────────────────────────────────────────────────
TOTAL                        6000-8000    ❌ Not started
```

---

# 3. ARCHITECTURE

## 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CYBERTRACE                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    CLI INTERFACE                         │    │
│  │                  (Click Framework)                       │    │
│  │                                                          │    │
│  │   $ cybertrace search "target"                          │    │
│  │   $ cybertrace search "target" --tor                    │    │
│  │   $ cybertrace search "target" --output pdf             │    │
│  └─────────────────────────┬───────────────────────────────┘    │
│                            │                                     │
│  ┌─────────────────────────▼───────────────────────────────┐    │
│  │                  INPUT DETECTOR                          │    │
│  │        (Auto-detect: email, phone, BTC, etc.)           │    │
│  └─────────────────────────┬───────────────────────────────┘    │
│                            │                                     │
│  ┌─────────────────────────▼───────────────────────────────┐    │
│  │                  MODULE ROUTER                           │    │
│  │           (Routes to appropriate modules)                │    │
│  └─────────────────────────┬───────────────────────────────┘    │
│                            │                                     │
│  ┌─────────────────────────▼───────────────────────────────┐    │
│  │                 DATA COLLECTION LAYER                    │    │
│  │  ┌─────────┬─────────┬─────────┬─────────┬─────────┐    │    │
│  │  │ Surface │  Deep   │  Dark   │ Block-  │ Indian  │    │    │
│  │  │   Web   │   Web   │   Web   │  chain  │ Sources │    │    │
│  │  │ 50+ src │ 25+ src │ 20+ src │ 10+ src │ 15+ src │    │    │
│  │  └─────────┴─────────┴─────────┴─────────┴─────────┘    │    │
│  └─────────────────────────┬───────────────────────────────┘    │
│                            │                                     │
│  ┌─────────────────────────▼───────────────────────────────┐    │
│  │                CORRELATION ENGINE                        │    │
│  │         (Link findings, build relationships)             │    │
│  └─────────────────────────┬───────────────────────────────┘    │
│                            │                                     │
│  ┌─────────────────────────▼───────────────────────────────┐    │
│  │                   CACHE LAYER                            │    │
│  │              (SQLite, 24hr expiry)                       │    │
│  └─────────────────────────┬───────────────────────────────┘    │
│                            │                                     │
│  ┌─────────────────────────▼───────────────────────────────┐    │
│  │                  OUTPUT FORMATTER                        │    │
│  │              (JSON, Table, HTML, PDF)                    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 3.2 Module Architecture

```
MODULES OVERVIEW:

cybertrace/modules/
├── base.py              # Base class for all modules
├── email_module.py      # Email OSINT (15+ sources)
├── phone_module.py      # Phone lookups (27+ sources)
├── username_module.py   # Username enum (2500+ sites)
├── domain_module.py     # Domain intel (20+ sources)
├── bitcoin_module.py    # Blockchain analysis (10+ sources)
├── indian_module.py     # Indian databases (15+ sources)
├── image_module.py      # Image analysis (10+ sources)
├── forum_module.py      # Forum search (50+ sources)
├── darkweb_module.py    # Dark web OSINT (20+ sources)
├── breach_module.py     # Breach databases (5+ sources)
├── telegram_module.py   # Telegram OSINT (5+ sources)
├── social_module.py     # Social media (15+ platforms)
├── geoint_module.py     # Geolocation intel (25+ sources)
└── correlation.py       # Link analysis
```

---

# 4. INPUT DETECTION SYSTEM

## 4.1 Supported Input Types

```
INPUT TYPE          EXAMPLE                         MODULES TRIGGERED
─────────────────────────────────────────────────────────────────────
Email               user@example.com                Email, Breach, Social
Phone (Indian)      +919876543210                   Phone, Social, Breach
Phone (Intl)        +14155551234                    Phone, Social
Username            hackerman123                    Username, Forum, Dark
Domain              example.com                     Domain, Archive
Bitcoin             1A1zP1eP5Q...                   Bitcoin, Dark
Ethereum            0x742d35Cc...                   Bitcoin (ETH module)
Onion URL           abc123.onion                    Dark Web
Vehicle (Indian)    MH12AB1234                      Indian
PAN (Indian)        ABCDE1234F                      Indian
GSTIN               22AAAAA0000A1Z5                 Indian
IP Address          192.168.1.1                     Domain, GEOINT
Image File          photo.jpg                       Image, GEOINT
```

## 4.2 Detection Patterns (Regex)

```python
INPUT_PATTERNS = {
    # Email
    'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    
    # Phone Numbers
    'phone_indian': r'^(?:\+91|91|0)?[6789]\d{9}$',
    'phone_international': r'^\+[1-9]\d{1,14}$',
    
    # Cryptocurrency
    'btc_legacy': r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',
    'btc_bech32': r'^bc1[a-z0-9]{39,59}$',
    'ethereum': r'^0x[a-fA-F0-9]{40}$',
    
    # Domains & URLs
    'domain': r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
    'onion': r'^[a-z2-7]{16,56}\.onion$',
    'url': r'^https?://[^\s]+$',
    
    # Indian Identifiers
    'vehicle_indian': r'^[A-Z]{2}[-.\s]?\d{1,2}[-.\s]?[A-Z]{1,2}[-.\s]?\d{4}$',
    'pan_indian': r'^[A-Z]{5}[0-9]{4}[A-Z]$',
    'aadhaar': r'^\d{4}\s?\d{4}\s?\d{4}$',
    'gstin': r'^\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}$',
    'ifsc': r'^[A-Z]{4}0[A-Z0-9]{6}$',
    
    # Network
    'ipv4': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    'ipv6': r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$',
    'mac': r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
    
    # Default
    'username': r'^[a-zA-Z0-9_.-]{3,30}$'
}
```

## 4.3 Detection Logic Flow

```
INPUT: "something"
         │
         ├─── Contains @ and domain? ──────────► EMAIL
         │
         ├─── Starts with +91/91/0, 10 digits? ► INDIAN PHONE
         │
         ├─── Starts with +, 7-15 digits? ─────► INTERNATIONAL PHONE
         │
         ├─── Starts with 1/3, 26-35 chars? ───► BTC LEGACY
         │
         ├─── Starts with bc1? ────────────────► BTC BECH32
         │
         ├─── Starts with 0x, 42 hex chars? ───► ETHEREUM
         │
         ├─── Ends with .onion? ───────────────► ONION URL
         │
         ├─── Has dots, looks like domain? ────► DOMAIN
         │
         ├─── Matches XX00XX0000? ─────────────► INDIAN VEHICLE
         │
         ├─── Matches XXXXX0000X? ─────────────► PAN CARD
         │
         ├─── 12 digits? ─────────────────────► AADHAAR (maybe)
         │
         ├─── IP pattern? ────────────────────► IP ADDRESS
         │
         └─── Default ────────────────────────► USERNAME
```

---

# 5. COMPLETE MODULE LIST

## 5.1 All Modules Summary

```
MODULE              SOURCES   RELIABILITY   BUILD PRIORITY
────────────────────────────────────────────────────────────
Username            2500+     90%           HIGH (Easy)
Domain              20+       85%           HIGH (Easy)
Bitcoin             10+       95%           HIGH (Easy)
Email               15+       70%           HIGH (Medium)
Phone               27+       40%           MEDIUM (Hard)
Indian              15+       50%           MEDIUM (Hard)
Dark Web            20+       50%           MEDIUM (Medium)
Social Media        15+       40%           LOW (Hard)
GEOINT              25+       70%           LOW (Medium)
Forum               50+       60%           LOW (Medium)
Image               10+       60%           LOW (Medium)
Breach              5+        30%           LOW (Limited)
Telegram            5+        70%           LOW (Easy)
────────────────────────────────────────────────────────────
TOTAL               200+
```

---

# 6. PHONE INVESTIGATION MODULE

## 6.1 Complete Phone Sources (27)

```
SOURCE                  METHOD          AUTH NEEDED      DIFFICULTY   REGION
────────────────────────────────────────────────────────────────────────────
Free Carrier Lookup     HTTP Scrape     None             Easy         Global
Carrier Lookup          HTTP Scrape     None             Easy         Global
Twilio                  API             Free Account     Easy         Global
Apeiron                 API/Web         Account          Medium       Global
Truecaller              Scraping        Session+Tricks   HARD         Global
Spy Dialer              Scraping        None             Medium       US
EPIEOS                  Web             None             Easy         Global
OSINT Industries        API             PAID             Skip         Global
Castrick                Web             None             Easy         Global
Google                  Dorking         None             Easy         Global
Bing                    Dorking         None             Easy         Global
UniversalSearchBot      Telegram Bot    Telegram Acc     Easy         Global
Phoneinfoga             Local Tool      None             Easy         Global
NumLookup               Scraping        None             Easy         Global
Osint.rocks             Web             None             Easy         Global
WhatsApp Checkleaked    Web             None             Easy         Global
WhitePages              Scraping        None             Medium       US
DeHashed                API             Free Account     Easy         Global
Detectdee               Local Tool      None             Easy         Global
Ignorant                Local Tool      None             Easy         Global
HaveIBeenZuckered       Web             None             Easy         Global
Sync.me                 Scraping        None             Medium       Global
Eyecon                  Scraping        None             Medium       Global
WhatsApp                Web Session     WhatsApp Acc     Medium       Global
Telegram                API             Bot Token        Easy         Global
Signal                  App Only        SKIP             -            -
NumVerify               API             Free Account     Easy         Global
TRAI DND                Web             None             Easy         India
```

## 6.2 Phone Sources by Access Method

### Easy Sources (Direct HTTP - No Auth)
```
1. Free Carrier Lookup   https://freecarrierlookup.com/
2. Carrier Lookup        https://www.carrierlookup.com/
3. EPIEOS                https://epieos.com/
4. Castrick              https://castrickclues.com/
5. NumLookup             https://www.numlookup.com/
6. Osint.rocks           https://osint.rocks/
7. WhatsApp Checkleaked  https://checkleaked.cc/
8. HaveIBeenZuckered     https://haveibeenzuckered.com/
9. TRAI DND              https://trai.gov.in/
10. Google Dorking       "phone number" searches
11. Bing Dorking         "phone number" searches
```

### Local Tools (Install and Run)
```
1. Phoneinfoga
   Install: go install github.com/sundowndev/phoneinfoga/v2@latest
   Usage: phoneinfoga scan -n "+919876543210"
   
2. Ignorant
   Install: pip install ignorant
   GitHub: github.com/megadose/ignorant
   Usage: ignorant +919876543210
   
3. Detectdee
   GitHub: github.com/BobTheShoplifter/Detectdee
   Usage: python detectdee.py +919876543210
```

### Telegram Bots
```
1. UniversalSearchBot    @UniversalSearchBot
2. LeakOsintBot          @LeakOsintBot
3. GetContact Bot        @getcontact_real_bot

Method: Send phone number to bot, receive results
Needs: Telegram account
```

### Free API (Need Account)
```
1. Twilio
   URL: https://www.twilio.com/
   Free: Yes (trial credits)
   Get: Phone line type, carrier
   
2. NumVerify
   URL: https://numverify.com/
   Free: 100 requests/month
   Get: Carrier, location, line type
   
3. DeHashed
   URL: https://dehashed.com/
   Free: Limited searches
   Get: Breach data with phone
```

### Hard Sources (Anti-Bot Protection)
```
1. Truecaller
   Challenge: Heavy anti-bot, needs mobile session
   Method: Selenium + mobile user agent + cookies
   Success Rate: 30%
   
2. Sync.me
   Challenge: Rate limiting
   Method: Session rotation
   Success Rate: 50%
   
3. Eyecon
   Challenge: Anti-bot
   Method: Browser automation
   Success Rate: 50%
   
4. WhitePages
   Challenge: US only, captcha sometimes
   Method: Selenium + proxy
   Success Rate: 60% (US only)
   
5. Spy Dialer
   Challenge: US focused
   Method: Scraping
   Success Rate: 70% (US only)
```

### Skip (Paid or Impossible)
```
1. OSINT Industries - Paid only
2. Pipl - Paid only
3. Signal - App only, can't automate
```

## 6.3 Phone Module Code Template

```python
# cybertrace/modules/phone_module.py

import asyncio
import aiohttp
from typing import Dict, Any
from .base import BaseModule

class PhoneModule(BaseModule):
    name = "phone"
    description = "Phone number OSINT"
    
    def __init__(self, config):
        super().__init__(config)
        
        # Categorize sources by difficulty
        self.easy_sources = [
            self.check_freecarrierlookup,
            self.check_epieos,
            self.check_numlookup,
            self.check_osint_rocks,
            self.check_haveibeenzuckered,
            self.google_dork,
            self.bing_dork,
        ]
        
        self.local_tools = [
            self.run_phoneinfoga,
            self.run_ignorant,
        ]
        
        self.api_sources = [
            self.check_numverify,
            self.check_twilio,
        ]
        
        self.hard_sources = [
            self.check_truecaller,
            self.check_syncme,
        ]
    
    async def search(self, phone: str, **options) -> Dict[str, Any]:
        """Search phone across ALL available sources"""
        
        results = {
            'target': phone,
            'type': 'phone',
            'sources': {},
            'summary': {}
        }
        
        # Normalize phone number
        phone = self.normalize_phone(phone)
        
        # 1. Run EASY sources (fast, reliable)
        easy_tasks = [source(phone) for source in self.easy_sources]
        easy_results = await asyncio.gather(*easy_tasks, return_exceptions=True)
        
        # 2. Run LOCAL tools
        local_tasks = [tool(phone) for tool in self.local_tools]
        local_results = await asyncio.gather(*local_tasks, return_exceptions=True)
        
        # 3. Run API sources (if keys available)
        if self.config.has_api_keys(['numverify', 'twilio']):
            api_tasks = [source(phone) for source in self.api_sources]
            api_results = await asyncio.gather(*api_tasks, return_exceptions=True)
        
        # 4. Run HARD sources (if enabled)
        if options.get('deep'):
            hard_tasks = [source(phone) for source in self.hard_sources]
            hard_results = await asyncio.gather(*hard_tasks, return_exceptions=True)
        
        # Aggregate all results
        return self.aggregate_results(results)
    
    def normalize_phone(self, phone: str) -> str:
        """Normalize phone to E.164 format"""
        phone = ''.join(filter(str.isdigit, phone))
        if phone.startswith('91') and len(phone) == 12:
            return '+' + phone
        if len(phone) == 10:
            return '+91' + phone
        return '+' + phone
    
    async def check_epieos(self, phone: str) -> dict:
        """Check EPIEOS for phone"""
        url = f"https://epieos.com/?phone={phone}"
        # Implementation...
        pass
    
    async def run_phoneinfoga(self, phone: str) -> dict:
        """Run Phoneinfoga locally"""
        import subprocess
        result = subprocess.run(
            ['phoneinfoga', 'scan', '-n', phone],
            capture_output=True, text=True
        )
        return {'raw': result.stdout}
    
    async def check_truecaller(self, phone: str) -> dict:
        """
        Truecaller - HARD
        Needs: Selenium, mobile UA, session cookies
        """
        # This is complex - needs browser automation
        pass
```

---

# 7. EMAIL MODULE

## 7.1 Complete Email Sources (15)

```
SOURCE              METHOD          AUTH NEEDED      DIFFICULTY   DATA RETURNED
───────────────────────────────────────────────────────────────────────────────
HaveIBeenPwned      Web Scrape      None             Easy         Breach names
Gravatar            API             None             Easy         Profile pic, info
Holehe              Local Tool      None             Easy         120+ site checks
EPIEOS              Web             None             Easy         Google account info
GitHub Commits      API             Token (free)     Easy         Repos, commits
GitLab Commits      API             Token (free)     Easy         Repos, commits
EmailRep.io         API             Free Key         Easy         Reputation, info
Hunter.io           API             Free Key         Easy         Company, sources
PGP Keyservers      HTTP            None             Easy         PGP keys
DeHashed            API             Free Account     Easy         Breach data
IntelligenceX       API             Free Key         Easy         Pastes, leaks
LeakCheck           API             Limited Free     Easy         Breach data
Pastebin (Dork)     Google          None             Easy         Paste mentions
Skype               Scraping        None             Medium       Profile exists
Spotify             Scraping        None             Medium       Profile exists
```

## 7.2 Email Sources Detail

```yaml
# Easy (No Auth)
gravatar:
  url: "https://www.gravatar.com/avatar/{md5_hash}?d=404"
  method: MD5 hash of email, check if 200
  returns: Profile picture URL

epieos:
  url: "https://epieos.com/?email={email}"
  method: Direct lookup
  returns: Google account info, linked services

haveibeenpwned:
  url: "https://haveibeenpwned.com/unifiedsearch/{email}"
  method: Web scraping (API is paid)
  returns: Breach names, dates

holehe:
  install: "pip install holehe"
  usage: "holehe {email}"
  returns: 120+ sites where email is registered

pgp_servers:
  - "https://keys.openpgp.org/search?q={email}"
  - "https://pgp.mit.edu/pks/lookup?search={email}"
  returns: PGP public keys

# Free API (Need Key)
emailrep:
  url: "https://emailrep.io/{email}"
  header: "Key: {api_key}"
  free: 100/day
  returns: Reputation, suspicious, references

github:
  url: "https://api.github.com/search/commits?q=author-email:{email}"
  header: "Authorization: token {token}"
  free: 5000/hour
  returns: Commits, repos, usernames

hunter:
  url: "https://api.hunter.io/v2/email-verifier?email={email}&api_key={key}"
  free: 25/month
  returns: Deliverable, company, sources
```

---

# 8. USERNAME MODULE

## 8.1 Username Enumeration Tools

```
TOOL            SITES       METHOD          USAGE
──────────────────────────────────────────────────────────
Maigret         2500+       Local Python    maigret username
Sherlock        300+        Local Python    sherlock username
WhatsMyName     500+        Local/API       python check.py
Namechk         100+        Web             namechk.com
KnowEm          500+        Web             knowem.com
Instant Username 100+       Web             instantusername.com
```

## 8.2 Major Platforms to Check

```yaml
social_media:
  - instagram.com/{username}
  - twitter.com/{username}
  - facebook.com/{username}
  - tiktok.com/@{username}
  - youtube.com/@{username}
  - pinterest.com/{username}
  - reddit.com/user/{username}
  - tumblr.com/{username}
  - snapchat.com/add/{username}
  - linkedin.com/in/{username}

developer:
  - github.com/{username}
  - gitlab.com/{username}
  - bitbucket.org/{username}
  - stackoverflow.com/users/{username}
  - dev.to/{username}
  - codepen.io/{username}
  - replit.com/@{username}
  - hackerrank.com/{username}

gaming:
  - steamcommunity.com/id/{username}
  - twitch.tv/{username}
  - mixer.com/{username}
  - discord (can't directly check)

indian:
  - sharechat.com/profile/{username}
  - kooapp.com/profile/{username}

messaging:
  - t.me/{username}

other:
  - medium.com/@{username}
  - about.me/{username}
  - keybase.io/{username}
  - patreon.com/{username}
```

## 8.3 Username Module Code Template

```python
# cybertrace/modules/username_module.py

import asyncio
import subprocess
from .base import BaseModule

class UsernameModule(BaseModule):
    name = "username"
    description = "Username enumeration across 2500+ sites"
    
    async def search(self, username: str, **options) -> dict:
        results = {
            'target': username,
            'type': 'username',
            'found_on': [],
            'not_found': [],
            'errors': []
        }
        
        # Run Maigret (best tool, 2500+ sites)
        maigret_results = await self.run_maigret(username)
        
        # Run Sherlock as backup
        sherlock_results = await self.run_sherlock(username)
        
        # Custom checks for sites tools might miss
        custom_results = await self.custom_checks(username)
        
        # Merge all results
        return self.merge_results(
            maigret_results, 
            sherlock_results, 
            custom_results
        )
    
    async def run_maigret(self, username: str) -> dict:
        """Run Maigret - 2500+ sites"""
        result = subprocess.run(
            ['maigret', username, '--json', 'output.json'],
            capture_output=True, text=True
        )
        # Parse JSON output
        return self.parse_maigret_output()
    
    async def run_sherlock(self, username: str) -> dict:
        """Run Sherlock - 300+ sites"""
        result = subprocess.run(
            ['sherlock', username, '--print-found'],
            capture_output=True, text=True
        )
        return self.parse_sherlock_output(result.stdout)
```

---

# 9. DOMAIN MODULE

## 9.1 Complete Domain Sources (20)

```
SOURCE              METHOD          AUTH NEEDED      DATA RETURNED
────────────────────────────────────────────────────────────────────
WHOIS               Library         None             Registrant, dates
DNS (A, MX, NS)     Library         None             IP, mail, nameservers
DNS (TXT, CNAME)    Library         None             SPF, DKIM, aliases
crt.sh              HTTP            None             SSL certificates, SANs
DNSDumpster         HTTP            None             Subdomains, map
SecurityTrails      API             Free Key         Subdomains, history
VirusTotal          API             Free Key         Analysis, detections
URLScan.io          API             Free Key         Screenshot, tech
Shodan              API             Free Key         Ports, services
Censys              API             Free Key         Certificates, hosts
BuiltWith           HTTP            None             Technology stack
Wappalyzer          Local           None             Technology detection
Archive.org         HTTP            None             Historical snapshots
Archive.today       HTTP            None             Snapshots
Google Cache        HTTP            None             Cached version
BGPView             HTTP            None             ASN, IP ranges
Robtex              HTTP            None             Network info
RapidDNS            HTTP            None             Subdomains
SSL Labs            API             None             SSL grade, config
```

## 9.2 Domain Module Data Flow

```
INPUT: example.com
         │
         ├── WHOIS ────────────► Registrant, Dates, Registrar
         │
         ├── DNS ──────────────► A, MX, NS, TXT, CNAME records
         │
         ├── SSL ──────────────► Certificate info, SANs, expiry
         │
         ├── crt.sh ───────────► All certificates, subdomains from SANs
         │
         ├── Subdomains ───────► DNSDumpster, SecurityTrails, RapidDNS
         │
         ├── Security ─────────► VirusTotal, URLScan, Shodan
         │
         ├── Technology ───────► BuiltWith, Wappalyzer detection
         │
         ├── Archives ─────────► Wayback Machine, Archive.today
         │
         └── Network ──────────► BGP, ASN, IP ranges

OUTPUT: Complete domain profile
```

---

# 10. BITCOIN/CRYPTO MODULE

## 10.1 Complete Blockchain Sources (10)

```
SOURCE              CHAINS          AUTH NEEDED      DATA RETURNED
────────────────────────────────────────────────────────────────────
Blockchain.info     BTC             None             Full tx history
Blockchair          BTC,ETH,LTC+    None             Multi-chain analysis
BlockCypher         BTC,ETH,LTC     Free Key         Detailed tx data
Blockstream.info    BTC             None             Full node data
BTC.com             BTC             None             Pool info, tx
OXT.me              BTC             None             Advanced analysis
WalletExplorer      BTC             None             Wallet clustering
BitcoinAbuse        BTC             None             Scam reports
Etherscan           ETH             Free Key         Full ETH data
Ethplorer           ETH             None             Token transfers
```

## 10.2 What You Can Find from BTC Address

```
INPUT: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

ALWAYS AVAILABLE (Blockchain is public):
├── Balance (current)
├── Total received (all time)
├── Total sent (all time)
├── Transaction count
├── First transaction date
├── Last transaction date
├── Full transaction list
│   ├── Each input address
│   ├── Each output address
│   ├── Amount
│   └── Timestamp
├── Connected addresses (1 hop)
└── Wallet cluster (same wallet)

ANALYSIS:
├── Known labels (exchange, service, scam)
├── Abuse reports
├── Mixing detection (Wasabi, Samourai patterns)
├── Exchange deposit detection
└── Time zone estimation (from tx times)
```

## 10.3 Why Blockchain Module Always Works

```
SUCCESS RATE: 95%

WHY IT'S RELIABLE:
├── Blockchain is PUBLIC by design
├── No authentication needed
├── No anti-bot protection
├── Multiple free APIs available
├── Data never changes (immutable)
└── Same result from any explorer

THIS IS YOUR MOST RELIABLE MODULE
```

---

# 11. INDIAN OSINT MODULE

## 11.1 Why Indian OSINT is "Weak" (Easy for investigators)

```
REASONS DATA IS EASILY AVAILABLE:

1. GOVERNMENT PORTALS ARE PUBLIC
   └── Vahan shows owner name + full address
   └── No real authentication (just captcha)

2. NO STRICT DATA PROTECTION LAW
   └── DPDP Act 2023 is new, not enforced
   └── Previously no privacy law existed

3. DATA BROKERS OPERATE OPENLY
   └── Apps aggregate government data
   └── CarInfo, Vehicle Info, etc.

4. EVERYTHING IS LINKED
   └── Aadhaar mandatory linking
   └── PAN → Aadhaar → Phone → Address

5. FREQUENT DATA LEAKS
   └── Aadhaar, Telecom, Bank leaks
   └── Data sold on dark web
```

## 11.2 Indian OSINT Sources (15)

```
SOURCE              INPUT TYPE       DATA RETURNED           DIFFICULTY
─────────────────────────────────────────────────────────────────────────
Vahan/Parivahan     Vehicle No.      Owner, Address, RC      Medium (captcha)
mParivahan App      Vehicle No.      Same as Vahan           Medium (app)
MCA Portal          Company/CIN      Directors, Filings      Easy
GST Portal          GSTIN            Business details        Easy
eCourts             Name/Case No.    Court cases             Easy
Indian Kanoon       Name/Keywords    Judgments               Easy
Zauba Corp          Company          Directors, Financials   Easy
Tofler              Company          Financials              Easy
JustDial            Business Name    Contact, Address        Easy
IndiaMART           Business         Manufacturer info       Easy
SEBI                Entity           Registered status       Easy
RBI                 Entity           Authorization           Easy
UGC                 University       Verification            Easy
EPFO                UAN              Employment records      Medium
Property Records    Name (varies)    Land ownership          Hard (state-wise)
```

## 11.3 Vehicle Number → Complete Profile

```
INPUT: MH12AB1234
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    VEHICLE OSINT FLOW                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  VAHAN PORTAL ────────────────────────────────────────────────► │
│  │                                                               │
│  └── Owner's Full Name                                          │
│  └── Father's Name                                              │
│  └── Full Address                                               │
│  └── Registration Date                                          │
│  └── Vehicle Make/Model/Color                                   │
│  └── Chassis Number                                             │
│  └── Engine Number                                              │
│  └── Fuel Type                                                  │
│  └── RTO                                                        │
│                                                                  │
│  INSURANCE PORTAL ────────────────────────────────────────────► │
│  │                                                               │
│  └── Insurance Status                                           │
│  └── Insurance Company                                          │
│  └── Policy Expiry                                              │
│                                                                  │
│  POLLUTION PORTAL ────────────────────────────────────────────► │
│  │                                                               │
│  └── PUCC Status                                                │
│  └── Validity                                                   │
│                                                                  │
│  CHALLAN PORTALS (State-wise) ────────────────────────────────► │
│  │                                                               │
│  └── Traffic Violations                                         │
│  └── Pending Fines                                              │
│                                                                  │
│  GOOGLE DORK ─────────────────────────────────────────────────► │
│  │                                                               │
│  └── OLX/Car Listings (may have phone)                         │
│  └── Forum Posts                                                │
│  └── Accident Reports                                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
    AGGREGATED PROFILE:
    ├── Owner: Rahul Sharma
    ├── Address: [Full address]
    ├── Vehicle: Honda City 2019 White
    ├── Insurance: ICICI Lombard (Active)
    ├── Challans: 3 pending
    └── Phone: Found via OLX listing
```

## 11.4 Phone Number → Identity (India)

```
INPUT: +919876543210
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│  TRUECALLER ───────► Name: "Rahul S"                            │
│                                                                  │
│  WHATSAPP ─────────► Profile Pic, Status                        │
│                                                                  │
│  FACEBOOK LEAK ────► Full profile (533M leak)                   │
│                      Name, DOB, Location, Email                 │
│                                                                  │
│  GOOGLE DORK ──────► Old listings, posts                        │
│                      "9876543210" site:olx.in                   │
│                      "9876543210" site:justdial.com             │
│                                                                  │
│  UPI HANDLE ───────► Name confirmation                          │
│                      9876543210@upi → "Rahul Sharma"            │
│                                                                  │
│  DATA BROKERS ─────► Full profile (if leaked)                   │
│                      Aadhaar, Address                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
    AGGREGATED PROFILE:
    ├── Name: Rahul Sharma
    ├── Location: Mumbai (from Facebook)
    ├── Email: rahul.s@gmail.com (from leak)
    └── More data if lucky
```

## 11.5 Company → Directors → Personal

```
INPUT: Company Name or CIN
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│  MCA PORTAL ───────────────────────────────────────────────────►│
│  │                                                               │
│  └── Company CIN                                                │
│  └── Registration Date                                          │
│  └── Registered Address                                         │
│  └── Directors List                                             │
│      ├── Director 1: Name, DIN, Address                        │
│      ├── Director 2: Name, DIN, Address                        │
│      └── ...                                                    │
│  └── Annual Filings                                             │
│  └── Charges (Loans)                                            │
│                                                                  │
│  GST PORTAL ───────────────────────────────────────────────────►│
│  │                                                               │
│  └── GST Number                                                 │
│  └── Trade Name                                                 │
│  └── Principal Place of Business                                │
│                                                                  │
│  ZAUBA CORP ───────────────────────────────────────────────────►│
│  │                                                               │
│  └── Financial Summary                                          │
│  └── Director History                                           │
│  └── Similar Companies                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
    FOR EACH DIRECTOR:
    ├── DIN → Other directorships
    ├── Address → Personal residence
    ├── Name → LinkedIn, Social Media
    └── Name + Address → More OSINT
```

## 11.6 Captcha Challenge

```
PROBLEM:
├── Vahan Portal has captcha on every search
├── eCourts has captcha
├── Some state portals have captcha

SOLUTIONS:

1. MANUAL (For testing)
   └── Just solve it manually
   └── Fine for development and testing

2. 2CAPTCHA SERVICE (Production)
   └── Cost: $2-3 per 1000 captchas
   └── API: Send image, get solution
   └── Works well

3. LOCAL OCR (Unreliable)
   └── Tesseract OCR
   └── Success rate: 30-40%
   └── Not recommended

4. CAPTCHA SOLVING SERVICES
   └── Anti-Captcha
   └── DeathByCaptcha
   └── Similar pricing to 2captcha
```

---

# 12. DARK WEB MODULE

## 12.1 How Dark Web Search Works

```
TWO METHODS:

METHOD 1: CLEARNET GATEWAYS (No Tor needed)
├── Search dark web FROM normal internet
├── Works without Tor installed
├── Fast and reliable
├── DEFAULT METHOD

METHOD 2: DIRECT TOR (--tor flag)
├── Connect to Tor network directly
├── Access .onion sites
├── Slower but more comprehensive
├── OPTIONAL
```

## 12.2 Clearnet Gateways (No Tor)

```
SOURCE              URL                         DATA AVAILABLE
───────────────────────────────────────────────────────────────
Ahmia.fi            ahmia.fi                    Indexed onion sites
DarkSearch.io       darksearch.io               Dark web search API
IntelligenceX       intelx.io                   Pastes, leaks, archives
Dark.fail           dark.fail                   Live onion addresses
Onion.live          onion.live                  Directory
Tor.taxi            tor.taxi                    Curated links
DarkWebDaily        darkwebdaily.live           Updated directory
```

## 12.3 Direct Tor Sources

```
SOURCE              TYPE                        ACCESS
───────────────────────────────────────────────────────────────
Torch               Search Engine               .onion (dynamic)
Haystack            Search Engine               .onion (dynamic)
Not Evil            Search Engine               .onion (dynamic)
Candle              Search Engine               .onion (dynamic)
Kilos               Market Search               .onion (dynamic)
DuckDuckGo          Search Engine               .onion (static)
Dread               Forum                       .onion (dynamic)
The Hub             Forum                       .onion (dynamic)

NOTE: Never hardcode .onion addresses - fetch from dark.fail
```

## 12.4 Dynamic Address Discovery

```python
# Onion addresses change frequently
# Always fetch current addresses from clearnet sources

DYNAMIC_SOURCES = {
    'dark.fail': 'https://dark.fail',
    'onion.live': 'https://onion.live',
    'tor.taxi': 'https://tor.taxi'
}

async def get_current_onion(service_name: str) -> str:
    """Fetch current .onion address from clearnet"""
    # Scrape dark.fail for current address
    # Cache for 6 hours
    # Return .onion URL
    pass
```

## 12.5 Tor Integration

```python
# Tor Configuration

# Install Tor:
# Linux: sudo apt install tor
# macOS: brew install tor

# Start Tor service:
# Linux: sudo service tor start
# macOS: brew services start tor

# Python config:
TOR_PROXIES = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

# Using with requests:
import requests
response = requests.get(
    'http://torchqsxkllsdc.onion/search?query=test',
    proxies=TOR_PROXIES,
    timeout=60  # Tor is slow
)

# Circuit rotation (new identity):
from stem import Signal
from stem.control import Controller

def new_identity():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
```

---

# 13. SOCIAL MEDIA MODULE

## 13.1 Platforms to Search

```
PLATFORM            METHOD          SUCCESS RATE    NOTES
───────────────────────────────────────────────────────────────
GitHub              API/Scrape      90%             Easy, reliable
Twitter/X           Scrape          40%             Heavy anti-bot
Instagram           Scrape          30%             Very aggressive blocking
Facebook            Scrape          20%             Extremely hard
LinkedIn            Scrape          30%             Blocks aggressively
TikTok              Scrape          40%             Anti-bot
Reddit              API             80%             Good free API
YouTube             API             70%             Free quota
Pinterest           Scrape          50%             Medium difficulty
Twitch              API             80%             Free API
Discord             Manual          -               Can't automate
Telegram            API             80%             Bot API works
Snapchat            Special         50%             Use tools below
```

## 13.2 Snapchat OSINT Tools

```
TOOL                URL/SOURCE                      PURPOSE
───────────────────────────────────────────────────────────────
SnapIntel           github.com/Kr0wZ/SnapIntel      Analyze user activity
Snap Map            snapchat.com/discover           Real-time location
Snap Map Scraper    github.com/nemec/snapchat-map-scraper  Location automation
GhostCodes          ghostcodes.com                  Find profiles by interest
```

---

# 14. GEOINT MODULE

## 14.1 Geospatial Intelligence Sources

```
CATEGORY            SOURCE                  PURPOSE
───────────────────────────────────────────────────────────────
MAPPING
                    Google Maps             General mapping
                    OpenStreetMap           Open source maps
                    Bing Maps               Alternative
                    Yandex Maps             Russian regions

STREET VIEW
                    Google Street View      Eye-level imagery
                    Mapillary               Crowdsourced
                    KartaView               Open source
                    Yandex Panorama         Russia/CIS

SATELLITE
                    Google Earth            Historical imagery
                    Sentinel Hub            Free satellite
                    Zoom Earth              Quick access
                    NASA Worldview          Scientific
                    USGS Earth Explorer     Landsat data

CELL TOWERS
                    CellMapper              Tower locations
                    OpenCelliD              Open database
                    WiGLE                   WiFi + Cell mapping

FLIGHT/MARINE
                    FlightRadar24           Aircraft tracking
                    ADS-B Exchange          Unfiltered flights
                    MarineTraffic           Ship tracking
                    VesselFinder            Ship tracking

WEATHER
                    Windy.com               Weather visualization
                    Earth.nullschool        Global wind/weather

COORDINATES
                    Nominatim               Reverse geocoding
                    What3Words              Location encoding
```

---

# 15. SEARCH ENGINES & OPERATORS

## 15.1 General Search Engines

```
ENGINE              URL                     BEST FOR
───────────────────────────────────────────────────────────────
Google              google.com              General, most indexed
Bing                bing.com                Alternative results
Yandex              yandex.com              Russia, faces, reverse image
Baidu               baidu.com               Chinese content
Yahoo               yahoo.com               Older content
DuckDuckGo          duckduckgo.com          Privacy, combined results
```

## 15.2 Specialized Search Engines

```
ENGINE              URL                     PURPOSE
───────────────────────────────────────────────────────────────
Shodan              shodan.io               IoT, ports, services
Censys              search.censys.io        Certificates, hosts
ZoomEye             zoomeye.org             Chinese Shodan
GreyNoise           greynoise.io            IP reputation
VirusTotal          virustotal.com          File/URL analysis
URLScan             urlscan.io              Website analysis
IntelX              intelx.io               Leaks, pastes, dark web
OCCRP Aleph         aleph.occrp.org         Investigations
Carrot2             search.carrot2.org      Clustered results
Brave Search        search.brave.com        Independent index
Qwant               qwant.com               European, privacy
Ask                 ask.com                 Question format
AOL                 search.aol.com          Older content
Search Engine       searchenginecolossus.com  Regional engines
Colossus
Isearchfrom         isearchfrom.com         Search from other countries
2lingual            2lingual.com            Bilingual search
Academia            academia.edu            Academic papers
Internet Archive    archive.org             Historical content
Newspaper Archive   newspaperarchive.com    Historical newspapers
```

## 15.3 Google Dork Operators

```
OPERATOR            PURPOSE                 EXAMPLE
───────────────────────────────────────────────────────────────
" "                 Exact phrase            "John Doe"
AND                 Both terms              "OSINT" AND "training"
OR                  Either term             "Apple" OR "Microsoft"
-                   Exclude term            Jaguar speed -car
*                   Wildcard                OSINT * cheatsheet
..                  Number range            crime rate "2000..2024"
site:               Specific domain         site:linkedin.com
filetype:           File type               "OSINT" filetype:pdf
related:            Related sites           related:osintframework.com
inurl:              Word in URL             inurl:admin
intitle:            Word in title           intitle:"index of"
intext:             Word in body            intext:password
cache:              Cached version          cache:example.com
info:               Site info               info:example.com
link:               Sites linking to        link:example.com
define:             Definition              define:OSINT
```

## 15.4 Google Dork Examples for OSINT

```
# Find email on specific site
"email@example.com" site:linkedin.com

# Find documents with email
"email@example.com" filetype:pdf OR filetype:doc

# Find phone number mentions
"9876543210" -site:truecaller.com

# Find username across sites
"username123" site:twitter.com OR site:instagram.com OR site:github.com

# Find leaked data
"email@example.com" site:pastebin.com

# Find old profiles
"username123" site:web.archive.org

# Find by name and location
"John Doe" "New York" site:linkedin.com

# Find exposed files
site:example.com filetype:sql OR filetype:env OR filetype:log

# Find directories
site:example.com intitle:"index of"
```

## 15.5 Filetype Extensions Reference

```
DOCUMENTS
───────────────────────────────────
TXT     Text File
DOC     Microsoft Word (old)
DOCX    Microsoft Word (new)
PDF     Portable Document Format
RTF     Rich Text Format
ODT     OpenOffice Text
PAGES   Apple Pages

SPREADSHEETS
───────────────────────────────────
XLS     Excel (old)
XLSX    Excel (new)
CSV     Comma Separated Values
ODS     OpenOffice Spreadsheet

PRESENTATIONS
───────────────────────────────────
PPT     PowerPoint (old)
PPTX    PowerPoint (new)
ODP     OpenOffice Presentation
KEY     Apple Keynote

IMAGES
───────────────────────────────────
JPG     JPEG Image
JPEG    JPEG Image
PNG     PNG Image
GIF     Animated Image
BMP     Bitmap Image
WEBP    Web Image
SVG     Vector Image

ARCHIVES
───────────────────────────────────
ZIP     Compressed Archive
RAR     RAR Archive
7Z      7-Zip Archive
TAR     Tape Archive
GZ      Gzip Compressed

GEOSPATIAL
───────────────────────────────────
KML     Google Earth
KMZ     Google Earth (compressed)
GPX     GPS Exchange Format

WEB
───────────────────────────────────
HTM     Web Page
HTML    Web Page
XML     Structured Data
JSON    JSON Data

CODE
───────────────────────────────────
PY      Python
JS      JavaScript
SQL     Database
ENV     Environment Config
LOG     Log File
```

## 15.6 Key Search Factors

```
1. USE MULTIPLE SEARCH ENGINES
   └── Google + Bing + Yandex = Better coverage

2. USE SEARCH OPERATORS
   └── Exact phrases, exclude, filetype, site

3. USE INTERNATIONAL ENGINES
   └── Baidu for China, Yandex for Russia

4. USE DIFFERENT NAME VARIATIONS
   └── United States, US, USA, America

5. USE DIFFERENT SPELLINGS
   └── München, Munich, Muenchen

6. SEARCH IN MULTIPLE LANGUAGES
   └── Translate name to local language

7. USE MULTIPLE DATA TYPES
   └── Name, phone, email, address together
```

---

# 16. DARK WEB TOOLS REFERENCE (82 Tools)

## 16.1 Communication & Messaging (22 Tools)

```
TOOL                DESCRIPTION
───────────────────────────────────────────────────────────────
Ricochet IM         Decentralized anonymous chat
CSpace              Secure P2P chat
Signal (Tor)        Encrypted messaging via Tor
Tox Messenger       Decentralized secure messaging
Cryptocat           Encrypted chat rooms
Bitmessage          Encrypted email replacement
OnionShare          Share files securely over Tor
ProtonMail (Onion)  Anonymous encrypted email
SecMail             Tor-based email provider
ZeroBin             Encrypted pastebin service
RiseUp              Secure email & VPN service
Mail2Tor            Anonymous email relay
TorChat             Instant messaging over Tor
Dark Mail Alliance  Encrypted mail protocol
Keybase             Public key directory & messaging
Delta Chat          Email-based chat app
Jitsi Meet          Secure conferencing
Wickr               Expiring encrypted messages
CounterMail         Browser-based encrypted email
SimpleX Chat        No ID, fully private messaging
Session             Decentralized messenger
Briar               P2P messaging, offline sync
```

## 16.2 Dark Web Search & Crypto (20 Tools)

```
SEARCH ENGINES
───────────────────────────────────────────────────────────────
Grams               Darknet search engine
Ahmia               Tor search engine (clearnet + onion)
Torch               Oldest onion search engine
NotEvil             Popular dark web search
Haystak             Paid dark web search
Candle              Lightweight Tor search
Kilos               Market-oriented search engine
DuckDuckGo (Onion)  Private search on dark web

DIRECTORIES
───────────────────────────────────────────────────────────────
Dark.fail           Trusted onion links
Hidden Wiki         Onion site directory
Onion City          Tor2Web gateway
Tor.link            Curated onion links

CRYPTO TOOLS
───────────────────────────────────────────────────────────────
Bitcoin Core        Official Bitcoin client
Electrum Wallet     Lightweight BTC wallet
Monero CLI          XMR privacy coin wallet
Wasabi Wallet       BTC wallet with mixing
Samourai Wallet     Privacy-first BTC wallet
Bisq                Decentralized crypto exchange
Zcash Wallet        Privacy coin wallet
Dark Wallet         Bitcoin anonymity tool
LocalMonero         P2P Monero exchange
Mixers/Tumblers     Obfuscate crypto trails
```

## 16.3 Encryption & Security (20 Tools)

```
ENCRYPTION
───────────────────────────────────────────────────────────────
VeraCrypt           Disk encryption software
GnuPG               Open-source encryption for files/email
KeePassXC           Password manager
OpenSSL             Secure communication toolkit
TrueCrypt           Discontinued but still used (legacy)
PeaZip              Encrypted archiver
Cryptomator         Cloud file encryption
AxCrypt             File-level encryption
EncFS               Encrypted filesystem

SECURITY TOOLS
───────────────────────────────────────────────────────────────
Hashcat             Password recovery tool
John the Ripper     Password cracking tool
Aircrack-ng         WiFi security testing suite
Metasploit          Penetration testing framework
Maltego             OSINT data gathering
Nmap                Network mapper & scanner
Burp Suite          Web app security tool

NETWORK PRIVACY
───────────────────────────────────────────────────────────────
Shadowsocks         Proxy for censorship bypass
Privoxy             Non-caching web proxy
WireGuard           Modern VPN protocol
OpenVPN             Open-source VPN solution
```

## 16.4 Anonymous Browsing & Privacy (20 Tools)

```
BROWSERS & OS
───────────────────────────────────────────────────────────────
Tor Browser         Browse hidden .onion sites
I2P                 Anonymous peer-to-peer communication
Freenet             Secure & censorship-free web
Subgraph OS         Hardened Linux for anonymity
Whonix              VM-based privacy-focused OS
Tails OS            Live OS for anonymity

MOBILE
───────────────────────────────────────────────────────────────
Orbot               Proxy app for Android with Tor
Orfox               Android browser over Tor (deprecated)
Yandex Onion        Tor-based private browsing

CENSORSHIP BYPASS
───────────────────────────────────────────────────────────────
Psiphon             Censorship circumvention tool
Lantern             Bypass internet restrictions
Snowflake Proxy     Bridges censorship
Pluggable Transports  Hide Tor traffic patterns

OTHER
───────────────────────────────────────────────────────────────
Tor2Web             Access onion sites without Tor
JonDoFox            Firefox profile for anonymous surfing
AnonSurf            Anonymize all OS traffic
Ghostery            Anti-tracking browser extension
Epic Privacy Browser  Minimal tracking browser
```

## 16.5 Dark Web OSINT Tools

```
TOOL                GITHUB/SOURCE                   PURPOSE
───────────────────────────────────────────────────────────────
DeepDarkCTI         github.com/fastfire/deepdarkCTI  Collect CTI from dark sources
TorCrawl.py         github.com/MikeMeliz/TorCrawl.py  Crawl and extract onion pages
OnionScan           github.com/s-rah/onionscan       Analyze onion services
Onioff              github.com/k4m4/onioff           Check if onion is online
PGP Tool            Various                          Encrypt/decrypt/verify PGP
```

---

# 17. SOURCE ACCESS METHODS

## 17.1 Source Categories

```
CATEGORY            % OF SOURCES    DIFFICULTY      REQUIREMENTS
───────────────────────────────────────────────────────────────
EASY (Direct HTTP)  40%             Easy            None
LOCAL TOOLS         15%             Easy            Install once
FREE API            15%             Easy            Sign up, get key
TELEGRAM BOTS       5%              Easy            Telegram account
HARD (Anti-bot)     15%             Hard            Selenium, tricks
SKIP (Paid)         10%             -               Money

TOTAL WORKING: ~90% of sources with setup
```

## 17.2 Easy Sources (Direct HTTP)

```
WHAT: Sources that can be accessed with simple HTTP requests
NEEDS: Nothing special
METHOD: requests.get() or aiohttp
SUCCESS RATE: 90%

EXAMPLES:
├── Gravatar (email → profile pic)
├── GitHub API (public endpoints)
├── WHOIS lookups
├── DNS queries
├── Blockchain explorers
├── Google dorking
├── PGP keyservers
├── Archive.org
├── crt.sh
├── Ahmia.fi
└── Most government portals (minus captcha)
```

## 17.3 Local Tools

```
WHAT: Tools that run on your machine
NEEDS: One-time installation
METHOD: subprocess.run() or import
SUCCESS RATE: 95%

TOOLS:
├── Maigret (pip install maigret)
├── Sherlock (pip install sherlock)
├── Holehe (pip install holehe)
├── Phoneinfoga (go install)
├── Ignorant (pip install ignorant)
├── Detectdee (git clone + python)
└── ExifTool (apt install exiftool)
```

## 17.4 Free API (Need Key)

```
WHAT: APIs that need registration but are free
NEEDS: Create account, get API key
METHOD: Add to .env, use in headers
SUCCESS RATE: 95%

RECOMMENDED FREE APIS:
├── VirusTotal (500/day)
├── Shodan (100/month free)
├── URLScan.io (5000/day)
├── GitHub (5000/hour)
├── EmailRep.io (100/day)
├── IntelligenceX (limited)
├── Twilio (free trial)
├── NumVerify (100/month)
└── Hunter.io (25/month)
```

## 17.5 Telegram Bots

```
WHAT: OSINT bots on Telegram
NEEDS: Telegram account, sometimes bot token
METHOD: python-telegram-bot library
SUCCESS RATE: 80%

BOTS:
├── @UniversalSearchBot
├── @LeakOsintBot
├── @maaborbot
├── @eyeikibot
└── @getcontact_real_bot
```

## 17.6 Hard Sources (Anti-Bot)

```
WHAT: Sources with anti-bot protection
NEEDS: Selenium/Playwright, session management, proxies
METHOD: Browser automation
SUCCESS RATE: 30-60%

SOURCES:
├── Truecaller (very hard)
├── LinkedIn (hard)
├── Instagram (very hard)
├── Facebook (extremely hard)
├── Sync.me (medium)
├── WhitePages (medium)
└── Indian govt portals with captcha (medium)

TRICKS NEEDED:
├── Selenium/Playwright (browser automation)
├── Mobile user agents
├── Session/cookie management
├── Proxy rotation
├── Random delays
├── Captcha solving (2captcha)
```

## 17.7 Skip (Paid Only)

```
WHAT: Services that require payment
ACTION: Skip in free version

PAID SERVICES:
├── OSINT Industries
├── Pipl
├── Chainalysis
├── Full Truecaller API
├── HaveIBeenPwned API ($3.50/month)
├── Dehashed Pro ($15/month)
├── PimEyes
└── Maltego transforms
```

---

# 18. REALISTIC EXPECTATIONS

## 18.1 Success Rates by Target Type

```
TARGET TYPE                 SUCCESS RATE    REASON
───────────────────────────────────────────────────────────────
Unique username             80-90%          Easy to track across sites
Tech person/developer       70-80%          Leave traces (GitHub, SO)
Email (gmail/common)        40-60%          Depends on breach exposure
Common Indian name          10-20%          Too many results to filter
Phone number (Indian)       50-70%          Truecaller usually has data
Bitcoin address             90-95%          Blockchain is always public
Domain                      85-90%          WHOIS, DNS always work
Privacy-conscious person    5-10%           Intentionally leave no trace
Dark web vendor             30-50%          Depends on their OpSec
```

## 18.2 Module Reliability

```
MODULE              WILL WORK?    RELIABILITY    NOTES
───────────────────────────────────────────────────────────────
Username            ✅ Yes        90%            Maigret/Sherlock work great
Domain              ✅ Yes        85%            WHOIS, DNS always work
Bitcoin             ✅ Yes        95%            Blockchain is public
Email (basic)       ✅ Yes        70%            Gravatar, Holehe work
Google Dorking      ✅ Yes        80%            Works with delays
Dark Web (clearnet) ✅ Yes        70%            Ahmia, DarkSearch work
Indian (easy ones)  ⚠️ Partial   60%            MCA, GST work; Vahan needs captcha
Phone               ⚠️ Partial   40%            Many blocked, US-focused
Dark Web (Tor)      ⚠️ Partial   50%            Slow, unreliable
Social Media        ⚠️ Partial   40%            Heavy anti-bot
Breach Data         ⚠️ Limited   30%            Free tiers very limited
```

## 18.3 What You Should Claim

```
✅ DO CLAIM:
├── "Automates OSINT across 100+ sources"
├── "Searches surface, deep, and dark web"
├── "Reduces investigation time from hours to minutes"
├── "Complete blockchain tracing"
├── "Indian database integration"
├── "Correlation across platforms"

❌ DON'T CLAIM:
├── "Can identify anyone"
├── "100% success rate"
├── "Breaks anonymity"
├── "Real-time surveillance"
├── "All 200+ sources work perfectly"
```

---

# 19. WHAT WORKS VS WHAT DOESN'T

## 19.1 What Will DEFINITELY Work

```
BUILD THESE FIRST - THEY WORK:

1. USERNAME ENUMERATION
   └── Maigret (2500+ sites)
   └── Sherlock (300+ sites)
   └── Success: 90%
   └── Effort: Low

2. BLOCKCHAIN ANALYSIS
   └── All explorers work (blockchain.info, etc.)
   └── No anti-bot
   └── Success: 95%
   └── Effort: Low

3. DOMAIN INTELLIGENCE
   └── WHOIS, DNS, SSL
   └── crt.sh, DNSDumpster
   └── VirusTotal, Shodan APIs
   └── Success: 85%
   └── Effort: Low

4. BASIC EMAIL CHECKS
   └── Gravatar, Holehe, GitHub
   └── PGP keyservers
   └── Success: 70%
   └── Effort: Low

5. GOOGLE DORKING
   └── Works with delays
   └── Success: 80%
   └── Effort: Low

6. DARK WEB (CLEARNET)
   └── Ahmia.fi works great
   └── DarkSearch.io API works
   └── Success: 70%
   └── Effort: Low
```

## 19.2 What Will STRUGGLE

```
THESE ARE HARD - EXPECT ISSUES:

1. TRUECALLER
   └── Heavy anti-bot
   └── Needs mobile session
   └── Changes frequently
   └── Success: 30%
   └── Effort: Very High

2. INDIAN GOVT PORTALS
   └── Captcha everywhere
   └── Need solving service
   └── Success: 50%
   └── Effort: High

3. INSTAGRAM / FACEBOOK
   └── Extremely aggressive blocking
   └── Need login for most data
   └── Success: 20-30%
   └── Effort: Very High

4. FULL BREACH DATA
   └── Free tiers: 5-10 searches
   └── Real data costs money
   └── Success: Limited
   └── Effort: N/A (need $)

5. DIRECT TOR SEARCHES
   └── Slow (30-60 sec/request)
   └── Sites go down constantly
   └── Success: 50%
   └── Effort: Medium
```

## 19.3 What Will FAIL

```
SKIP OR RETHINK THESE:

1. SIGNAL LOOKUP
   └── App only, no API
   └── Can't automate

2. WHATSAPP AT SCALE
   └── Gets banned instantly
   └── Legal gray area

3. REAL-TIME SURVEILLANCE
   └── OSINT is not real-time

4. PAID SERVICES FOR FREE
   └── No workaround exists

5. 100% GUARANTEE
   └── Privacy-conscious targets won't be found
```

---

# 20. CONFIGURATION

## 20.1 File Structure

```
cybertrace/
├── .gitignore          # Ignore secrets
├── .env                # API KEYS (never commit!)
├── .env.example        # Template (commit this)
├── config/
│   ├── config.yaml     # General settings
│   └── sources.yaml    # URLs and endpoints
└── cybertrace/
    └── config.py       # Load configuration
```

## 20.2 .env File (Secrets)

```bash
# .env - NEVER COMMIT THIS FILE

# ========== FREE API KEYS ==========
# Get these from respective websites

VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
GITHUB_TOKEN=your_token_here
EMAILREP_API_KEY=your_key_here
INTELX_API_KEY=your_key_here
HUNTER_API_KEY=your_key_here
NUMVERIFY_API_KEY=your_key_here
TWILIO_SID=your_sid_here
TWILIO_TOKEN=your_token_here
DEHASHED_API_KEY=your_key_here

# ========== TELEGRAM ==========
TELEGRAM_BOT_TOKEN=your_token_here
TELEGRAM_API_ID=your_id_here
TELEGRAM_API_HASH=your_hash_here

# ========== TOR CONFIG ==========
TOR_SOCKS_HOST=127.0.0.1
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
TOR_PASSWORD=your_tor_password

# ========== DATABASE ==========
DATABASE_PATH=./data/cybertrace.db
CACHE_EXPIRY_HOURS=24

# ========== CAPTCHA (Optional) ==========
TWOCAPTCHA_API_KEY=your_key_here
```

## 20.3 .env.example (Template to Commit)

```bash
# .env.example - Copy to .env and fill in your keys

# Free API Keys
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
URLSCAN_API_KEY=
GITHUB_TOKEN=
EMAILREP_API_KEY=
INTELX_API_KEY=

# Telegram
TELEGRAM_BOT_TOKEN=

# Tor
TOR_SOCKS_HOST=127.0.0.1
TOR_SOCKS_PORT=9050

# Database
DATABASE_PATH=./data/cybertrace.db
CACHE_EXPIRY_HOURS=24
```

## 20.4 .gitignore

```gitignore
# SECRETS - NEVER COMMIT
.env
*.env
config/secrets.yaml
config/api_keys.yaml

# DATABASE
*.db
*.sqlite
*.sqlite3
data/*.db

# CACHE
cache/
__pycache__/
*.pyc
*.pyo
.pytest_cache/

# LOGS
logs/
*.log

# REPORTS
reports/
output/
exports/

# PYTHON
venv/
env/
.venv/
*.egg-info/
dist/
build/

# IDE
.idea/
.vscode/
*.swp
*.swo
.DS_Store

# Tor
tor_data/
```

---

# 21. PROGRAM FLOW

## 21.1 Main Search Flow

```
USER: cybertrace search "target"
         │
         ▼
┌─────────────────────┐
│    CLI PARSER       │
│    (Click)          │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  INPUT DETECTOR     │
│  Regex matching     │
│  Returns: type      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  CHECK CACHE        │
│  SQLite lookup      │
│  Fresh? Return      │
└──────────┬──────────┘
           │ Not in cache
           ▼
┌─────────────────────┐
│  MODULE SELECTOR    │
│  Pick module(s)     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  RUN ALL SOURCES    │
│  asyncio.gather()   │
│  Parallel execution │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  AGGREGATE          │
│  Merge results      │
│  Remove duplicates  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  CORRELATE          │
│  Find connections   │
│  Build graph        │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  SAVE TO CACHE      │
│  SQLite insert      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  FORMAT OUTPUT      │
│  JSON/Table/PDF     │
└──────────┬──────────┘
           │
           ▼
        DISPLAY
```

## 21.2 All Layers Search (One Input)

```
INPUT: "username123"
         │
         ├──────────────────────────────────────────┐
         │                                          │
    SURFACE WEB                               DEEP WEB
         │                                          │
    ├── Google: "username123"                 ├── Pastebin search
    ├── GitHub: profile check                 ├── Breach databases
    ├── Twitter: profile check                ├── Archive.org
    ├── Reddit: profile check                 ├── Forum search
    ├── 2500+ sites (Maigret)                 └── Paste sites
         │                                          │
         │                                          │
         └──────────────┬───────────────────────────┘
                        │
                   DARK WEB
                        │
                   ├── Ahmia.fi search
                   ├── DarkSearch.io
                   ├── IntelligenceX
                   ├── Torch (if --tor)
                   └── Dread (if --tor)
                        │
                        ▼
              COMBINED RESULTS
              (All layers merged)
```

---

# 22. CLI STRUCTURE

## 22.1 Commands

```bash
# Auto-detect and search
cybertrace search "target"

# Explicit type
cybertrace search "target" --type email
cybertrace search "target" --type phone
cybertrace search "target" --type username
cybertrace search "target" --type domain
cybertrace search "target" --type btc

# Search options
cybertrace search "target" --deep       # Deep scan (more sources)
cybertrace search "target" --tor        # Include direct Tor
cybertrace search "target" --fast       # Quick scan only
cybertrace search "target" --timeout 60 # Custom timeout

# Output options
cybertrace search "target" --output json
cybertrace search "target" --output table
cybertrace search "target" --output pdf
cybertrace search "target" --output html
cybertrace search "target" --save report.json

# Configuration
cybertrace config --check     # Check API keys status
cybertrace config --show      # Show current config
cybertrace config --test      # Test all sources

# Module-specific commands
cybertrace email "user@example.com"
cybertrace phone "+919876543210"
cybertrace username "hackerman"
cybertrace domain "example.com"
cybertrace btc "1A1zP1..."
cybertrace vehicle "MH12AB1234"
cybertrace image "./photo.jpg"

# Help
cybertrace --help
cybertrace search --help
```

## 22.2 Example Output

```
$ cybertrace search "cryptohacker99"

╔══════════════════════════════════════════════════════════════╗
║                    CYBERTRACE RESULTS                         ║
╠══════════════════════════════════════════════════════════════╣
║  Target: cryptohacker99                                       ║
║  Type: Username (auto-detected)                               ║
║  Time: 2024-12-08 20:30:00                                   ║
║  Duration: 45.2 seconds                                       ║
╚══════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────┐
│ SURFACE WEB                                                   │
├──────────────────────────────────────────────────────────────┤
│ ✅ GitHub        │ Profile found, 15 repos                   │
│ ✅ Reddit        │ Account found, 2 years old               │
│ ✅ Twitter       │ Account found, 450 followers             │
│ ✅ Bitcointalk   │ Member since 2019, 127 posts             │
│ ❌ Instagram     │ Not found                                 │
│ ❌ LinkedIn      │ Not found                                 │
│ ✅ HackerNews    │ Account found, 12 karma                  │
│ ... and 45 more checked                                      │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ DEEP WEB                                                      │
├──────────────────────────────────────────────────────────────┤
│ ✅ Pastebin      │ 2 pastes mention username                │
│ ✅ DeHashed      │ Found in 1 breach (email exposed)        │
│ ✅ Archive.org   │ Old profile snapshot from 2020           │
│ ❌ IntelX        │ No results                                │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ DARK WEB                                                      │
├──────────────────────────────────────────────────────────────┤
│ ✅ Ahmia.fi      │ 3 mentions found                         │
│ ✅ DarkSearch    │ 2 results                                │
│ ⚠️ Torch         │ Skipped (use --tor for direct access)    │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ CORRELATION                                                   │
├──────────────────────────────────────────────────────────────┤
│ Email found:     │ crypto***@gmail.com (from breach)        │
│ Possible name:   │ "Chris H." (from Bitcointalk)            │
│ Location hint:   │ Timezone suggests EST (from post times)  │
│ Bitcoin mention: │ 1A1zP... discussed in forum              │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ SUMMARY                                                       │
├──────────────────────────────────────────────────────────────┤
│ Surface profiles: 12 found                                   │
│ Deep web mentions: 4 found                                   │
│ Dark web mentions: 5 found                                   │
│ Total findings: 21                                           │
│ Confidence: Medium-High                                       │
└──────────────────────────────────────────────────────────────┘

[Next Steps]
├── Search found email: crypto***@gmail.com
├── Search Bitcoin address: 1A1zP...
└── Check Bitcointalk posts for more info

Report saved to: reports/cryptohacker99_2024-12-08.json
```

---

# 23. CODE TEMPLATES

## 23.1 Main Entry Point

```python
# cybertrace/__main__.py

from .cli import cli

if __name__ == '__main__':
    cli()
```

## 23.2 CLI Module

```python
# cybertrace/cli.py

import click
import asyncio
from .config import config
from .detector import detect_input_type
from .modules import get_module
from .output import format_output

@click.group()
@click.version_option(version='1.0.0')
def cli():
    """CyberTrace - Multi-Layer OSINT Investigation Tool"""
    pass

@cli.command()
@click.argument('target')
@click.option('--type', '-t', default='auto', 
              help='Target type (auto, email, phone, username, domain, btc)')
@click.option('--deep', is_flag=True, help='Deep scan with more sources')
@click.option('--tor', is_flag=True, help='Include direct Tor searches')
@click.option('--output', '-o', default='table',
              help='Output format (table, json, pdf, html)')
@click.option('--save', '-s', default=None, help='Save report to file')
@click.option('--timeout', default=30, help='Timeout per source in seconds')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def search(target, type, deep, tor, output, save, timeout, verbose):
    """Search for TARGET across all sources"""
    
    # Detect input type if auto
    if type == 'auto':
        type = detect_input_type(target)
        click.echo(f"[*] Detected type: {type}")
    
    # Get appropriate module
    module = get_module(type)
    if not module:
        click.echo(f"[!] No module for type: {type}")
        return
    
    # Run search
    click.echo(f"[*] Searching for: {target}")
    click.echo(f"[*] Using module: {module.name}")
    click.echo(f"[*] Deep scan: {deep}, Tor: {tor}")
    
    # Async execution
    results = asyncio.run(
        module.search(target, deep=deep, tor=tor, timeout=timeout)
    )
    
    # Format and display
    format_output(results, output)
    
    # Save if requested
    if save:
        with open(save, 'w') as f:
            import json
            json.dump(results, f, indent=2)
        click.echo(f"[+] Saved to: {save}")

@cli.command()
@click.option('--check', is_flag=True, help='Check API key status')
@click.option('--show', is_flag=True, help='Show current configuration')
def config_cmd(check, show):
    """Check configuration status"""
    if check:
        config.check_api_keys()
    if show:
        config.show()

if __name__ == '__main__':
    cli()
```

## 23.3 Base Module Class

```python
# cybertrace/modules/base.py

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import aiohttp
import asyncio

class BaseModule(ABC):
    """Base class for all OSINT modules"""
    
    name: str = "base"
    description: str = "Base module"
    input_types: list = []
    
    def __init__(self, config=None):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    @abstractmethod
    async def search(self, target: str, **options) -> Dict[str, Any]:
        """Run the search - must be implemented by subclasses"""
        pass
    
    def can_handle(self, input_type: str) -> bool:
        """Check if module can handle this input type"""
        return input_type in self.input_types
    
    async def fetch(self, url: str, **kwargs) -> Optional[str]:
        """Fetch URL with error handling"""
        try:
            async with self.session.get(url, **kwargs) as resp:
                if resp.status == 200:
                    return await resp.text()
        except Exception as e:
            pass
        return None
    
    async def fetch_json(self, url: str, **kwargs) -> Optional[dict]:
        """Fetch URL and parse JSON"""
        try:
            async with self.session.get(url, **kwargs) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            pass
        return None
```

## 23.4 Input Detector

```python
# cybertrace/detector.py

import re
from typing import str

PATTERNS = {
    'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'phone_indian': r'^(?:\+91|91|0)?[6789]\d{9}$',
    'phone_intl': r'^\+[1-9]\d{1,14}$',
    'btc_legacy': r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',
    'btc_bech32': r'^bc1[a-z0-9]{39,59}$',
    'ethereum': r'^0x[a-fA-F0-9]{40}$',
    'domain': r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
    'onion': r'^[a-z2-7]{16,56}\.onion$',
    'vehicle_indian': r'^[A-Z]{2}[-.\s]?\d{1,2}[-.\s]?[A-Z]{1,2}[-.\s]?\d{4}$',
    'pan_indian': r'^[A-Z]{5}[0-9]{4}[A-Z]$',
    'gstin': r'^\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}$',
    'ipv4': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
}

# Priority order for detection
DETECTION_ORDER = [
    'email',
    'phone_indian',
    'phone_intl',
    'btc_bech32',
    'btc_legacy',
    'ethereum',
    'onion',
    'gstin',
    'pan_indian',
    'vehicle_indian',
    'ipv4',
    'domain',
]

def detect_input_type(input_string: str) -> str:
    """Detect the type of input string"""
    
    input_string = input_string.strip()
    
    # Check each pattern in priority order
    for input_type in DETECTION_ORDER:
        pattern = PATTERNS.get(input_type)
        if pattern and re.match(pattern, input_string, re.IGNORECASE):
            # Map to module type
            if input_type.startswith('phone'):
                return 'phone'
            if input_type.startswith('btc'):
                return 'bitcoin'
            if input_type in ['pan_indian', 'gstin', 'vehicle_indian']:
                return 'indian'
            return input_type
    
    # Default to username
    return 'username'
```

## 23.5 Config Loader

```python
# cybertrace/config.py

import os
from pathlib import Path
from dotenv import load_dotenv
from dataclasses import dataclass
from typing import Optional, List

load_dotenv()

@dataclass
class APIKeys:
    virustotal: Optional[str] = None
    shodan: Optional[str] = None
    urlscan: Optional[str] = None
    github: Optional[str] = None
    emailrep: Optional[str] = None
    intelx: Optional[str] = None
    hunter: Optional[str] = None
    numverify: Optional[str] = None
    twilio_sid: Optional[str] = None
    twilio_token: Optional[str] = None
    dehashed: Optional[str] = None
    telegram_bot: Optional[str] = None
    twocaptcha: Optional[str] = None
    
    @classmethod
    def from_env(cls):
        return cls(
            virustotal=os.getenv('VIRUSTOTAL_API_KEY'),
            shodan=os.getenv('SHODAN_API_KEY'),
            urlscan=os.getenv('URLSCAN_API_KEY'),
            github=os.getenv('GITHUB_TOKEN'),
            emailrep=os.getenv('EMAILREP_API_KEY'),
            intelx=os.getenv('INTELX_API_KEY'),
            hunter=os.getenv('HUNTER_API_KEY'),
            numverify=os.getenv('NUMVERIFY_API_KEY'),
            twilio_sid=os.getenv('TWILIO_SID'),
            twilio_token=os.getenv('TWILIO_TOKEN'),
            dehashed=os.getenv('DEHASHED_API_KEY'),
            telegram_bot=os.getenv('TELEGRAM_BOT_TOKEN'),
            twocaptcha=os.getenv('TWOCAPTCHA_API_KEY'),
        )
    
    def has_key(self, service: str) -> bool:
        key = getattr(self, service, None)
        return key is not None and key.strip() != ''
    
    def has_api_keys(self, services: List[str]) -> bool:
        return all(self.has_key(s) for s in services)

@dataclass
class TorConfig:
    socks_host: str = '127.0.0.1'
    socks_port: int = 9050
    control_port: int = 9051
    password: Optional[str] = None
    
    @classmethod
    def from_env(cls):
        return cls(
            socks_host=os.getenv('TOR_SOCKS_HOST', '127.0.0.1'),
            socks_port=int(os.getenv('TOR_SOCKS_PORT', 9050)),
            control_port=int(os.getenv('TOR_CONTROL_PORT', 9051)),
            password=os.getenv('TOR_PASSWORD'),
        )
    
    @property
    def proxy_url(self) -> str:
        return f"socks5h://{self.socks_host}:{self.socks_port}"

class Config:
    def __init__(self):
        self.api_keys = APIKeys.from_env()
        self.tor = TorConfig.from_env()
        self.database_path = os.getenv('DATABASE_PATH', './data/cybertrace.db')
        self.cache_expiry = int(os.getenv('CACHE_EXPIRY_HOURS', 24))
    
    def check_api_keys(self):
        """Print status of all API keys"""
        print("\n=== API Key Status ===\n")
        keys = [
            ('VirusTotal', self.api_keys.has_key('virustotal')),
            ('Shodan', self.api_keys.has_key('shodan')),
            ('URLScan', self.api_keys.has_key('urlscan')),
            ('GitHub', self.api_keys.has_key('github')),
            ('EmailRep', self.api_keys.has_key('emailrep')),
            ('IntelX', self.api_keys.has_key('intelx')),
            ('Hunter', self.api_keys.has_key('hunter')),
            ('NumVerify', self.api_keys.has_key('numverify')),
            ('Twilio', self.api_keys.has_key('twilio_sid')),
            ('DeHashed', self.api_keys.has_key('dehashed')),
            ('Telegram', self.api_keys.has_key('telegram_bot')),
            ('2Captcha', self.api_keys.has_key('twocaptcha')),
        ]
        for name, status in keys:
            icon = "✅" if status else "❌"
            print(f"  {icon} {name}")
        print()

config = Config()
```

---

# 24. LEGAL CONSIDERATIONS

## 24.1 What's Legal (Your Tool Does This)

```
✅ LEGAL:
├── Searching public websites
├── Querying public APIs
├── Reading public blockchain
├── Checking public records
├── Looking at public profiles
├── DNS/WHOIS lookups
├── Searching paste sites
├── Using Tor to browse
├── Aggregating public info
└── Scraping public pages (civil issue at worst)
```

## 24.2 What's Illegal (Your Tool Does NOT Do This)

```
❌ ILLEGAL:
├── Breaking into systems
├── Bypassing authentication
├── Stealing credentials
├── Accessing private databases
├── Intercepting communications
├── Deploying malware
├── Using leaked passwords to login
└── Unauthorized access of any kind
```

## 24.3 IT Act 2000 (India) Compliance

```
SECTION 43: Penalty for unauthorized access
└── Your tool: Does NOT access unauthorized systems

SECTION 66: Computer-related offences
└── Your tool: No hacking, only public data

SECTION 66F: Cyber terrorism
└── Your tool: Not applicable

SECTION 72: Breach of confidentiality
└── Your tool: Only collects public data

STATUS: YOUR TOOL IS LEGAL
REASON: OSINT = Open Source Intelligence = Public Data
```

---

# 25. PROJECT TIMELINE

## 25.1 Realistic Timeline

```
PHASE 1: MVP (Week 1-4)                    STATUS
─────────────────────────────────────────────────
CLI Framework                              ❌
Input Detector                             ❌
Username Module (Maigret)                  ❌
Domain Module (WHOIS, DNS, crt.sh)         ❌
Bitcoin Module (blockchain.info)           ❌
Basic Output                               ❌
─────────────────────────────────────────────────
MVP DELIVERABLE: Working tool with 3 modules

PHASE 2: Core (Week 5-8)                   STATUS
─────────────────────────────────────────────────
Email Module (Gravatar, Holehe)            ❌
Dark Web Module (Ahmia, clearnet)          ❌
Google Dorking                             ❌
Breach Check (HIBP scrape)                 ❌
Cache System                               ❌
─────────────────────────────────────────────────

PHASE 3: Indian (Week 9-12)                STATUS
─────────────────────────────────────────────────
MCA Integration                            ❌
GST Integration                            ❌
Vahan (with captcha)                       ❌
eCourts                                    ❌
─────────────────────────────────────────────────

PHASE 4: Advanced (Week 13-16)             STATUS
─────────────────────────────────────────────────
Phone Module (challenging)                 ❌
Tor Direct Integration                     ❌
Correlation Engine                         ❌
PDF Reports                                ❌
─────────────────────────────────────────────────

TOTAL: 16 weeks for full implementation
```

---

# 26. FILE STRUCTURE

```
cybertrace/
├── .gitignore
├── .env                    # Secrets (never commit)
├── .env.example            # Template
├── README.md
├── requirements.txt
├── setup.py
├── LICENSE
│
├── config/
│   ├── config.yaml
│   └── sources.yaml
│
├── cybertrace/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── config.py
│   ├── detector.py
│   ├── output.py
│   │
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── email_module.py
│   │   ├── phone_module.py
│   │   ├── username_module.py
│   │   ├── domain_module.py
│   │   ├── bitcoin_module.py
│   │   ├── indian_module.py
│   │   ├── darkweb_module.py
│   │   ├── social_module.py
│   │   ├── image_module.py
│   │   ├── geoint_module.py
│   │   ├── forum_module.py
│   │   ├── breach_module.py
│   │   ├── telegram_module.py
│   │   └── correlation.py
│   │
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── http.py
│   │   ├── tor.py
│   │   ├── cache.py
│   │   ├── ratelimit.py
│   │   └── captcha.py
│   │
│   └── data/
│       ├── sites.json
│       └── patterns.json
│
├── data/
│   ├── cybertrace.db
│   └── onion_cache.json
│
├── tests/
│   ├── __init__.py
│   ├── test_detector.py
│   └── test_modules.py
│
├── docs/
│   └── ...
│
└── reports/
    └── ...
```

---

# 27. INSTALLATION GUIDE

## 27.1 Requirements

```
OS: Linux (Ubuntu 20.04+), macOS, or Windows WSL
Python: 3.8+
RAM: 4GB minimum
Storage: 1GB free
Network: Internet
Optional: Tor for dark web
```

## 27.2 Quick Start

```bash
# Clone
git clone https://github.com/anubhavmohandas/cybertrace.git
cd cybertrace

# Virtual environment
python3 -m venv venv
source venv/bin/activate

# Install
pip install -r requirements.txt

# Configure
cp .env.example .env
nano .env  # Add API keys

# Optional: Install Tor
sudo apt install tor
sudo service tor start

# Run
python -m cybertrace search "target"
```

## 27.3 requirements.txt

```
# Core
click>=8.0.0
aiohttp>=3.8.0
requests>=2.28.0
requests[socks]
beautifulsoup4>=4.11.0
lxml>=4.9.0

# Database
sqlalchemy>=2.0.0

# Tor
stem>=1.8.0
PySocks>=1.7.0

# DNS/Network
dnspython>=2.2.0
python-whois>=0.8.0

# Config
python-dotenv>=1.0.0
PyYAML>=6.0

# Output
tabulate>=0.9.0
rich>=13.0.0

# Analysis
pandas>=2.0.0
networkx>=3.0

# Image (optional)
Pillow>=10.0.0

# Phone (optional)
phonenumbers>=8.13.0

# Testing
pytest>=7.0.0
pytest-asyncio>=0.21.0
```

---

# 28. BUILD ORDER PRIORITY

## 28.1 What to Build First

```
PRIORITY 1: Core Foundation
──────────────────────────────────────────────
1. CLI Framework (Click)
2. Input Detector (Regex)
3. Username Module (Maigret integration)
4. Domain Module (WHOIS, DNS)
5. Bitcoin Module (blockchain.info)
6. Basic Output (Table)

TIME: 2-3 weeks
RESULT: Working tool with core modules

PRIORITY 2: Essential Features
──────────────────────────────────────────────
7. Email Module (Gravatar, Holehe)
8. Dark Web Module (Ahmia clearnet)
9. Google Dorking
10. Cache System

TIME: 2 weeks
RESULT: More comprehensive tool

PRIORITY 3: Indian Sources
──────────────────────────────────────────────
11. MCA Integration
12. GST Integration
13. Indian Kanoon

TIME: 2 weeks
RESULT: India-specific capabilities

PRIORITY 4: Nice to have
──────────────────────────────────────────────
14. Phone Module (partial)
15. Vahan with captcha
16. Correlation Engine
17. PDF Reports
18. More social media

TIME: 4+ weeks
RESULT: Full-featured tool
```

## 28.2 Minimum Viable Product

```
FOR A WORKING TOOL, YOU NEED AT MINIMUM:

1. Working CLI
2. Username search (Maigret)
3. Bitcoin lookup
4. Domain lookup
5. One Indian source (MCA)
6. Ahmia search

THIS GIVES YOU A FUNCTIONAL OSINT TOOL.

Don't try to build everything at once.
Build module by module, test as you go.
```

---

# APPENDIX A: COMPLETE SOURCE URLS

## A.1 Phone Sources

```
# Easy (No Auth)
https://freecarrierlookup.com/
https://www.carrierlookup.com/
https://epieos.com/
https://castrickclues.com/
https://www.numlookup.com/
https://osint.rocks/
https://checkleaked.cc/
https://haveibeenzuckered.com/

# APIs (Free tier)
https://numverify.com/
https://www.twilio.com/
https://dehashed.com/

# Tools
https://github.com/sundowndev/phoneinfoga
https://github.com/megadose/ignorant
https://github.com/BobTheShoplifter/Detectdee
```

## A.2 Email Sources

```
https://gravatar.com/avatar/{md5}?d=404
https://epieos.com/
https://haveibeenpwned.com/
https://emailrep.io/
https://hunter.io/
https://keys.openpgp.org/
https://api.github.com/search/commits
```

## A.3 Domain Sources

```
# WHOIS/DNS
python-whois library
dnspython library

# Certificates
https://crt.sh/?q={domain}

# Subdomains
https://dnsdumpster.com/
https://rapiddns.io/
https://securitytrails.com/

# Analysis
https://www.virustotal.com/
https://urlscan.io/
https://www.shodan.io/
```

## A.4 Dark Web Sources

```
# Clearnet (No Tor)
https://ahmia.fi/search/?q={query}
https://darksearch.io/api/search?query={query}
https://intelx.io/
https://dark.fail/

# Directories
https://onion.live/
https://tor.taxi/
https://darkwebdaily.live/
```

## A.5 Indian Sources

```
# Government
https://parivahan.gov.in/rcdlstatus/
https://www.mca.gov.in/
https://services.gst.gov.in/
https://ecourts.gov.in/
https://indiankanoon.org/

# Business
https://www.zaubacorp.com/
https://www.tofler.in/
https://www.justdial.com/
```

---

# APPENDIX B: QUICK REFERENCE

## B.1 Input Detection Cheat Sheet

```
INPUT                           → TYPE          → MODULE
────────────────────────────────────────────────────────
user@example.com                → email         → Email
+919876543210                   → phone         → Phone
hackerman123                    → username      → Username
example.com                     → domain        → Domain
1A1zP1eP5QGe...                → bitcoin       → Bitcoin
0x742d35Cc6634...              → ethereum      → Bitcoin
abc123.onion                    → onion         → Dark Web
MH12AB1234                      → vehicle       → Indian
ABCDE1234F                      → pan           → Indian
22AAAAA0000A1Z5                → gst           → Indian
192.168.1.1                     → ip            → Domain
```

## B.2 Module Success Rates

```
MODULE          WORKS?    RATE    EFFORT
──────────────────────────────────────────
Username        ✅        90%     Low
Bitcoin         ✅        95%     Low
Domain          ✅        85%     Low
Email (basic)   ✅        70%     Low
Dark (clearnet) ✅        70%     Low
Indian (easy)   ⚠️        60%     Medium
Phone           ⚠️        40%     High
Social Media    ⚠️        40%     High
Dark (Tor)      ⚠️        50%     Medium
Breach          ⚠️        30%     N/A (paid)
```

---

# END OF DOCUMENT

```
════════════════════════════════════════════════════════════════
                    CYBERTRACE FINAL BLUEPRINT
════════════════════════════════════════════════════════════════

Document:     CYBERTRACE_FINAL_BLUEPRINT.md
Version:      2.0 (Final)
Date:         December 2024
Author:       Anubhav Mohandas
Purpose:      Complete reference for building CyberTrace

CONTENTS:
├── 28 Major Sections
├── 2 Appendices
├── 200+ Data Sources
├── 82 Dark Web Tools
├── 27 Phone Sources
├── 15 Search Engines
├── 12 Google Dork Operators
├── Complete Code Templates
├── Full Architecture
├── Indian OSINT Detail
├── Realistic Expectations
└── Build Priority Order

STATUS: BLUEPRINT COMPLETE
NEXT: START CODING

════════════════════════════════════════════════════════════════
```
