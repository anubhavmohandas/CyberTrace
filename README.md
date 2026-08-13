# CyberTrace

Multi-Layer OSINT Investigation Tool - Search across Surface Web, Deep Web, and Dark Web simultaneously.

## Features

- **Auto-detection** of input type (email, phone, username, domain, Bitcoin, Indian IDs)
- **95% reliability** for blockchain analysis (public data)
- **90% reliability** for username enumeration (2500+ sites via Maigret)
- **85% reliability** for domain intelligence (WHOIS, DNS, crt.sh)
- **70% reliability** for email OSINT and dark web search
- Indian-specific databases (MCA, GST, eCourts, Indian Kanoon)

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/anubhavmohandas/cybertrace.git
cd cybertrace

./setup.sh          # macOS / Linux
setup.bat           # Windows
```

The script creates the venv, installs CyberTrace with maigret, sherlock and
holehe bundled in, seeds `.env` from `.env.example`, and verifies each tool.
Re-run it any time; it's idempotent.

Then:

```bash
source venv/bin/activate      # Windows: venv\Scripts\activate
cybertrace search "user@example.com"
```

`exiftool` is the one thing pip can't supply — install it separately
(`brew install exiftool` / `apt install libimage-exiftool-perl`) for full EXIF
extraction. Without it the image module falls back to Pillow.

## Quick Start

```bash
# Auto-detect input type and search
cybertrace search "user@example.com"

# Search specific type
cybertrace search "hackerman123" --type username

# Output as JSON
cybertrace search "example.com" --output json

# Save results to file
cybertrace search "1A1zP1..." --save report.json

# Rich colored output
cybertrace search "MH12AB1234" --output rich
```

## Modules

| Module | Success Rate | Description |
|--------|--------------|-------------|
| bitcoin | 95% | Blockchain analysis (BTC, ETH) |
| username | 90% | Username enumeration (3000+ sites) |
| domain | 85% | WHOIS, DNS, SSL, subdomains |
| email | 70% | Gravatar, Holehe, GitHub commits |
| darkweb | 70% | Ahmia, DarkSearch (clearnet) |
| indian | 60-70% | MCA, GST, eCourts, vehicle lookup |

## Configuration

Create `.env` file for API keys (optional, enhances results):

```bash
cp .env.example .env
# Edit .env with your API keys
```

`setup.sh` / `setup.bat` create `.env` for you on first run.

Free API keys that improve results:
- VirusTotal (500/day): https://virustotal.com
- Shodan (100/month): https://shodan.io
- URLScan (5000/day): https://urlscan.io
- GitHub (5000/hour): https://github.com/settings/tokens
- EmailRep (100/day): https://emailrep.io

Tunable settings (all optional, set in `.env`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `REQUEST_TIMEOUT` | 30 | Per-HTTP-request timeout, seconds |
| `TOOL_TIMEOUT` | 300 | Budget for maigret/sherlock/holehe subprocesses |
| `MAX_CONCURRENT` | 10 | Concurrent request cap |
| `CACHE_TTL_HOURS` | 24 | Cache lifetime |

Maigret sweeping 3000+ sites from one IP will trip bot protection and captchas
on a share of them — that's rate limiting, not a bug. A proxy or `TOR_ENABLED=true`
improves coverage.

## CLI Commands

```bash
# Main search command
cybertrace search TARGET [OPTIONS]

# Shortcut commands
cybertrace email EMAIL
cybertrace username USERNAME
cybertrace domain DOMAIN
cybertrace btc ADDRESS
cybertrace indian TARGET

# Configuration
cybertrace config --check    # Check API key status
cybertrace modules           # List available modules
```

## Input Types

CyberTrace auto-detects these input types:

| Input | Example | Module |
|-------|---------|--------|
| Email | user@example.com | email |
| Phone (India) | +919876543210 | phone |
| Username | hackerman123 | username |
| Domain | example.com | domain |
| Bitcoin | 1A1zP1eP5Q... | bitcoin |
| Ethereum | 0x742d35Cc... | bitcoin |
| Vehicle (India) | MH12AB1234 | indian |
| PAN (India) | ABCDE1234F | indian |
| GSTIN | 22AAAAA0000A1Z5 | indian |

## Legal Notice

CyberTrace only accesses **publicly available** information. It does not:
- Break into systems
- Bypass authentication
- Access private databases
- Intercept communications

Use responsibly and ethically for legitimate OSINT research.

## Documentation

For complete technical documentation including:
- Architecture overview
- Module API reference
- Development guide
- Troubleshooting

See [docs/TECHNICAL_DOCUMENTATION.md](docs/TECHNICAL_DOCUMENTATION.md)

## Testing

```bash
# Run test suite
pytest tests/ -v

# Quick test
python -m cybertrace search "MH12AB1234" --output json
```

## License

MIT License - see [LICENSE](LICENSE) file
