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

```bash
# Clone repository
git clone https://github.com/anubhavmohandas/cybertrace.git
cd cybertrace

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install CyberTrace
pip install -e .

# Install optional OSINT tools
pip install maigret sherlock-project holehe
```

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

Free API keys that improve results:
- VirusTotal (500/day): https://virustotal.com
- Shodan (100/month): https://shodan.io
- URLScan (5000/day): https://urlscan.io
- GitHub (5000/hour): https://github.com/settings/tokens
- EmailRep (100/day): https://emailrep.io

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
