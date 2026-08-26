# CyberTrace

Multi-Layer OSINT Investigation Tool — search across Surface Web, Deep Web and
Dark Web, then correlate what comes back into auditable operator attribution.

Two things live here:

1. **Investigation** — point it at an email, username, domain, wallet or
   `.onion` and it sweeps the sources that cover that type.
2. **Attribution** — fold several dark web investigations into one evidence
   graph and rank who is behind which sites, with every claim walkable back to
   a hashed capture and every objection to it stated alongside.

## Features

- **Auto-detection** of input type (email, phone, username, domain, Bitcoin, Indian IDs)
- **Live `.onion` collection over Tor** with a bounded same-host crawl, page
  hashes and DOM fingerprints
- **Evidence store with provenance** — SQLite; every relationship resolves to
  the observations and hashed snapshots supporting it
- **Correlation engine** — cross-market operator, infrastructure and IP
  candidates, successor hypotheses, and the contradictions that constrain them
- **Ground-truth evaluation** — a labeled corpus and a harness that scores the
  engine on precision, recall and ecosystem leakage
- **Monitoring** — re-check a case, detect sites going dark, diff the candidates
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

## Dark web operator attribution

The part that answers "who runs these sites", rather than "what is on them".

```bash
# 1. Collect. Needs a running Tor SOCKS proxy (127.0.0.1:9050).
cybertrace search "abcd...onion" --save runs/raw/market-a.json
cybertrace search "efgh...onion" --save runs/raw/market-b.json

# 2. Correlate into one evidence store, and render both views.
cybertrace correlate runs/raw/*.json --db case.db --html graph.html --dossier case.html

# 3. Come back later: what changed, what went dark, what moved.
cybertrace watch --db case.db --discover --dossier case.html
```

`case.html` is the investigator view — candidates with their evidence chain,
timeline, contradictions and next steps. `graph.html` is the entity graph.
Both are standalone files with no remote assets, so opening one on an evidence
machine announces nothing to anybody.

What the engine will and will not say:

- A shared PGP key is **not** treated as shared control on its own — a copycat
  can republish a victim's key, so the clone guard weighs page structure and
  temporal precedence first
- A key the site actually **signed** with counts differently from one it merely
  displayed
- Artifacts common across the corpus (a mail platform's own domain, its
  documentation mailbox) are discounted automatically — running the same
  software is not being the same operator
- Sharing something you *link to* is not evidence; sharing something you
  *control* is
- Succession requires the predecessor to have been **observed dark**; two sites
  live at once get `LINKED_TO`, never `SUCCESSOR_OF`
- Scores rank candidates. They are not probabilities — see
  [section 16.6](docs/TECHNICAL_DOCUMENTATION.md#166-what-the-scores-do-not-mean)

### Evaluating it

`corpus/labels.toml` labels a live corpus with each target's operator and
platform, each citing evidence outside the tool's own output. The harness
scores the engine against it:

```bash
python tools/eval_corpus.py runs/raw/*.json --pairs
```

It reports operator precision and recall, **ecosystem leakage** (same-platform
pairs wrongly called same-operator), false attribution, and the pairs it could
not evaluate because a target was dark. It exits non-zero on any false
attribution, so a change to the scoring model can be gated on it.

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

# Attribution
cybertrace correlate FILES... [--db case.db] [--html graph.html] [--dossier case.html]
cybertrace watch --db case.db [--target ONION] [--discover] [--dossier case.html]
# run continuously via cron, not a built-in scheduler:
#   0 */6 * * * cybertrace watch --db case.db -o json >> watch.log
cybertrace feedback CANDIDATE_ID --db case.db --outcome confirmed|rejected|benign|malicious|unknown [--note TEXT] [--analyst NAME]

# Shortcut commands
cybertrace email EMAIL
cybertrace username USERNAME
cybertrace domain DOMAIN
cybertrace btc ADDRESS
cybertrace ip ADDRESS
cybertrace phone NUMBER
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
# Unit + integration suite (offline; no network, no Tor)
pytest tests/ -q

# Extractor precision over saved runs: what validated, what was refused
python tools/audit_corpus.py runs/raw/*.json --values

# Correlation scored against the labeled corpus
python tools/eval_corpus.py runs/raw/*.json --pairs
```

The suite is offline by design — every correlation scenario is seeded through
the same `ingest()` path a real crawl takes. It does not replace the corpus
runs: tests prove the logic behaves, the corpus proves it behaves *on real
sites*, and each has caught failures the other could not.

## License

MIT License - see [LICENSE](LICENSE) file
