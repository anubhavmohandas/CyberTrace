#!/usr/bin/env bash
# CyberTrace setup — creates venv, installs everything, verifies. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")"

# Colors only when stdout is a terminal, so piping to a log stays clean.
if [ -t 1 ]; then
    R=$'\033[0m'; B=$'\033[1m'; DIM=$'\033[2m'
    CYAN=$'\033[36m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
    AMBER=$'\033[38;5;214m'   # 256-colour amber; degrades to default if unsupported
else
    R=''; B=''; DIM=''; CYAN=''; GREEN=''; YELLOW=''; RED=''; AMBER=''
fi

step() { echo "${CYAN}${B}▸${R} ${B}$1${R}"; }
ok()   { echo "  ${GREEN}✅ $1${R}"; }
warn() { echo "  ${YELLOW}⚠️  $1${R}"; }
die()  { echo "  ${RED}❌ $1${R}" >&2; exit 1; }

cat <<EOF
${CYAN}${B}
   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗██████╗  █████╗  ██████╗███████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝   ██║   ██████╔╝███████║██║     █████╗
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗   ██║   ██╔══██╗██╔══██║██║     ██╔══╝
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗███████╗
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
${R}${DIM}  🔎 Multi-Layer OSINT Investigation Tool  ·  Surface · Deep · Dark${R}

${AMBER}${B}  ────────────────⟡  A N U B H A V   M O H A N D A S  ⟡────────────────${R}

EOF

step "🐍 Checking Python"
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || die "$PY not found. Install Python 3.10 or newer."
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' \
    || die "Python 3.10+ required, found $("$PY" -V 2>&1)"
ok "$("$PY" -V 2>&1)"

step "📦 Setting up virtual environment"
if [ -d venv ]; then
    ok "venv already exists — reusing"
else
    "$PY" -m venv venv || die "Could not create venv"
    ok "Created ./venv"
fi

step "⬇️  Installing CyberTrace + OSINT tools"
echo "${DIM}     maigret · sherlock · holehe · phonenumbers · Tor/SOCKS support${R}"
echo "${DIM}     (first run pulls ~200MB, grab a coffee ☕)${R}"
./venv/bin/python -m pip install --upgrade --quiet pip || die "pip upgrade failed"
./venv/bin/pip install --quiet -e '.[dev]' || die "Install failed — see pip output above"
ok "Dependencies installed"

step "🔑 Configuring environment"
if [ -f .env ]; then
    ok ".env already present — left untouched"
else
    cp .env.example .env
    ok "Created .env from .env.example"
    echo "${DIM}     All API keys are optional; CyberTrace degrades gracefully without them.${R}"
fi

step "🧪 Verifying installation"
FAILED=0
for t in cybertrace maigret sherlock holehe; do
    if [ -x "venv/bin/$t" ]; then ok "$t"; else echo "  ${RED}❌ $t missing${R}"; FAILED=1; fi
done
command -v exiftool >/dev/null 2>&1 \
    && ok "exiftool (full EXIF extraction)" \
    || warn "exiftool not found — image module falls back to Pillow (brew install exiftool)"

[ "$FAILED" -eq 0 ] || die "Some tools failed to install. Re-run ./setup.sh"

cat <<EOF

${GREEN}${B}  ✅ Setup complete!${R}

${B}  🚀 Start investigating:${R}

     ${CYAN}source venv/bin/activate${R}
     ${CYAN}cybertrace search "user@example.com"${R}

${DIM}  Try also:  cybertrace search "torvalds" -t username
             cybertrace search "example.com" -o rich
             cybertrace modules${R}

${AMBER}${B}  ────────────────⟡  A N U B H A V   M O H A N D A S  ⟡────────────────${R}
${DIM}          🛡️  Use responsibly · authorized targets only${R}
${B}              💛  I   L O V E   Y O U U U U U  💛${R}

EOF
