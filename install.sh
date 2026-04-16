#!/bin/bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}[~]${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       BountyGrimoire — Installer         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Dependencies ──────────────────────────────────────────────────────────────

info "Checking dependencies..."

command -v node >/dev/null 2>&1    && ok "Node.js $(node --version)" || fail "Node.js missing : https://nodejs.org"
command -v claude >/dev/null 2>&1  && ok "Claude Code $(claude --version 2>/dev/null | head -1)" || fail "Claude Code missing : npm install -g @anthropic-ai/claude-code"
command -v python3 >/dev/null 2>&1 && ok "Python $(python3 --version)" || fail "Python3 missing"
command -v curl >/dev/null 2>&1    && ok "curl" || fail "curl missing"
command -v git >/dev/null 2>&1     && ok "git"  || fail "git missing"

echo ""

# ── Python dependencies ───────────────────────────────────────────────────────

info "Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv && ok ".venv created"
else
    ok ".venv already exists"
fi
# shellcheck source=/dev/null
source .venv/bin/activate
pip install anthropic openai datasets --quiet && ok "anthropic + openai + datasets installed"
info "Virtual environment activated — run 'source .venv/bin/activate' before using generate-skill.py"

echo ""

# ── Directory structure ───────────────────────────────────────────────────────

info "Setting up directory structure..."
mkdir -p .claude/skills .claude/commands sessions
ok "Directories created"

# ── Skills ────────────────────────────────────────────────────────────────────

info "Generating initial skills..."

if [ -f "generate-skill.py" ] && [ -f ".env" ] && (grep -q "ANTHROPIC_API_KEY=sk-" .env 2>/dev/null || grep -q "OPENAI_API_KEY=" .env 2>/dev/null); then
    python3 generate-skill.py --all --max 20
    ok "Skills generated"
else
    info "Skills not generated — fill in an API key in .env then run:"
    echo "     python3 generate-skill.py --all --max 20"
fi

echo ""

# ── Environment ───────────────────────────────────────────────────────────────

if [ ! -f ".env" ]; then
    cp .env.example .env
    info ".env created — fill in your API key (see README)"
else
    ok ".env already present"
fi

echo ""
echo "╔══════════════════════════════════════╗"
echo "║          Installation complete!      ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "  Start BountyGrimoire:"
echo ""
echo "    cd $(pwd)"
echo "    claude --dangerously-skip-permissions"
echo ""
echo "  Inside Claude Code:"
echo ""
echo "    /load-program <ywh-slug>      # load a YesWeHack program"
echo "    /load-program-h1 <h1-handle>  # load a HackerOne program"
echo "    /session-list                 # list saved sessions"
echo "    /report                       # generate a bug bounty report"
echo ""
