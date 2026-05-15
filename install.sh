#!/bin/bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[\u2713]${NC} $1"; }
fail() { echo -e "${RED}[\u2717]${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}[~]${NC} $1"; }

echo ""
echo "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557"
echo "\u2551       BountyGrimoire \u2014 Installer         \u2551"
echo "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d"
echo ""

# -- Dependencies --------------------------------------------------------------

info "Checking dependencies..."

command -v node >/dev/null 2>&1    && ok "Node.js $(node --version)"   || fail "Node.js missing : https://nodejs.org"
command -v python3 >/dev/null 2>&1 && ok "Python $(python3 --version)" || fail "Python3 missing"
command -v curl >/dev/null 2>&1    && ok "curl"                        || fail "curl missing"
command -v git >/dev/null 2>&1     && ok "git"                         || fail "git missing"

# Detect AI runtime: prefer opencode, fall back to claude
if command -v opencode >/dev/null 2>&1; then
    RUNTIME="opencode"
    ok "OpenCode $(opencode --version 2>/dev/null | head -1 || echo detected)"
elif command -v claude >/dev/null 2>&1; then
    RUNTIME="claude"
    ok "Claude Code $(claude --version 2>/dev/null | head -1) (legacy)"
    info "Consider switching to OpenCode: https://opencode.ai"
else
    fail "No AI runtime found. Install OpenCode (https://opencode.ai) or Claude Code (npm install -g @anthropic-ai/claude-code)"
fi

echo ""

# -- Python dependencies -------------------------------------------------------

info "Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv && ok ".venv created"
else
    ok ".venv already exists"
fi
# shellcheck source=/dev/null
source .venv/bin/activate
pip install anthropic openai datasets --quiet && ok "anthropic + openai + datasets installed"
info "Virtual environment activated -- run 'source .venv/bin/activate' before using generate-skill.py"

echo ""

# -- Directory structure -------------------------------------------------------

info "Setting up directory structure..."
mkdir -p .claude/skills .commands sessions memory
ok "Core directories created"

# -- OpenCode skill layout -----------------------------------------------------

if [ "$RUNTIME" = "opencode" ]; then
    info "Setting up OpenCode skill layout (.agent/skills/)..."
    if [ -d ".claude/skills" ]; then
        for skill_file in .claude/skills/*.md; do
            [ -f "$skill_file" ] || continue
            skill_name=$(basename "$skill_file" .md)
            mkdir -p ".agent/skills/${skill_name}"
            cp "$skill_file" ".agent/skills/${skill_name}/SKILL.md"
        done
        ok "Skills mirrored to .agent/skills/<name>/SKILL.md"
    else
        info ".claude/skills/ not populated yet -- skills will be mirrored after generation"
    fi
fi

# -- Skills --------------------------------------------------------------------

info "Generating initial skills..."

if [ -f "generate-skill.py" ] && [ -f ".env" ] && (grep -q "ANTHROPIC_API_KEY=sk-" .env 2>/dev/null || grep -q "OPENAI_API_KEY=" .env 2>/dev/null); then
    python3 generate-skill.py --all --max 20

    # After generation, re-mirror into .agent/skills/ for OpenCode
    if [ "$RUNTIME" = "opencode" ] && [ -d ".claude/skills" ]; then
        for skill_file in .claude/skills/*.md; do
            [ -f "$skill_file" ] || continue
            skill_name=$(basename "$skill_file" .md)
            mkdir -p ".agent/skills/${skill_name}"
            cp "$skill_file" ".agent/skills/${skill_name}/SKILL.md"
        done
        ok "Skills mirrored to .agent/skills/ after generation"
    fi

    ok "Skills generated"
else
    info "Skills not generated -- fill in an API key in .env then run:"
    echo "     python3 generate-skill.py --all --max 20"
    if [ "$RUNTIME" = "opencode" ]; then
        echo "     Then run: ./mirror-skills.sh"
    fi
fi

echo ""

# -- Environment ---------------------------------------------------------------

if [ ! -f ".env" ]; then
    cp .env.example .env
    info ".env created -- fill in your API key (see README)"
else
    ok ".env already present"
fi

# -- mirror-skills helper (OpenCode only) --------------------------------------

if [ "$RUNTIME" = "opencode" ]; then
    chmod +x mirror-skills.sh 2>/dev/null || true
    ok "mirror-skills.sh ready -- run it after re-generating skills"
fi

echo ""
echo "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557"
echo "\u2551          Installation complete!      \u2551"
echo "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d"
echo ""

if [ "$RUNTIME" = "opencode" ]; then
    echo "  Start BountyGrimoire with OpenCode:"
    echo ""
    echo "    cd $(pwd)"
    echo "    source .venv/bin/activate"
    echo "    opencode"
    echo ""
    echo "  Available workflows (prompt OpenCode with these):"
    echo ""
    echo "    Run the load-program workflow for <ywh-slug>"
    echo "    Run the load-program-h1 workflow for <h1-handle>"
    echo "    Run the hunt workflow for <target>"
    echo "    Run the hunt-auth workflow for <target>"
    echo "    Run the report workflow"
    echo "    Run the session-list workflow"
    echo "    Run the session-save workflow for <name>"
    echo "    Run the session-load workflow for <name>"
    echo ""
    echo "  Tip: OpenCode reads AGENTS.md at startup."
    echo "       Workflows in .commands/ | Skills in .agent/skills/<name>/SKILL.md"
else
    echo "  Start BountyGrimoire with Claude Code:"
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
fi
echo ""
