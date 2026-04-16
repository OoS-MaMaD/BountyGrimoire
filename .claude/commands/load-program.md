---
description: Load a YesWeHack program rules and scopes. Usage: /load-program <slug>
---

# Load YesWeHack Program

Load the rules, scopes and guidelines of a YesWeHack program into CLAUDE.md.

## Instructions

Given the program slug in $ARGUMENTS:

### Step 1 — Fetch program data

```bash
curl -s -A "BountyGrimoire/1.0" "https://api.yeswehack.com/programs/$ARGUMENTS"
```

If a YWH_PAT environment variable is set, add the header:
```bash
curl -s -A "BountyGrimoire/1.0" -H "X-AUTH-TOKEN: $YWH_PAT" "https://api.yeswehack.com/programs/$ARGUMENTS"
```

### Step 2 — Parse and display

Extract from the JSON response:
- `title` → program name
- `scopes[]` → list of targets with `scope`, `scope_type`, `eligible_for_bounty`
- `guidelines` → program rules (strip HTML tags)

Display a clean summary:
- ✅ IN scope targets (eligible_for_bounty: true)
- ❌ OUT of scope targets (eligible_for_bounty: false)
- Key rules from guidelines

### Step 3 — Write CLAUDE.md

Write a CLAUDE.md file at the root of the project with:

```
# Security Agent — <program name>

YesWeHack: https://yeswehack.com/programs/<slug>

## ⚠️ Program Rules (MANDATORY)
<extracted rules, max 2000 chars>

## ✅ IN Scope — Authorized targets
<list of in-scope targets with type>

## ❌ OUT of Scope — NEVER test these
<list of out-of-scope targets>

## Proxy
All curl requests MUST use: -x http://localhost:8088 --proxy-insecure

## Workflow
1. Always verify the target is IN scope before any request
2. NEVER test OUT of scope targets
3. Use curl with proxy AND user-agent for ALL requests
4. Use available skills to analyze findings
```

### Step 4 — Confirm

Tell the user:
- How many scopes are loaded
- Which targets are authorized
- That CLAUDE.md is ready and will be applied for this session
