---
description: Load a HackerOne program rules and scopes. Usage: /load-program-h1 <handle>
---

# Load HackerOne Program

Load the rules, scopes and policy of a HackerOne program into CLAUDE.md.

## Instructions

Given the program handle in $ARGUMENTS:

### Step 1 — Fetch program data

```bash
curl -s -A "BountyGrimoire/1.0" "https://api.hackerone.com/v1/hackers/programs/$ARGUMENTS" \
  -H "Accept: application/json"
```

If H1_USER and H1_TOKEN environment variables are set, use auth:
```bash
curl -s -A "BountyGrimoire/1.0" --user "$H1_USER:$H1_TOKEN" \
  "https://api.hackerone.com/v1/hackers/programs/$ARGUMENTS" \
  -H "Accept: application/json"
```

### Step 2 — Parse and display

Extract from the JSON response:
- `attributes.name` → program name
- `relationships.structured_scopes.data[]` → scopes with:
  - `attributes.asset_identifier` → target URL/domain
  - `attributes.asset_type` → type (URL, CIDR, etc.)
  - `attributes.eligible_for_bounty` → in scope for bounty
  - `attributes.eligible_for_submission` → can submit reports
  - `attributes.instruction` → specific scope rules
- `attributes.policy` → program policy/rules (strip markdown if needed)

Display a clean summary:
- ✅ IN scope targets (eligible_for_submission: true)
- 💰 Bounty eligible targets (eligible_for_bounty: true)
- ❌ OUT of scope targets (eligible_for_submission: false)
- Key rules from policy

### Step 3 — Write CLAUDE.md

Write a CLAUDE.md file at the root of the project with:

```
# Security Agent — <program name>

HackerOne: https://hackerone.com/<handle>

## ⚠️ Program Rules (MANDATORY)
<extracted policy, max 2000 chars>

## ✅ IN Scope — Authorized targets
<list with type and bounty eligibility>

## 💰 Bounty eligible targets
<subset of in-scope that pay bounty>

## ❌ OUT of Scope — NEVER test these
<list of out-of-scope targets>

## Proxy
All curl requests MUST use: -x http://localhost:8088 --proxy-insecure

## Workflow
1. Always verify the target is IN scope before any request
2. NEVER test OUT of scope targets
3. Prioritize bounty-eligible targets first
4. Use curl with proxy AND user-agent for ALL requests
5. Use available skills to analyze findings
```

### Step 4 — Confirm

Tell the user:
- How many scopes are loaded
- Which targets are bounty eligible
- That CLAUDE.md is ready and will be applied for this session
