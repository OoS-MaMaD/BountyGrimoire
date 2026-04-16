---
description: Launch authenticated security audit using stored test accounts. Usage: /hunt-auth <target> [--types xss,idor]
---

# Authenticated Multi-Agent Security Hunt (Token-Optimized)

Same as /hunt but all requests use authenticated sessions.
Uses two accounts for IDOR testing: attacker vs victim.

## Instructions

Given the target in $ARGUMENTS:

### Step 1 — Load accounts

```bash
cat "accounts/<target>.json" 2>/dev/null
```

If file missing → tell user to run `/setup-account <target>` first and stop.

### Step 2 — Parse options

Extract `--types` from arguments if present. If provided, only launch the listed hunter types.
Supported types: idor, auth, xss, bizlogic, pii, secrets, enumerable

### Step 3 — Extract minimal context

Read CLAUDE.md and extract ONLY these fields (do NOT inject the full file):

```
PROGRAM_SLUG: <slug>
IN_SCOPE: <list of targets>
QUALIFYING: <list of qualifying vulns>
NON_QUALIFYING: <list of non-qualifying vulns>
RULES: <key rules only — UA, proxy, restrictions>
USER_AGENT: <from CLAUDE.md>
PROXY: <from CLAUDE.md>
```

Read memory:
```bash
cat "memory/${PROGRAM_SLUG}.json" 2>/dev/null || echo "{}"
```

### Step 4 — Refresh sessions if expired

```bash
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -A "<USER_AGENT>" "https://<target>/profile" \
  -b "<ACCOUNT1_COOKIE>")

# If not 200, re-authenticate using credentials from accounts/<target>.json
```

### Step 5 — Authenticated Recon FIRST (single agent, blocking)

Launch ONE recon subagent. Wait for it to complete before proceeding.

```
Target: <target>
RULES: User-Agent must include "<USER_AGENT>". Use proxy <PROXY>.
MEMORY: <confirmed_patterns and false_positives from previous hunts on this program>
ACCOUNTS:
  Attacker — email: <A1_EMAIL> | id: <A1_ID> | cookie: <A1_COOKIE>
  Victim   — email: <A2_EMAIL> | id: <A2_ID> | cookie: <A2_COOKIE>

Authenticated reconnaissance task:
1. If MEMORY has confirmed_patterns, prioritize testing those endpoints first
2. If MEMORY has false_positives, skip those patterns — they waste time
3. As attacker, browse all authenticated areas: profile, settings, dashboard, API
4. Discover all API endpoints and routes accessible to authenticated users
5. Identify endpoints accepting user IDs or object IDs as parameters
6. Map admin/privileged endpoints if accessible
7. List all forms and their fields

Return JSON:
{
  "technologies": ["<tech>"],
  "endpoints": [
    {"url": "<path>", "method": "GET|POST", "params": ["<param>"], "auth_required": true, "description": "<desc>"}
  ],
  "forms": [
    {"action": "<path>", "method": "POST", "fields": ["<field>"]}
  ],
  "idor_candidates": [
    {"endpoint": "<path>", "param": "<param>", "pattern": "sequential|uuid|email"}
  ],
  "memory_hits": ["<endpoints from memory that are still accessible>"],
  "notes": "<anything relevant>"
}
```

### Step 6 — Launch targeted authenticated hunter subagents

Each hunter receives ONLY:

```
SCOPE: <in_scope_targets>
RULES: User-Agent must include "<USER_AGENT>". Use proxy <PROXY>.
QUALIFYING: <qualifying_vulns>
NON_QUALIFYING: <non_qualifying_vulns>
ACCOUNTS:
  Attacker — email: <A1_EMAIL> | id: <A1_ID> | cookie: <A1_COOKIE>
  Victim   — email: <A2_EMAIL> | id: <A2_ID> | cookie: <A2_COOKIE>
ENDPOINTS: <recon output>
MEMORY: <relevant patterns from memory>
```

All curl: `-b <A1_COOKIE> -A "<USER_AGENT>"` (unless stated otherwise).

### Rate limiting rules (MANDATORY)

ALL hunters MUST follow these rules to avoid triggering rate limits or bans:
- Max 2 requests per second per endpoint
- Add `--limit-rate 100k` to curl to cap bandwidth
- Stagger requests with `sleep 0.5` between curl calls on the same host
- If you receive 429 (Too Many Requests) or 503, STOP and report partial results
- Rotate between different endpoints rather than hammering one

Launch all selected hunters in parallel. If no `--types`, launch all 7.

---

**Task 1 — IDOR Hunter**
```
<trimmed context>

Specialized in authenticated IDOR.
Strategy:
1. As attacker, browse your own profile/resources to discover ID patterns
2. Replace your ID with victim ID (<A2_ID>) in every endpoint from recon
3. Focus on idor_candidates from recon output
4. Try victim ID in POST body, query params, and headers
Return JSON: {"type":"idor","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 2 — Auth/Privilege Escalation Hunter**
```
<trimmed context>

Specialized in privilege escalation and broken access control.
Test with attacker session:
- Access admin-only endpoints from recon
- Modify roles/permissions via API
- Access other users' settings, billing, data
Return JSON: {"type":"auth","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 3 — Stored XSS Hunter**
```
<trimmed context>

Specialized in stored XSS requiring authentication.
Test all authenticated inputs from recon: profile fields, comments, messages, settings, bio.
Return JSON: {"type":"xss","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 4 — Business Logic Hunter**
```
<trimmed context>

Specialized in authenticated business logic flaws.
Test: price/quantity manipulation, workflow bypass, race conditions, negative values.
Focus on forms and endpoints with financial/order/subscription logic.
Return JSON: {"type":"bizlogic","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 5 — PII Hunter**
```
<trimmed context>

Specialized in PII exposure for authenticated users.
Test: API responses leaking other users' data, export features, search results.
Compare attacker vs victim data access.
Return JSON: {"type":"pii","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 6 — Secrets Hunter**
```
<trimmed context>

Specialized in secrets exposed to authenticated users.
Test: tokens, keys, internal data in authenticated API responses.
Return JSON: {"type":"secrets","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 7 — Enumeration Hunter**
```
<trimmed context>

Specialized in authenticated enumeration.
Using attacker session, enumerate other users' IDs, emails, resources.
Compare responses between victim ID and random IDs.
Return JSON: {"type":"enumerable","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

---

### Step 7 — Collect raw results

Wait for all hunters to complete. Collect all findings into a single JSON array.

### Step 8 — Batch validate (single agent)

Same batch validation as /hunt — one validator for all findings.

```
SCOPE: <in_scope_targets>
QUALIFYING: <qualifying_vulns>
NON_QUALIFYING: <non_qualifying_vulns>
RULES: User-Agent must include "<USER_AGENT>". Use proxy <PROXY>.

Validate ALL findings in a single pass. Return JSON array with status, confidence, reproduction, evidence, severity.
Keep only CONFIRMED/LIKELY with IN_SCOPE and QUALIFYING (confidence >= 70).
```

### Step 9 — Update memory

Merge into `memory/<program_slug>.json` — same format as /hunt.

### Step 10 — Display results

```
═══════════════════════════════════════════════
 AUTHENTICATED HUNT RESULTS — <target>
═══════════════════════════════════════════════
 ENDPOINTS DISCOVERED: X (authenticated)
 HUNTERS LAUNCHED: X/7
 ✅ CONFIRMED   X
 ⚠️  LIKELY      X
 ❌ DISCARDED   X false positives
 🚫 OUT_OF_SCOPE X
 🧠 MEMORY      Updated

 VALIDATED FINDINGS
 ─────────────────────────────────────────────
 [HIGH] IDOR — /api/users/<A2_ID> ✅ CONFIRMED (92%)
   Attacker accessed victim profile data
   curl: curl -b session1.txt ...
 ═══════════════════════════════════════════════
```

Save `sessions/hunt-auth-<target>-<date>.json`.
Suggest `/report` for confirmed findings.
