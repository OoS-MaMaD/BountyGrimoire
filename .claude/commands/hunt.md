---
description: Launch a full parallel multi-agent security audit on a target. Usage: /hunt <target> [--types xss,idor]
---

# Multi-Agent Security Hunt (Token-Optimized)

## Instructions

Given the target in $ARGUMENTS:

### Step 1 — Verify scope

Read CLAUDE.md and confirm the target is IN scope. If not, refuse and list authorized targets.

### Step 2 — Parse options

Extract `--types` from arguments if present. If provided, only launch the listed hunter types.
Supported types: idor, ssrf, sqli, xss, auth, rce, xxe, ssti, secrets, otp, pii, bizlogic, callback, enumerable, insecure, referer, checksum

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

This trimmed context (~20 lines vs 65) will be injected into every subagent.

### Step 4 — Recon FIRST (single agent, blocking)

Launch ONE recon subagent. Wait for it to complete before proceeding.

```
Target: <target>
RULES: User-Agent must include "<USER_AGENT>". Use proxy <PROXY>.
MEMORY: <confirmed_patterns and false_positives from previous hunts on this program>

Reconnaissance task:
1. If MEMORY has confirmed_patterns, prioritize testing those endpoints first
2. If MEMORY has false_positives, skip those patterns — they waste time
3. Fetch the main page and extract technology stack, endpoints, forms, links
4. Check robots.txt, sitemap.xml, common paths (/api, /admin, /login, /graphql)
5. Enumerate JavaScript files for API routes and endpoints
6. Check for interesting parameters in URLs
7. Identify form fields, API endpoints, and potential injection points

Return JSON:
{
  "technologies": ["<tech>"],
  "endpoints": [
    {"url": "<path>", "method": "GET|POST", "params": ["<param>"], "description": "<desc>"}
  ],
  "forms": [
    {"action": "<path>", "method": "POST", "fields": ["<field>"]}
  ],
  "interesting_paths": ["<path>"],
  "memory_hits": ["<endpoints from memory that are still accessible>"],
  "notes": "<anything relevant>"
}
```

### Step 5 — Launch targeted hunter subagents

Use the recon output to build a minimal ENDPOINTS block. Each hunter receives ONLY:

```
SCOPE: <in_scope_targets>
RULES: User-Agent must include "<USER_AGENT>". Use proxy <PROXY>.
QUALIFYING: <qualifying_vulns>
NON_QUALIFYING: <non_qualifying_vulns>
ENDPOINTS: <recon output — technologies, endpoints, forms, paths>
MEMORY: <relevant confirmed_patterns and false_positives from memory>
```

~30 lines of context per hunter (vs 100+ previously).

### Rate limiting rules (MANDATORY)

ALL hunters MUST follow these rules to avoid triggering rate limits or bans:
- Max 2 requests per second per endpoint
- Add `--limit-rate 100k` to curl to cap bandwidth
- Stagger requests with `sleep 0.5` between curl calls on the same host
- If you receive 429 (Too Many Requests) or 503, STOP and report partial results
- Rotate between different endpoints rather than hammering one

Launch all selected hunters in parallel. If no `--types`, launch all 17 (skip recon — already done).

---

**Task 1 — IDOR Hunter**
```
<trimmed context>

Specialized in Insecure Direct Object Reference.
Test endpoint ID enumeration, horizontal/vertical privilege escalation on discovered endpoints.
Try memory patterns first.
Return JSON: {"type":"idor","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 2 — SSRF Hunter**
```
<trimmed context>

Specialized in Server-Side Request Forgery.
Test URL/redirect/callback parameters found in recon, webhook endpoints, file fetch features.
Return JSON: {"type":"ssrf","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 3 — SQLi Hunter**
```
<trimmed context>

Specialized in SQL Injection.
Test all discovered inputs with error-based, boolean-based, time-based payloads.
Return JSON: {"type":"sqli","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 4 — XSS Hunter**
```
<trimmed context>

Specialized in Cross-Site Scripting.
Test reflected, stored, DOM-based XSS on discovered endpoints and parameters.
Return JSON: {"type":"xss","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 5 — Auth Hunter**
```
<trimmed context>

Specialized in authentication and authorization.
Test auth bypass, broken access control, privilege escalation on discovered auth endpoints.
Return JSON: {"type":"auth","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 6 — RCE Hunter**
```
<trimmed context>

Specialized in Remote Code Execution and command injection.
Test file uploads, template engines, deserialization, command injection. Do not cause damage.
Return JSON: {"type":"rce","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 7 — XXE Hunter**
```
<trimmed context>

Specialized in XML External Entity injection.
Test all XML inputs, file upload with XML/SVG, SOAP endpoints.
Return JSON: {"type":"xxe","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 8 — SSTI Hunter**
```
<trimmed context>

Specialized in Server-Side Template Injection.
Test all discovered parameters with {{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}.
Return JSON: {"type":"ssti","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 9 — Secrets Hunter**
```
<trimmed context>

Specialized in information disclosure and exposed credentials.
Look for API keys, credentials, sensitive files, debug endpoints, source maps, .git, .env.
Return JSON: {"type":"secrets","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 10 — OTP Hunter**
```
<trimmed context>

Specialized in OTP/2FA/MFA bypass.
Test OTP reuse, brute force, response manipulation, backup code exposure, flow bypass.
Return JSON: {"type":"otp","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 11 — PII Hunter**
```
<trimmed context>

Specialized in PII exposure and privacy violations.
Look for exposed personal data, user enumeration via responses, unmasked sensitive fields.
Return JSON: {"type":"pii","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 12 — Business Logic Hunter**
```
<trimmed context>

Specialized in business logic flaws.
Test price manipulation, workflow bypass, race conditions, negative values, parameter tampering.
Return JSON: {"type":"bizlogic","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 13 — Callback/Redirect Hunter**
```
<trimmed context>

Specialized in open redirect and callback vulnerabilities.
Test all redirect/return/callback/next parameters for open redirect and SSRF via callbacks.
Return JSON: {"type":"callback","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 14 — Enumeration Hunter**
```
<trimmed context>

Specialized in ID and user enumeration.
Test sequential IDs, username enumeration via response differences, timing attacks.
Return JSON: {"type":"enumerable","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 15 — Insecure Config Hunter**
```
<trimmed context>

Specialized in misconfigurations and insecure settings.
Test CORS, security headers, HTTP methods, directory listing, exposed admin panels.
Return JSON: {"type":"insecure","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 16 — Referer Hunter**
```
<trimmed context>

Specialized in referer-based vulnerabilities.
Test token leakage via Referer header, auth bypass using Referer, sensitive data in Referer.
Return JSON: {"type":"referer","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

**Task 17 — Checksum Hunter**
```
<trimmed context>

Specialized in checksum and signature bypass.
Test hash/checksum manipulation, signature bypass, integrity check weaknesses.
Return JSON: {"type":"checksum","findings":[{"endpoint":"","severity":"","description":"","evidence":"","curl_command":""}]}
```

---

### Step 6 — Collect raw results

Wait for all hunters to complete. Collect all findings into a single JSON array.

### Step 7 — Batch validate (single agent)

Spawn ONE Validator subagent for ALL findings combined:

```
SCOPE: <in_scope_targets>
QUALIFYING: <qualifying_vulns>
NON_QUALIFYING: <non_qualifying_vulns>
RULES: User-Agent must include "<USER_AGENT>". Use proxy <PROXY>.

You are a senior security researcher validating potential vulnerabilities.
Be skeptical — assume each finding is WRONG until proven otherwise.

Target: <target>
Total findings to validate: <N>

<all findings as numbered list>

For EACH finding, perform:

## Check 1 — Program eligibility
- Is the endpoint explicitly listed as IN scope? If not → OUT_OF_SCOPE
- Is this vulnerability type in the qualifying list? If not → OUT_OF_SCOPE
- Is this vulnerability type in the non-qualifying list? If yes → OUT_OF_SCOPE
- Does it violate any program rule? If yes → INVALID

## Check 2 — Technical reproduction
- Run the curl command — observe the actual response
- Verify the response confirms the vulnerability
- Check if behavior is intentional or a real security issue

## Check 3 — Business impact
- Real security impact for the program?
- Eligible for bounty?
- Estimated severity: Critical / High / Medium / Low

Return ONLY this JSON array:
[
  {
    "finding_id": 1,
    "type": "<vuln_type>",
    "status": "CONFIRMED|LIKELY|UNLIKELY|FALSE_POSITIVE|OUT_OF_SCOPE",
    "confidence": 0-100,
    "scope_check": "IN_SCOPE|OUT_OF_SCOPE",
    "qualifying": "QUALIFYING|NON_QUALIFYING|UNKNOWN",
    "reproduction": "curl command",
    "evidence": "response",
    "estimated_severity": "Critical|High|Medium|Low|Informational",
    "notes": "reason"
  }
]
```

Keep only:
- CONFIRMED with scope_check=IN_SCOPE and qualifying=QUALIFYING (confidence >= 80)
- LIKELY with scope_check=IN_SCOPE and qualifying=QUALIFYING (confidence >= 70)

Discard everything else.

### Step 8 — Update program memory

```bash
mkdir -p memory
PROGRAM_SLUG=$(grep -oP 'programs/\K[^/\s]+' CLAUDE.md | head -1)
```

Write/merge `memory/${PROGRAM_SLUG}.json`:
```json
{
  "program": "<slug>",
  "last_updated": "<date>",
  "confirmed_patterns": [
    {
      "type": "<vuln_type>",
      "endpoint_pattern": "<pattern>",
      "parameter": "<param>",
      "payload": "<what worked>",
      "curl_command": "<reproduction>",
      "confirmed_at": "<date>",
      "severity": "<severity>"
    }
  ],
  "false_positives": [
    {
      "type": "<vuln_type>",
      "endpoint_pattern": "<pattern>",
      "reason": "<why false positive>"
    }
  ],
  "technology_stack": ["<tech1>", "<tech2>"],
  "discovered_endpoints": ["<endpoint from recon>"],
  "notes": "<anything useful for future hunts>"
}
```

### Step 9 — Display results

```
═══════════════════════════════════════════════
 HUNT RESULTS — <target>
═══════════════════════════════════════════════
 ENDPOINTS DISCOVERED: X
 HUNTERS LAUNCHED: X/17
 ✅ CONFIRMED   X findings
 ⚠️  LIKELY      X findings
 ❌ DISCARDED   X false positives
 🚫 OUT_OF_SCOPE X findings
 🧠 MEMORY      Updated with X new patterns

 VALIDATED FINDINGS
 ─────────────────────────────────────────────
 [CRITICAL] <type> — <endpoint> ✅ CONFIRMED (95%)
   <description>
   curl: <reproduction>

 DISCARDED
 ─────────────────────────────────────────────
 [LOW] <type> ❌ FALSE_POSITIVE — <reason>
 [MEDIUM] <type> 🚫 OUT_OF_SCOPE — not in qualifying list
 ═══════════════════════════════════════════════
```

### Step 10 — Save and suggest

Save `sessions/hunt-<target>-<date>.json` with validated findings only.
- CONFIRMED → suggest `/report`
- LIKELY → suggest manual verification then `/report`
- All discarded → suggest `/hunt` on another target
