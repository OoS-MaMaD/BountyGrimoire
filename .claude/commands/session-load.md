---
description: Resume a saved audit session. Usage: /session-load <name>
---

# Load Audit Session

Resume a previously saved audit session.

## Instructions

Given the session name in $ARGUMENTS:

### Step 1 — Read session file

```bash
cat sessions/$ARGUMENTS.json
```

If not found, list available sessions:
```bash
ls sessions/*.json 2>/dev/null | sed 's/sessions\///' | sed 's/\.json//'
```

### Step 2 — Restore context

From the session file, display a clear summary:

```
═══════════════════════════════════════
 SESSION: <name>
 Program : <program> (<platform>)
 Saved   : <saved_at>
═══════════════════════════════════════

 SCOPE
 ├─ target1.com
 └─ target2.com

 PROGRESS
 ├─ URLs tested : X
 └─ Findings    : Y

 FINDINGS
 ├─ [High]   IDOR in /api/users/{id} — confirmed
 └─ [Medium] XSS in /search?q= — to verify

 LAST TESTED URLS
 ├─ GET https://target.com/api/users
 └─ POST https://target.com/api/login
═══════════════════════════════════════
```

### Step 3 — Update CLAUDE.md

Rewrite CLAUDE.md with the restored scope and rules:

```
# Security Agent — <program>

Platform: <ywh|h1>
Session: <name> (resumed <datetime>)

## ✅ IN Scope
<scope targets>

## Known Findings
<list findings already confirmed — do not re-test these>

## Already Tested
<list of tested URLs — skip these unless specifically asked>

## Workflow
1. Always verify target is IN scope before testing
2. Skip already-confirmed findings
3. Continue from where the session left off
```

### Step 4 — Confirm

Tell the user the session is restored and ready to continue.
