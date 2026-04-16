---
description: Save the current audit session state. Usage: /session-save <name>
---

# Save Audit Session

Save the current audit session to a JSON file so it can be resumed later.

## Instructions

Given an optional session name in $ARGUMENTS (default: use program slug):

### Step 1 — Collect current state

Gather from the current conversation context:
- Program name and slug (from CLAUDE.md if loaded)
- Platform (yeswehack or hackerone)
- In-scope targets
- URLs tested so far this session
- Findings discovered (title, severity, endpoint, status)

### Step 2 — Write session file

Create a file at `./sessions/<name>.json`:

```json
{
  "name": "<session_name>",
  "program": "<program_slug>",
  "platform": "<ywh|h1>",
  "saved_at": "<ISO datetime>",
  "scope": ["target1.com", "target2.com"],
  "tested_urls": [
    {"url": "https://target.com/api/users", "method": "GET", "tested_at": "..."}
  ],
  "findings": [
    {
      "title": "IDOR in /api/users/{id}",
      "severity": "High",
      "endpoint": "GET /api/users/123",
      "status": "confirmed",
      "notes": "Can access other users data by changing ID"
    }
  ],
  "notes": ""
}
```

Create the `sessions/` directory if it doesn't exist:
```bash
mkdir -p sessions
```

### Step 3 — Confirm

Tell the user:
- Session saved to `sessions/<name>.json`
- Summary: X URLs tested, Y findings
- How to resume: `/session-load <name>`
