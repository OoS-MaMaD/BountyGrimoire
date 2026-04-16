---
description: List all saved audit sessions.
---

# List Audit Sessions

Display all saved sessions with their key info.

## Instructions

### Step 1 — Find session files

```bash
ls sessions/*.json 2>/dev/null
```

If no sessions found, tell the user and suggest:
```
No sessions found. Start one with /load-program then /session-save <name>
```

### Step 2 — Display summary table

For each `.json` file in `sessions/`, read and display:

```
╔══════════════════════════════════════════════════════════╗
║                    AUDIT SESSIONS                        ║
╠══════════╦══════════════════╦══════════╦═══════╦════════╣
║ Name     ║ Program          ║ Saved    ║ URLs  ║ Finds  ║
╠══════════╬══════════════════╬══════════╬═══════╬════════╣
║ example  ║ example-program  ║ Mar 23   ║  12   ║   2    ║
║ ywh-test ║ withings-public  ║ Mar 22   ║   5   ║   0    ║
╚══════════╩══════════════════╩══════════╩═══════╩════════╝
```

### Step 3 — Suggest next action

Tell the user:
- To resume a session: `/session-load <name>`
- To start a new session: `/load-program <slug>` then audit, then `/session-save <name>`
