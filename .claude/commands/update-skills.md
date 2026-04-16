---
description: Update skills from confirmed findings and improve them. Usage: /update-skills [skill-name]
---

# Update Skills from Confirmed Findings

Feed confirmed findings back into the corresponding skills to improve future hunts.

## Instructions

Given an optional skill name in $ARGUMENTS:

### Step 1 — Load confirmed findings

```bash
# If skill name provided, load memory for that type
# Otherwise, load all memory files

PROGRAM_SLUG=$(grep -oP 'programs/\K[^/\s]+' CLAUDE.md | head -1)
cat "memory/${PROGRAM_SLUG}.json" 2>/dev/null || echo "{}"
```

Also load the latest session file:
```bash
ls -t sessions/hunt-*.json sessions/hunt-auth-*.json 2>/dev/null | head -1
```

### Step 2 — Extract patterns to inject

From memory and session files, extract:
- **confirmed_patterns**: working payloads, endpoints, parameters
- **false_positives**: patterns that waste time, skip next time
- **technology_stack**: detected technologies

Filter by skill name if provided.

### Step 3 — Load target skill(s)

```bash
# Single skill
cat .claude/skills/find-<name>/SKILL.md

# Or all skills
for dir in .claude/skills/find-*/; do
    echo "=== $(basename $dir) ==="
    head -5 "$dir/SKILL.md"
done
```

### Step 4 — Improve each skill

For each skill that has new patterns in memory:

1. Read the current skill file
2. Identify gaps — what patterns are in memory but NOT in the skill?
3. Append new sections at the end of the skill:

```markdown
## Program-Learned Patterns (auto-updated)

### Confirmed Working Patterns
- **<vuln_type> on <program>**: <endpoint> with param `<param>` using payload `<payload>`
  - Reproduction: `<curl_command>`
  - Severity: <severity>
  - Confirmed: <date>

### Confirmed False Positives (skip these)
- **<pattern>** — <reason>
- **<pattern>** — <reason>

### Technology Notes
- <tech> commonly uses <pattern>
```

4. Do NOT duplicate patterns already present in the skill
5. Keep existing content intact

### Step 5 — Save and report

```bash
# Skills are saved in place
```

Report what was updated:
```
═══════════════════════════════════════════════
 SKILL UPDATE RESULTS
═══════════════════════════════════════════════
 ✅ find-idor    +3 patterns, +2 false positives
 ✅ find-xss     +1 pattern
 ⏭️  find-ssrf    no new patterns
 ═══════════════════════════════════════════════
 Total: 4 skills updated with 6 new patterns
```
