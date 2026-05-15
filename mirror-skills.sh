#!/bin/bash
# Re-sync .claude/skills/ -> .agent/skills/<name>/SKILL.md
# Run this after every `python3 generate-skill.py` call.
set -e
for skill_file in .claude/skills/*.md; do
    [ -f "$skill_file" ] || continue
    skill_name=$(basename "$skill_file" .md)
    mkdir -p ".agent/skills/${skill_name}"
    cp "$skill_file" ".agent/skills/${skill_name}/SKILL.md"
    echo "  mirrored: ${skill_name}"
done
echo "Done."
