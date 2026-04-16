#!/usr/bin/env python3
"""
Security Skills Generator

Generates or improves vulnerability hunting skills from real bug bounty reports.
Supports multiple LLM providers: Anthropic, OpenAI, and any OpenAI-compatible API.

Usage:
  python3 generate-skill.py xss
  python3 generate-skill.py xss --max 20
  python3 generate-skill.py xss --extra ./my-reports/
  python3 generate-skill.py --all --max 20
  python3 generate-skill.py --list

  # Use OpenAI
  python3 generate-skill.py xss --provider openai --model gpt-4o

  # Use Xiaomi MiMo
  python3 generate-skill.py xss --provider openai-compat --model MiMo-v2-Pro

  # Use any OpenAI-compatible API (local LLM, proxy, etc.)
  python3 generate-skill.py xss --provider openai-compat --model my-model --base-url http://localhost:8000/v1

Environment variables (.env):
  # Anthropic (default)
  ANTHROPIC_API_KEY=sk-ant-...

  # OpenAI
  OPENAI_API_KEY=sk-...

  # OpenAI-compatible (e.g. Xiaomi MiMo)
  OPENAI_API_KEY=...
  OPENAI_BASE_URL=https://api.xiaomi.com/v1  # or any compatible endpoint

  # HuggingFace (optional, faster downloads)
  HF_TOKEN=hf_...
"""

import argparse
import json
import os
import sys
from pathlib import Path

# ── Load .env ─────────────────────────────────────────────────────────────────
_env = Path(__file__).parent / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

if os.environ.get("HF_TOKEN"):
    os.environ["HUGGING_FACE_HUB_TOKEN"] = os.environ["HF_TOKEN"]

# ── Config ────────────────────────────────────────────────────────────────────
SKILLS_DIR = Path(__file__).parent / ".claude" / "skills"
MAX_REPORTS = 40

# Default models per provider
DEFAULTS = {
    "anthropic": {
        "model": "claude-sonnet-4-5",
        "env_key": "ANTHROPIC_API_KEY",
    },
    "openai": {
        "model": "gpt-4o",
        "env_key": "OPENAI_API_KEY",
    },
    "openai-compat": {
        "model": "MiMo-v2-Pro",
        "env_key": "OPENAI_API_KEY",
        "env_base_url": "OPENAI_BASE_URL",
    },
}

# weakness.name HuggingFace -> skill name
VULN_MAP = {
    "idor": [
        "Insecure Direct Object Reference (IDOR)",
        "Broken Object Level Authorization",
    ],
    "ssrf": ["Server-Side Request Forgery (SSRF)"],
    "sqli": ["SQL Injection", "SQL Injection - Generic", "Blind SQL Injection"],
    "xss": [
        "Cross-site Scripting (XSS) - Generic",
        "Cross-site Scripting (XSS) - Reflected",
        "Cross-site Scripting (XSS) - Stored",
        "Cross-site Scripting (XSS) - DOM",
    ],
    "auth": [
        "Improper Authentication - Generic",
        "Improper Authorization",
        "Authentication Bypass",
        "Broken Authentication",
    ],
    "rce": [
        "Code Injection",
        "Remote Code Execution",
        "Command Injection - Generic",
        "OS Command Injection",
    ],
    "xxe": [
        "XML External Entities (XXE)",
        "Improper Restriction of XML External Entity",
    ],
    "ssti": ["Server-Side Template Injection"],
    "secrets": [
        "Information Disclosure",
        "Insecure Storage of Sensitive Information",
        "Exposed Credentials",
    ],
    "otp": ["Improper Authentication - Generic", "Two-Factor Authentication Bypass"],
    "pii": ["Information Disclosure", "Privacy Violation"],
    "bizlogic": ["Business Logic Errors", "Race Condition"],
    "callback": ["Open Redirect", "URL Redirection to Untrusted Site"],
    "enumerable": ["Insecure Direct Object Reference (IDOR)", "User Enumeration"],
    "insecure": [
        "Security Misconfiguration",
        "Improper Access Control - Generic",
        "Cross-Origin Resource Sharing (CORS)",
    ],
    "referer": ["Information Disclosure", "Sensitive Data Exposure"],
    "checksum": [
        "Improper Verification of Cryptographic Signature",
        "Improper Input Validation",
    ],
}

# ── LLM Provider Abstraction ──────────────────────────────────────────────────


def call_llm(prompt: str, provider: str, model: str, base_url: str | None) -> str:
    """
    Call an LLM provider and return the response text.

    Supports: anthropic, openai, openai-compat
    """
    if provider == "anthropic":
        return _call_anthropic(prompt, model)
    elif provider == "openai":
        return _call_openai(prompt, model, base_url=None)
    elif provider == "openai-compat":
        return _call_openai(prompt, model, base_url=base_url)
    else:
        raise ValueError(f"Unknown provider: {provider}")


def _call_anthropic(prompt: str, model: str) -> str:
    try:
        import anthropic
    except ImportError:
        print("[!] pip install anthropic")
        sys.exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[!] ANTHROPIC_API_KEY not set in .env")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    print(f"  [~] Calling Anthropic API ({model})...")
    msg = client.messages.create(
        model=model,
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )
    cost = (msg.usage.input_tokens / 1_000_000) * 3 + (
        msg.usage.output_tokens / 1_000_000
    ) * 15
    print(
        f"  [~] {msg.usage.input_tokens} in / {msg.usage.output_tokens} out | ~${cost:.3f}"
    )
    return msg.content[0].text


def _call_openai(prompt: str, model: str, base_url: str | None) -> str:
    try:
        from openai import OpenAI
    except ImportError:
        print("[!] pip install openai")
        sys.exit(1)

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("[!] OPENAI_API_KEY not set in .env")
        sys.exit(1)

    kwargs = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
        print(f"  [~] Calling OpenAI-compatible API ({model}) @ {base_url}...")
    else:
        print(f"  [~] Calling OpenAI API ({model})...")

    client = OpenAI(**kwargs)
    resp = client.chat.completions.create(
        model=model,
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )

    usage = resp.usage
    if usage:
        print(f"  [~] {usage.prompt_tokens} in / {usage.completion_tokens} out")
    else:
        print(f"  [~] Response received (no usage data)")

    return resp.choices[0].message.content


# ── HuggingFace ───────────────────────────────────────────────────────────────


def fetch_hf_reports(vuln_name: str, max_reports: int) -> list:
    try:
        from datasets import load_dataset
    except ImportError:
        print("[!] pip install datasets --break-system-packages")
        return []

    target_weaknesses = [w.lower() for w in VULN_MAP[vuln_name]]
    reports = []
    checked = 0

    print(f"  [~] HuggingFace streaming (bounty=true, weakness match)...")

    try:
        ds = load_dataset(
            "Hacker0x01/hackerone_disclosed_reports",
            split="train",
            streaming=True,
        )

        for row in ds:
            checked += 1

            if not row.get("has_bounty?"):
                continue

            weakness = (row.get("weakness") or {}).get("name", "") or ""
            if not any(w in weakness.lower() for w in target_weaknesses):
                continue

            body = row.get("vulnerability_information", "") or ""
            if not body:
                continue

            reports.append(
                {
                    "title": row.get("title", ""),
                    "severity": weakness,
                    "bounty": True,
                    "body": body[:2000],
                }
            )

            print(
                f"  [~] {len(reports)}/{max_reports} found ({checked} checked)",
                end="\r",
            )

            if len(reports) >= max_reports:
                break

    except Exception as e:
        print(f"\n  [!] HuggingFace error: {e}")

    print(f"\n  [+] {len(reports)} HF reports fetched ({checked} checked)")
    return reports


# ── Extra files ───────────────────────────────────────────────────────────────


def read_extra_files(paths: list) -> str:
    """Read extra files and return their raw concatenated content."""
    contents = []

    for p in paths:
        path = Path(p)
        if not path.exists():
            print(f"  [!] File not found: {p}")
            continue

        files = list(path.rglob("*")) if path.is_dir() else [path]

        for f in files:
            if not f.is_file():
                continue
            ext = f.suffix.lower()
            try:
                if ext in [".json"]:
                    data = json.loads(f.read_text(errors="replace"))
                    contents.append(
                        f"=== {f.name} ===\n{json.dumps(data, indent=2)[:3000]}"
                    )
                elif ext in [".csv", ".txt", ".md", ".html"]:
                    contents.append(
                        f"=== {f.name} ===\n{f.read_text(errors='replace')[:3000]}"
                    )
                elif ext == ".pdf":
                    try:
                        import subprocess

                        result = subprocess.run(
                            ["pdftotext", str(f), "-"],
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        if result.returncode == 0:
                            contents.append(f"=== {f.name} ===\n{result.stdout[:3000]}")
                        else:
                            print(
                                f"  [!] pdftotext failed for {f.name} (install poppler-utils)"
                            )
                    except FileNotFoundError:
                        print(f"  [!] pdftotext not found, install poppler-utils")
                else:
                    print(f"  [~] Format skipped: {f.name}")
            except Exception as e:
                print(f"  [!] Error reading {f.name}: {e}")

    return "\n\n".join(contents)


# ── Prompts ───────────────────────────────────────────────────────────────────

CREATE_PROMPT = """You are a senior security researcher. Below are {count} real HackerOne bounty-paid reports about {vuln_type} vulnerabilities.

Synthesize these into a single actionable skill file for an AI security agent that tests web applications directly using curl and CLI tools.

Include:
1. High-value patterns from real reports (param names, endpoint patterns, ID types, headers)
2. Bash commands to discover and test vulnerabilities (curl, grep, etc.)
3. Step-by-step testing methodology with concrete curl examples
4. Severity rating table
5. False positives to ignore
6. Finding report template

Start with this frontmatter:
---
description: Find {vuln_type} vulnerabilities in web applications. Use when testing for {vuln_type} issues.
---

Be concrete — use real patterns and examples from the reports. No preamble.

--- REPORTS ---
{reports}"""

IMPROVE_PROMPT = """You are a senior security researcher improving an existing security skill file.

Below is:
1. The CURRENT skill file to improve
2. NEW material (bug reports, writeups, or research) to extract patterns from

Your task: enhance the skill by adding NEW patterns, techniques, and examples from the new material.
- Keep all existing content
- Add new sections or extend existing ones with concrete findings from the new material
- Do NOT repeat patterns already present
- Remove any references to log.txt or mitmproxy if present
- Maintain the same frontmatter and structure

--- CURRENT SKILL ---
{current_skill}

--- NEW MATERIAL ---
{new_material}"""


def format_reports(reports: list) -> str:
    parts = []
    for i, r in enumerate(reports, 1):
        parts.append(f"[{i}] {r['title']} | {r['severity']}\n{r['body']}")
    return "\n\n---\n\n".join(parts)


def save_skill(vuln_name: str, content: str) -> Path:
    skill_dir = SKILLS_DIR / f"find-{vuln_name}"
    skill_dir.mkdir(parents=True, exist_ok=True)
    path = skill_dir / "SKILL.md"
    path.write_text(content)
    print(f"  [+] -> {path}")
    return path


# ── Pipeline ──────────────────────────────────────────────────────────────────


def process(
    vuln_name: str,
    max_reports: int,
    extra_paths: list,
    no_hf: bool,
    provider: str,
    model: str,
    base_url: str | None,
) -> bool:
    if vuln_name not in VULN_MAP:
        print(f"[!] Unknown skill '{vuln_name}'. Run --list.")
        return False

    print(f"\n[*] {vuln_name}")

    skill_path = SKILLS_DIR / f"find-{vuln_name}" / "SKILL.md"
    skill_exists = skill_path.exists()

    # Fetch HF reports
    hf_reports = []
    if not no_hf:
        hf_reports = fetch_hf_reports(vuln_name, max_reports)

    # Read extra files
    extra_content = ""
    if extra_paths:
        print(f"  [~] Reading extra files...")
        extra_content = read_extra_files(extra_paths)
        print(f"  [+] {len(extra_content)} chars of extra content")

    if not hf_reports and not extra_content:
        print("  [!] No source material available")
        return False

    if not skill_exists:
        # Create
        if not hf_reports:
            print("  [!] No HF reports to create initial skill")
            return False
        prompt = CREATE_PROMPT.format(
            count=len(hf_reports),
            vuln_type=vuln_name.upper(),
            reports=format_reports(hf_reports),
        )
        if extra_content:
            prompt += f"\n\n--- EXTRA MATERIAL ---\n{extra_content[:3000]}"
        content = call_llm(prompt, provider, model, base_url)
        save_skill(vuln_name, content)
        print(f"  [v] Skill created")

    else:
        # Improve
        current = skill_path.read_text()
        new_material_parts = []
        if hf_reports:
            new_material_parts.append(
                f"=== HackerOne Reports ===\n{format_reports(hf_reports)}"
            )
        if extra_content:
            new_material_parts.append(f"=== Extra Files ===\n{extra_content[:3000]}")

        if not new_material_parts:
            print("  [!] Nothing new to add")
            return False

        prompt = IMPROVE_PROMPT.format(
            current_skill=current,
            new_material="\n\n".join(new_material_parts),
        )
        content = call_llm(prompt, provider, model, base_url)
        save_skill(vuln_name, content)
        print(f"  [v] Skill improved")

    return True


# ── CLI ───────────────────────────────────────────────────────────────────────


def detect_provider(args) -> tuple[str, str, str | None]:
    """Detect the LLM provider, model, and base URL from args and env."""
    # If provider explicitly set, use it
    if args.provider:
        provider = args.provider
    elif os.environ.get("LLM_PROVIDER"):
        provider = os.environ["LLM_PROVIDER"]
    else:
        # Auto-detect: check which API key is set
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.environ.get("OPENAI_API_KEY"):
            # If OPENAI_BASE_URL is set, assume openai-compat
            if os.environ.get("OPENAI_BASE_URL"):
                provider = "openai-compat"
            else:
                provider = "openai"
        else:
            print(
                "[!] No API key found. Set one of:\n"
                "    ANTHROPIC_API_KEY  (for Claude)\n"
                "    OPENAI_API_KEY     (for OpenAI / compatible)\n"
                "    OPENAI_BASE_URL    (for OpenAI-compatible APIs)"
            )
            sys.exit(1)

    if provider not in DEFAULTS:
        print(f"[!] Unknown provider '{provider}'. Choose from: {', '.join(DEFAULTS)}")
        sys.exit(1)

    defaults = DEFAULTS[provider]

    # Model: CLI > env > default
    model = args.model or os.environ.get("LLM_MODEL") or defaults["model"]

    # Base URL: CLI > env (only for openai-compat)
    base_url = args.base_url
    if not base_url and provider == "openai-compat":
        base_url = os.environ.get(defaults.get("env_base_url", "OPENAI_BASE_URL"))

    return provider, model, base_url


def main():
    global MAX_REPORTS
    parser = argparse.ArgumentParser(
        description="Generate/improve security skills from bug bounty reports"
    )
    parser.add_argument("skills", nargs="*", help="Skill names (e.g. xss idor)")
    parser.add_argument("--all", action="store_true", help="Generate all skills")
    parser.add_argument("--list", action="store_true", help="List available skills")
    parser.add_argument("--max", type=int, default=MAX_REPORTS, metavar="N")
    parser.add_argument(
        "--extra", nargs="+", default=[], help="Extra files/folders to include"
    )
    parser.add_argument(
        "--no-hf", action="store_true", help="Skip HuggingFace, use only extra files"
    )

    # LLM provider options
    llm_group = parser.add_argument_group("LLM provider")
    llm_group.add_argument(
        "--provider",
        choices=["anthropic", "openai", "openai-compat"],
        help="LLM provider (auto-detected from env if not set)",
    )
    llm_group.add_argument(
        "--model",
        help="Model name (default: provider-specific, e.g. claude-sonnet-4-20250514, gpt-4o, MiMo-v2-Pro)",
    )
    llm_group.add_argument(
        "--base-url",
        help="API base URL for openai-compat provider (e.g. https://api.xiaomi.com/v1)",
    )

    args = parser.parse_args()

    if args.list:
        print(f"{'Skill':<15} Weakness types")
        print("-" * 60)
        for name, types in VULN_MAP.items():
            print(f"{name:<15} {types[0][:45]}")
        return

    # Detect provider
    provider, model, base_url = detect_provider(args)
    print(f"[i] Provider: {provider} | Model: {model}")

    MAX_REPORTS = args.max
    targets = list(VULN_MAP.keys()) if args.all else args.skills
    if not targets:
        parser.print_help()
        return

    ok = sum(
        process(v, MAX_REPORTS, args.extra, args.no_hf, provider, model, base_url)
        for v in targets
    )
    print(f"\n[v] {ok}/{len(targets)} skills processed -> {SKILLS_DIR}")


if __name__ == "__main__":
    main()
