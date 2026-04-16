<div align="center">

# 🦊 BountyGrimoire
**Fully Autonomous AI Agents for Continuous Bug Bounty Hunting**

Powered by **18 specialized AI agents** playing both Attacker and Validator.<br/>
Skills built from real, paid HackerOne disclosures via the public transparency dataset.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Skills](https://img.shields.io/badge/Vuln_Skills-18-success.svg?style=for-the-badge)](.claude/skills/)
[![Claude Code](https://img.shields.io/badge/Powered_by-Claude_Code-orange.svg?style=for-the-badge&logo=anthropic)](https://docs.anthropic.com/en/docs/claude-code)
[![Python](https://img.shields.io/badge/Python-3.10+-yellow.svg?style=for-the-badge&logo=python)]()

</div>

---

## ⚡ Why BountyGrimoire?

Hunting for bugs manually takes days of repetitive reconnaissance. BountyGrimoire orchestrates an army of **18 highly specialized AI hunters** that operate in parallel to map, scan, and exploit vulnerabilities across your targets. 

Unlike traditional scanners that spit out hundreds of false positives, **BountyGrimoire thinks like a real hacker:**

- **🧠 Native Intuition**: Agents are trained on thousands of real, paid HackerOne disclosures via the public transparency dataset.
- **🎯 Minimal False Positives**: Every finding goes to an isolated **Validator agent**. If the Validator can't independently reproduce the attack using `curl`, you won't even see it.
- **🔑 Authenticated Workflows**: Swaps effortlessly between Attacker and Victim sessions to uncover complex IDOR and privilege escalation flaws.
- **📚 Continuous Memory**: The more you hunt, the smarter it gets. Successful attack vectors and target tech-stack state are saved per-program.

---

## 🚀 Quick Start

From zero to fully automated hacking in 3 simple commands:

```bash
git clone https://github.com/N1neKitsune/BountyGrimoire.git
cd BountyGrimoire
./install.sh
```

> [!WARNING]
> **BountyGrimoire requires elevated permissions to operate.**
> The command below grants Claude Code unrestricted access to execute shell commands on your machine. This is necessary for automated security testing (curl, recon, payload execution).
> **Only run this inside a dedicated VM or isolated environment. Never on your personal machine.**

```bash
source .venv/bin/activate
claude --dangerously-skip-permissions
```

### 🛠️ The 3-Step Hacking Workflow

No configuration nightmare. Just point and shoot:

```bash
# 1. Load your scope program rules automatically (H1 or YWH)
/load-program ywh-program-slug 

# 2. Launch all 18 parallel agents on your target
/hunt target.com

# 3. Export a complete, submission-ready report (CVSS, PoC, Remediation)
/report
```

---

## 🦠 The 18 Specialized Hunters

Each agent is a dedicated expert in a single vulnerability class. They don't just scan — they exploit.

| 🕵️ Agent | 🎯 Primary Target | 🕵️ Agent | 🎯 Primary Target |
| :--- | :--- | :--- | :--- |
| **`IDOR`** | BOLA, BFLA, Context Swapping | **`SSRF`** | Metadata AWS/GCP, Internal networks |
| **`SQLi`** | Error, Time-based, Blind | **`XSS`** | Stored, Reflected, DOM |
| **`Auth`** | Session hijacking, MFA Bypass | **`RCE`** | Command/Code Injection, Deserialization |
| **`XXE`** | Entity Injection, LFI | **`SSTI`** | Jinja2, Twig, Mako, Pug |
| **`Secrets`**| Exposed Env, API Keys, Maps | **`OTP`** | Brute force, Logic/flow tricks |
| **`PII`** | Data leaks, Privacy exposures | **`BizLogic`**| Price manipulation, Race conditions |
| **`Callback`**| Webhook hijacking, Open Redirect| **`Recon`** | JS mapping, Tech stack inference |
| **`Insecure`**| CORS, Exposed Admin panels | **`Referer`** | Tokens leaking through Headers |
| **`Checksum`**| Integrity bypassing, Mismatch | **`Enumerable`**| Timing attacks, Sequential IDs |

---

## 🧬 Dynamic Skill Generator

The threat landscape evolves every day. So does BountyGrimoire. The built-in **Skill Generator** pulls the absolute latest resolved HackerOne reports (via HuggingFace) and automatically updates the agent's logic with new attack vectors.

```bash
# Enhance the XSS agent with patterns from the last 20 public reports
python3 generate-skill.py xss --max 20

# Rebuild and optimize ALL agents simultaneously
python3 generate-skill.py --all --max 20

# Feed your own private writeups (PDF, Markdown, HTML, JSON) to the agents!
python3 generate-skill.py rce --extra ./my-private-writeups/
```

BountyGrimoire supports multiple LLMs for skill generation:
- **Anthropic** (e.g. `claude-sonnet-4-5`)
- **OpenAI** (e.g. `gpt-4o`)
- **Local/Custom Providers** via OpenAI-compatibilities (Ollama, vLLM, DeepSeek...)

> **Note:** Activate the virtual environment before running the generator: `source .venv/bin/activate`

---

## 📂 Memory & Advanced Hunts

### 💾 Auto-Memory System
BountyGrimoire never forgets what works. After every hunt, `memory/<program>.json` stores confirmed payload patterns, detected tech stacks, and previous false-positives so agents don't waste time on the next run. You can resume any session when needed:

```bash
/session-save friday-night-hunt
/session-load friday-night-hunt
```

### 🎭 Authenticated Hunts
For deep, complex applications, build both sides of the attack to verify cross-account permissions:
```bash
/setup-account target.com      # Sets up Attacker and Victim tokens
/hunt-auth target.com          # Launches agents capable of session-swapping
```

<details>
<summary><b>⚙️ Custom .env Configuration (Optional)</b></summary>

The `.env` file is primarily used to fuel the **Skill Generator**. Testing runs entirely local via Claude.

```bash
# Define your LLM for the Skill Generator Engine
ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-proj-...
# OPENAI_BASE_URL=http://localhost:8000/v1

# Platform Tokens (To automatically load scopes & rules)
HF_TOKEN=hf_...               # Faster HuggingFace downloads
YWH_PAT=your_ywh_token        # YesWeHack Private Programs
H1_USER=your_h1_username      # HackerOne Private Programs
H1_TOKEN=your_h1_api_token
```

</details>

---

## ⚖️ Rules of Engagement

> 🛑 **WARNING**: Unauthorized hacking is illegal.
> BountyGrimoire is an offensive tool designed **strictly** for authorized Bug Bounty programs you are enrolled in, your own infrastructure, or contracted penetration tests. Do not use this tool on targets you do not have explicit, documented permission to test. Always respect program rules.

<br/>

<div align="center">
  <i>Built with ✨ for the security community. Native skills aggregated from the <a href="https://huggingface.co/datasets/Hacker0x01/hackerone_disclosed_reports">HackerOne Transparency Dataset</a>.</i>
</div>
