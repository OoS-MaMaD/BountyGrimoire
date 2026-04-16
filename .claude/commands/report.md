---
description: Generate a professional bug bounty report formatted for YesWeHack submission. Usage: /report
---

# Generate Bug Bounty Report

Generate a complete, submission-ready bug bounty report formatted for YesWeHack.

## Instructions

### Step 1 — Collect finding details

Ask the user which finding to report if multiple exist, or use the current session's confirmed finding.

### Step 2 — Generate the report in English

Write a complete report using this exact structure matching YesWeHack's submission form:

---

## BUG DETAILS

**Bug type**: `<CWE category — e.g. Improper Authentication - Generic (CWE-287)>`
**Scope**: `<exact scope from CLAUDE.md — e.g. target.example.com>`
**Endpoint**: `<full endpoint — e.g. target.example.com/user/login>`
**Vulnerable part**: `<POST parameter | GET parameter | Header | Cookie | Path>`
**Part name**: `<parameter or field name — e.g. antibot_key>`
**Payload**: `<full raw HTTP request used to reproduce>`
**Technical environment**: `Linux, curl`
**IPs used**: `<attacker IP — remind user to fill this>`

---

## BUG CHARACTERISTICS

**CVSS Vector**: `CVSS:3.1/AV:<>/AC:<>/PR:<>/UI:<>/S:<>/C:<>/I:<>/A:<>`

Provide recommended CVSS values based on the vulnerability:
- Attack Vector: Network / Adjacent / Local / Physical
- Attack Complexity: Low / High
- Privileges Required: None / Low / High
- User Interaction: None / Required
- Scope: Unchanged / Changed
- Confidentiality: None / Low / High
- Integrity: None / Low / High
- Availability: None / Low / High

---

## BUG DESCRIPTION

**Report title**: `<concise title — e.g. "Antibot module bypass allows unauthenticated credential stuffing on shareholder login">`

**Description**:

```
## Description
<General description of the vulnerability type and where it appears in the application workflow>

## Exploitation
<Step-by-step exploitation with exact curl commands>

### Step 1 — <action>
<command and explanation>

### Step 2 — <action>
<command and explanation>

## PoC
<Proof of concept: exact request and response demonstrating the vulnerability>

Request:
<raw HTTP request>

Response:
<relevant part of server response>

## Risk
<Business impact: what an attacker can do, who is affected, what data is at risk>

## Remediation
<Concrete fix recommendations with references>
```

---

### Step 3 — Save the report

Save to `reports/report-<vuln-type>-<target>-<date>.md`

```bash
mkdir -p reports
```

### Step 4 — Display submission checklist

```
═══════════════════════════════════════════
 REPORT READY — Submission Checklist
═══════════════════════════════════════════
 ✅ Bug type selected (CWE)
 ✅ Scope set
 ✅ Endpoint filled
 ✅ Vulnerable part identified
 ✅ Payload included
 ✅ Technical environment: Linux, curl
 ⚠️  IPs used — fill with your actual IP
 ⚠️  CVSS vector — review and adjust
 ✅ Title written
 ✅ Description complete
 ✅ PoC included
 ✅ Remediation provided
═══════════════════════════════════════════
 Submit at: https://yeswehack.com/programs/<slug>/submit
═══════════════════════════════════════════
```

### Step 5 — Language check

Ensure the entire report is written in **English** only.
Check that:
- No French words remain
- Technical terms are correct
- The title is concise and clear
