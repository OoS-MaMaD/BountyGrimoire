---
description: Find REFERER vulnerabilities in web applications. Use when testing for REFERER issues.
---

# REFERER Vulnerability Testing

This skill tests for information disclosure through HTTP Referer header leakage, including CSRF tokens, sensitive parameters, and private URLs.

## High-Value Patterns from Reports

### Parameter Names
- `formName`, `formAction`, `sig_gen`, `insp_pingurln`
- Authentication tokens: `csrf_token`, `_token`, `authenticity_token`
- Session identifiers: `sid`, `sessionid`, `PHPSESSID`
- User data: `uid`, `user_id`, `email`, `username`
- Action parameters: `redirect_url`, `next`, `return_to`

### Vulnerable Endpoint Patterns
- `/login`, `/signin`, `/auth/*`
- `/_/api/*`, `/api/v*/user/me`
- `/dashboard`, `/settings/*`
- `/*?shareToken=*`, `/*?invite=*`
- Form processors: `/form`, `/submit`, `/*formAction=*`

### Sensitive Headers/Tokens
- `Authorization`, `Proxy-Authorization`
- `X-CSRF-Token`, `X-Requested-With`
- Custom auth headers: `X-Auth-Token`, `X-API-Key`

## Testing Methodology

### Step 1: Discover Login and Sensitive Endpoints

```bash
# Find login endpoints
curl -s "$TARGET" | grep -oP 'action="[^"]*' | sed 's/action="//' | grep -E '(login|signin|auth)'

# Find API endpoints in JavaScript
curl -s "$TARGET" | grep -oP '["'"'"'][^"'"'"']*api[^"'"'"']*["'"'"']' | sort -u

# Find form endpoints
curl -s "$TARGET" | grep -oP 'action="[^"]*' | sed 's/action="//' | sort -u

# Check robots.txt for sensitive paths
curl -s "$TARGET/robots.txt" | grep -E '^(Disallow|Allow):' | awk '{print $2}'
```

### Step 2: Test for CSRF Token Leakage via GET

```bash
# Test login with GET method
LOGIN_URL="$TARGET/login"
curl -sI -X GET "$LOGIN_URL?username=test&password=test&csrf_token=abc123" \
  -H "Referer: https://external-site.com" | grep -i location

# Test if login accepts GET parameters
curl -s "$LOGIN_URL?email=test@test.com&_token=sensitive123" \
  -H "Referer: https://attacker.com" -o /tmp/login_response.html

# Check if sensitive data appears in URL
grep -i "token\|csrf\|session" /tmp/login_response.html
```

### Step 3: Test Referer Leakage to External Sites

```bash
# Create test page that loads external resources
cat > /tmp/referer_test.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <script src="https://external-analytics.com/track.js"></script>
    <img src="https://cdn.example.com/pixel.gif" />
    <link rel="stylesheet" href="https://fonts.googleapis.com/css" />
</head>
<body>
    <a href="https://external-site.com">Click me</a>
</body>
</html>
EOF

# Test for referer policy
curl -s "$TARGET" | grep -i "referrer-policy\|referer-policy"

# Test cross-origin referer leakage
curl -sI "$TARGET/sensitive-page?token=secret123" \
  -H "Referer: https://attacker.com" | grep -i referrer-policy
```

### Step 4: Test Redirect-Based Referer Leakage

```bash
# Test open redirect with sensitive referer
SENSITIVE_URL="$TARGET/dashboard?csrf_token=abc123&user_id=456"
curl -sL -H "Referer: $SENSITIVE_URL" \
  "$TARGET/redirect?url=https://attacker.com" \
  -w "Final URL: %{url_effective}\n"

# Test parameter pollution for redirect bypass
curl -sL "$TARGET/logout?next=https://attacker.com&return_to=https://safe-site.com"
```

### Step 5: Test API Endpoint Referer Leakage

```bash
# Test API endpoints with sensitive referers
API_ENDPOINTS="/api/v1/user/me /api/user /api/profile /_/api/1.0/invitation_request.json"

for endpoint in $API_ENDPOINTS; do
  echo "Testing $TARGET$endpoint"
  curl -s "$TARGET$endpoint" \
    -H "Referer: $TARGET/settings?api_key=secret123&token=sensitive" \
    -H "X-Requested-With: XMLHttpRequest" | head -20
done
```

### Step 6: Test Authentication Header Leakage

```bash
# Test cross-origin request with auth headers
curl -s "https://external-api.com/endpoint" \
  -H "Authorization: Bearer sensitive_token" \
  -H "Proxy-Authorization: Basic dXNlcjpwYXNz" \
  -H "Referer: $TARGET/dashboard?session=abc123" \
  -w "Response code: %{http_code}\n"
```

## Concrete Testing Examples

### Test 1: CSRF Token in Login URL
```bash
TARGET="https://example.com"

# Check if login uses GET
curl -s "$TARGET/login?email=test@test.com&password=test&_token=csrf123" \
  | grep -i "invalid\|error\|welcome\|dashboard"

# Test referer leakage
curl -s "$TARGET/login" -H "Referer: $TARGET/page?_token=sensitive" \
  | grep -oP '_token[^&]*'
```

### Test 2: Private Share Link Enumeration
```bash
# Test workspace/share endpoints  
curl -H "OCS-APIREQUEST: true" \
  "$TARGET/ocs/v2.php/apps/text/public/workspace?shareToken=TESTTOKEN123" \
  -H "Referer: $TARGET/admin?session_id=admin123"
```

### Test 3: Invitation Code Enumeration
```bash
# Test invite code pattern
CODES="a1b2c 3d4e5 f6g7h"
for code in $CODES; do
  RESPONSE=$(curl -s "$TARGET/invite/$code" -H "Referer: $TARGET/dashboard?user_id=123")
  if echo "$RESPONSE" | grep -q "free gift from\|Sign up now"; then
    echo "Valid invite code: $code"
  fi
done
```

## Severity Rating Table

| Impact | Criteria | Example |
|--------|----------|---------|
| **Critical** | Auth tokens/API keys leaked to external domains | CSRF tokens in GET params with external JS |
| **High** | Session IDs, user credentials exposed via referer | Login URLs with passwords in query string |
| **Medium** | Internal structure, private URLs disclosed | Share tokens, invitation codes enumerable |
| **Low** | Version info, non-sensitive paths exposed | Software versions, public endpoint structure |
| **Info** | General application behavior | Redirect patterns, form structures |

## False Positives to Ignore

```bash
# These are typically not vulnerabilities:
grep -v "cache-control\|expires\|last-modified" results.txt
grep -v "Content-Security-Policy.*upgrade-insecure-requests" results.txt  
grep -v "X-Frame-Options.*SAMEORIGIN" results.txt
# Version disclosure in common locations (unless critical infrastructure)
grep -v "nginx/1\.\|Apache/2\.\|PHP/[0-9]" results.txt
# Standard WordPress author enumeration (unless sensitive usernames)
grep -v "wp-content/themes\|/?author=[0-9]" results.txt
```

## Automated Testing Script

```bash
#!/bin/bash
test_referer_leakage() {
  local target="$1"
  echo "=== Testing Referer Leakage for $target ==="
  
  # Test 1: Login endpoints
  echo "1. Testing login endpoints..."
  curl -s "$target" | grep -oP 'action="[^"]*' | while read -r endpoint; do
    endpoint=$(echo "$endpoint" | sed 's/action="//')
    if [[ "$endpoint" =~ (login|signin|auth) ]]; then
      curl -sI "$target$endpoint?test=1&_token=test123" \
        -H "Referer: https://attacker.com" | grep -i location
    fi
  done
  
  # Test 2: API endpoints
  echo "2. Testing API endpoints..."
  for api in "/api/user/me" "/_/api/1.0/user" "/api/v1/profile"; do
    curl -s "$target$api" -H "Referer: $target/settings?api_key=test123" \
      | head -5 | grep -i "error\|unauthorized\|user\|email"
  done
  
  # Test 3: Redirect testing
  echo "3. Testing redirects..."
  curl -sL "$target/?next=https://attacker.com" \
    -H "Referer: $target/dashboard?session=abc123" \
    -w "Final URL: %{url_effective}\n"
}

# Usage: test_referer_leakage "https://example.com"
```

## Finding Report Template

```markdown
## REFERER Information Disclosure

**Vulnerability Type:** Information Disclosure via HTTP Referer Header
**Severity:** [Critical/High/Medium/Low]
**Endpoint:** [URL]

### Description
The application leaks sensitive information through the HTTP Referer header when [specific scenario].

### Steps to Reproduce
1. Navigate to: `[SENSITIVE_URL_WITH_PARAMS]`
2. Click on external link or trigger redirect to: `[EXTERNAL_URL]`
3. Observe referer header contains: `[SENSITIVE_DATA]`

### Proof of Concept
```bash
curl -s "[ENDPOINT]" \
  -H "Referer: [SENSITIVE_REFERER_URL]" \
  | grep -E "(token|session|api_key)"
```

### Impact
- Exposure of CSRF tokens to external sites
- Session hijacking via leaked session IDs  
- API key compromise leading to unauthorized access
- Privacy violation through URL parameter leakage

### Recommendation
1. Implement `Referrer-Policy: no-referrer` for sensitive pages
2. Use POST method for authentication with tokens in request body
3. Avoid sensitive data in URL parameters
4. Validate referer headers for state-changing operations

### References
- [OWASP Referrer Policy Cheat Sheet]
- [RFC 7231 - Referer Header Field]
```