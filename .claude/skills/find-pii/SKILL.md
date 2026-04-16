---
description: Find PII vulnerabilities in web applications. Use when testing for PII issues.
---

## High-Value PII Vulnerability Patterns

### Critical Endpoints & Parameters
```bash
# Metadata servers (AWS EC2/OpenStack)
curl -s "http://169.254.169.254/latest/meta-data/hostname" 2>/dev/null
curl -s "http://169.254.169.254/latest/user-data" 2>/dev/null

# GraphQL PII exposure
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"query {team(handle:\"TARGET\"){whitelisted_hackers{total_count}}}"}' \
  https://target.com/graphql

# User enumeration via API
curl -s "https://target.com/api/v1/s/user/me" -H "Authorization: Bearer TOKEN"
curl -s "https://target.com/_/api/1.0/invitation_request.json" -d "email=test@test.com&full_name=1&full_name=2"

# Export/download endpoints
curl -s "https://target.com/do_action-export-[TIMESTAMP]/"
curl -s "https://target.com/?p=[ID]" | grep -i "export\|download\|csv"
```

### Common Vulnerable Parameters
- `full_name`, `email`, `user_id`, `handle`, `sig_gen`
- `author`, `p` (page ID), `formAction`, `shareToken`
- `insp_pingurln`, `folder`, `nbyte`, `len`

### PII-Exposing File Patterns
```bash
# Configuration files
curl -s "https://target.com/readme.html"
curl -s "https://target.com/wp-content/plugins/*/readme.txt"
curl -s "https://target.com/mysql.initial.sql"

# CSS debug info
curl -s "https://target.com/assets/application-*.css" | grep -oP "file.:.*?scss"

# Directory listings
curl -s "https://target.com/" | grep -i "index of\|directory listing"
```

## Step-by-Step Testing Methodology

### 1. Metadata Server Discovery
```bash
# Test AWS/OpenStack metadata
echo "Testing metadata servers..."
for endpoint in hostname public-ipv4 local-ipv4 security-groups user-data; do
  response=$(curl -s -m 5 "http://169.254.169.254/latest/meta-data/$endpoint" 2>/dev/null)
  if [[ -n "$response" && "$response" != "404"* ]]; then
    echo "FOUND: $endpoint - $response"
  fi
done
```

### 2. GraphQL PII Enumeration
```bash
# Test GraphQL for PII exposure
test_graphql_pii() {
  local target=$1
  
  # Test team information disclosure
  curl -X POST -H "Content-Type: application/json" \
    -d '{"query":"query Team($handle:String!){team(handle:$handle){id,name,whitelisted_hackers{total_count},vpn_suspended}}","variables":{"handle":"'$target'"}}' \
    https://$target/graphql 2>/dev/null | jq .
    
  # Test user enumeration
  curl -X POST -H "Content-Type: application/json" \
    -d '{"query":"query {me{id,email,username}}"}' \
    https://$target/graphql 2>/dev/null | jq .
}
```

### 3. WordPress User Enumeration
```bash
# Enumerate WordPress users
enumerate_wp_users() {
  local target=$1
  echo "Enumerating WordPress users on $target..."
  
  for i in {1..20}; do
    response=$(curl -s -L "https://$target/?author=$i")
    username=$(echo "$response" | grep -oP 'author/\K[^/]+' | head -1)
    if [[ -n "$username" ]]; then
      echo "User ID $i: $username"
    fi
  done
}
```

### 4. API Endpoint PII Discovery  
```bash
# Test common API endpoints for PII
test_api_pii() {
  local target=$1
  
  # Platform APIs
  curl -s "https://$target/api/v1/s/user/me" -H "Cookie: session=test"
  curl -s "https://$target/api/v5/user/" -H "Authorization: Bearer test"
  
  # Form handlers with parameter pollution
  curl -X POST "https://$target/_/api/1.0/invitation_request.json" \
    -d "email=test@test.com&full_name=1&full_name=2" 2>/dev/null
    
  # Export endpoints
  curl -s "https://$target/sidekiq/scheduled" | grep -i "email\|user"
}
```

### 5. File/Directory Exposure Detection
```bash
# Check for exposed sensitive files
check_exposed_files() {
  local target=$1
  
  files=("readme.html" "wp-content/plugins/all-in-one-seo-pack/readme.txt" 
         "mysql.initial.sql" ".env" "config.php" "database.yml")
         
  for file in "${files[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "https://$target/$file")
    if [[ "$response" == "200" ]]; then
      echo "EXPOSED FILE: https://$target/$file"
      curl -s "https://$target/$file" | head -20
    fi
  done
}
```

### 6. Export/Download PII Discovery
```bash
# Search for CSV/export endpoints with PII
find_export_pii() {
  local target=$1
  
  # Test numeric page enumeration
  for id in {1000..2000..100}; do
    location=$(curl -s -o /dev/null -w "%{redirect_url}" "https://$target/?p=$id")
    if [[ "$location" == *"export"* ]]; then
      echo "EXPORT FOUND: $location"
      curl -s "$location" | head -5 | grep -i "name,email,phone"
    fi
  done
  
  # Test timestamp-based exports
  for year in 2023 2024; do
    timestamp=$(date -d "$year-01-01" +%s)
    curl -s "https://$target/do_action-export-$timestamp/" | grep -i "csv\|download"
  done
}
```

## Complete Testing Script
```bash
#!/bin/bash

test_pii_vulnerabilities() {
  local target=$1
  
  echo "=== PII Vulnerability Testing for $target ==="
  
  # 1. Metadata servers
  echo "[1] Testing metadata servers..."
  curl -s -m 5 "http://169.254.169.254/latest/user-data" 2>/dev/null && echo "AWS metadata accessible!"
  
  # 2. GraphQL enumeration  
  echo "[2] Testing GraphQL PII exposure..."
  curl -X POST -H "Content-Type: application/json" \
    -d '{"query":"query{me{email}}"}' \
    "https://$target/graphql" 2>/dev/null | grep -i email
    
  # 3. WordPress users
  echo "[3] WordPress user enumeration..."
  for i in {1..5}; do
    curl -s -L "https://$target/?author=$i" | grep -oP 'author/\K[^/]+' | head -1
  done
  
  # 4. API endpoints
  echo "[4] Testing API endpoints..."
  curl -s "https://$target/api/v1/s/user/me" | grep -i "email\|user"
  
  # 5. Exposed files
  echo "[5] Checking exposed files..."
  for file in readme.html mysql.initial.sql .env; do
    [[ $(curl -s -o /dev/null -w "%{http_code}" "https://$target/$file") == "200" ]] && echo "FOUND: $file"
  done
  
  # 6. Export endpoints
  echo "[6] Searching for export endpoints..."
  curl -s "https://$target/" | grep -oiP 'href="[^"]*export[^"]*"'
  
  echo "=== Testing complete ==="
}
```

## Severity Rating Table

| Vulnerability Type | Severity | CVSS Range |
|-------------------|----------|------------|
| AWS metadata access (user-data) | Critical | 9.0-10.0 |
| Database dumps with PII | Critical | 8.5-9.5 |
| CSV exports with PII (names, emails, phones) | High | 7.0-8.5 |
| GraphQL user enumeration | High | 6.5-8.0 |
| WordPress user enumeration | Medium | 4.0-6.5 |
| Version disclosure | Low | 2.0-4.0 |
| Path disclosure in errors | Medium | 4.5-6.0 |
| Internal statistics disclosure | Medium | 5.0-7.0 |

## False Positives to Ignore

- Empty metadata responses (404/timeout)
- Version numbers in public documentation
- Generic error messages without paths
- Public user profiles (intended disclosure)
- Empty GraphQL responses
- WordPress author pages with display names only
- CSS source maps in development environments

## Finding Report Template

```markdown
## PII Disclosure Vulnerability

**Severity:** [Critical/High/Medium/Low]
**CVSS Score:** X.X
**Vulnerability Type:** Information Disclosure - PII

### Summary
Brief description of PII disclosed and access method.

### Steps to Reproduce
1. Navigate to https://target.com/[endpoint]
2. Execute: `curl -s "https://target.com/[endpoint]" | grep -i "email\|name\|phone"`
3. Observe disclosed PII in response

### Proof of Concept
```bash
curl -s "https://target.com/vulnerable-endpoint"
```

**Response:**
```json
{"users":[{"name":"John Doe","email":"john@company.com","phone":"555-1234"}]}
```

### Impact
- Unauthorized access to user PII (names, emails, phone numbers)
- Potential for targeted phishing attacks
- Privacy violation affecting X users
- GDPR/CCPA compliance violations

### Affected Endpoints
- https://target.com/api/users/export
- https://target.com/admin/csv-download

### Remediation
1. Implement proper authentication for PII endpoints
2. Add rate limiting to prevent enumeration
3. Remove PII from error messages
4. Audit all export functionalities

### References
- CWE-200: Information Exposure
- OWASP A3: Sensitive Data Exposure
```