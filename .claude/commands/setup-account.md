---
description: Create test accounts and store sessions for authenticated testing. Usage: /setup-account <target>
---

# Setup Test Accounts

Create and authenticate test accounts for authenticated vulnerability testing.
Manages two accounts: attacker (account_1) and victim (account_2) for IDOR testing.

## Instructions

Given the target in $ARGUMENTS:

### Step 1 — Read program context

```bash
cat CLAUDE.md
```

Check the account_access section:
- Does the program allow account creation?
- Are there specific naming/alias requirements?
- If account creation is forbidden → inform the user and stop.

### Step 2 — Ask for test email alias

Ask the user:
```
What is your bug bounty platform email alias?
Examples:
  YesWeHack : yourhandle-xxxx@yeswehack.ninja
  HackerOne : yourhandle+test@wearehackerone.com

This alias will be used as base for both test accounts.
```

Wait for the user to provide their alias before continuing.

### Step 3 — Generate test identities

Using the provided alias as base:
```bash
SUFFIX=$(date +%s | tail -c 5)
ALIAS="<user_provided_alias>"  # e.g. handle-xxxx@yeswehack.ninja

# Extract base and domain
BASE=$(echo $ALIAS | cut -d@ -f1)
DOMAIN=$(echo $ALIAS | cut -d@ -f2)

ACCOUNT1_EMAIL="${BASE}+attacker${SUFFIX}@${DOMAIN}"
ACCOUNT2_EMAIL="${BASE}+victim${SUFFIX}@${DOMAIN}"
ACCOUNT1_PASS="BbTest_$(openssl rand -hex 8)!"
ACCOUNT2_PASS="BbTest_$(openssl rand -hex 8)!"
```

### Step 4 — Discover registration endpoint

```bash
curl -s -A "<user_agent_from_CLAUDE.md>" "https://<target>" | \
  grep -iE '(register|signup|create.account)' | head -10

for path in /register /signup /user/register /account/create /join; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -A "<user_agent>" "https://<target>${path}")
  echo "$path → $STATUS"
done
```

### Step 5 — Create Account 1 (attacker)

```bash
mkdir -p accounts

# Fetch registration page for form tokens
curl -s -A "<user_agent>" \
  "https://<target>/register" \
  -c /tmp/reg1.txt -o /tmp/reg1.html

# Extract form tokens
grep -oP 'name="[^"]*" value="[^"]*"' /tmp/reg1.html | head -20

# Submit registration — adapt fields to what was discovered
curl -s -A "<user_agent>" \
  -X POST "https://<target>/register" \
  -b /tmp/reg1.txt -c /tmp/reg1.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "email=${ACCOUNT1_EMAIL}&password=${ACCOUNT1_PASS}&name=BugBounty+TEST&<other_fields>"
```

Add any program-required mention to free text fields (check account_access in CLAUDE.md).

### Step 6 — Create Account 2 (victim)

Same process with `ACCOUNT2_EMAIL` and `ACCOUNT2_PASS`.

### Step 7 — Authenticate both accounts

```bash
# Login Account 1
curl -s -A "<user_agent>" \
  "https://<target>/login" \
  -c /tmp/session1.txt -o /tmp/login1.html

curl -s -A "<user_agent>" \
  -X POST "https://<target>/login" \
  -b /tmp/session1.txt -c /tmp/session1.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "email=${ACCOUNT1_EMAIL}&password=${ACCOUNT1_PASS}&<tokens>" \
  -L -o /tmp/after_login1.html

# Verify login success
grep -iE '(logout|dashboard|my.account|profile)' /tmp/after_login1.html | head -3

# Extract user ID if visible
grep -oP '"user_id":\s*\K[0-9]+' /tmp/after_login1.html | head -1
grep -oP '"id":\s*\K[0-9]+' /tmp/after_login1.html | head -1

# Extract auth token if API-based
grep -oP '"token":"[^"]*"' /tmp/after_login1.html | head -1

# Repeat for Account 2
```

### Step 8 — Save to accounts/<target>.json

```bash
mkdir -p accounts
```

Write `accounts/<target>.json`:
```json
{
  "target": "<target>",
  "created_at": "<date>",
  "user_agent": "<from CLAUDE.md>",
  "account1": {
    "role": "attacker",
    "email": "<ACCOUNT1_EMAIL>",
    "password": "<ACCOUNT1_PASS>",
    "user_id": "<extracted_id>",
    "token": "<extracted_token_or_null>",
    "cookie_file": "/tmp/session1.txt",
    "login_endpoint": "<discovered_login_url>"
  },
  "account2": {
    "role": "victim",
    "email": "<ACCOUNT2_EMAIL>",
    "password": "<ACCOUNT2_PASS>",
    "user_id": "<extracted_id>",
    "token": "<extracted_token_or_null>",
    "cookie_file": "/tmp/session2.txt",
    "login_endpoint": "<discovered_login_url>"
  }
}
```

### Step 9 — Verify sessions

```bash
# Confirm both sessions work
curl -s -A "<user_agent>" "https://<target>/profile" \
  -b /tmp/session1.txt -o /dev/null -w "Account 1: %{http_code}\n"

curl -s -A "<user_agent>" "https://<target>/profile" \
  -b /tmp/session2.txt -o /dev/null -w "Account 2: %{http_code}\n"
```

### Step 10 — Confirm to user

Tell the user:
- Both accounts created and authenticated
- Credentials saved to `accounts/<target>.json`
- Run `/hunt-auth <target>` to start authenticated testing

### Step 11 — Handle failures

If registration requires email verification:
- Inform the user and provide exact curl commands
- Ask user to confirm email and provide the verified session cookie

If the program forbids account creation:
- Read CLAUDE.md account_access and explain
- Stop without creating accounts
