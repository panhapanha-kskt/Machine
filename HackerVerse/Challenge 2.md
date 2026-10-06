# HackerVerse September 2026 — Level 2: Network Intrusion Forensics

> **Challenge:** ChatOps Breached — Synixon Technologies
> **Platform:** Kali Linux VM (`root` / `toor`)
> **Artifact:** `/root/Pcap Artifacts/synixon_breach_capture.pcapng`
> **Date solved:** 2026-10-05
> **Tools:** `tshark`, `strings`, `grep`

---

## Answer Summary

| # | Challenge | Answer |
|---|-----------|--------|
| 1 | Attacker's initial signup email | `root@hacker.com` |
| 2 | Supervisor email whose password was reset | `tony@synixon.com` |
| 3 | LFI-vulnerable debug page filename | `debug-view.php` |
| 4 | Log file accessed via LFI | `legacy_dev_keys.log` |
| 5 | New admin account email | `admin@hacker.com` |
| 6 | Port of the newly discovered web service | `17645` |
| 7 | Hidden admin login page filename | `admin_login_ERHG23W2.php` |
| 8 | Legacy feedback service port | `5000` |
| 9 | Reverse shell callback (IP:port) | `10.10.1.2:8998` |
| 10 | Root flag | `flag{A1EL2L8P}` |

---

## Setup

```bash
cd "/root/Pcap Artifacts"
F=synixon_breach_capture.pcapng       # save retyping the long name; use $F
```

Hosts in the capture:
- `10.10.1.111` — Synixon ChatOps server (victim)
- `10.10.1.2` — attacker

---

## The four commands that cracked the whole level

### 1. All email addresses (Challenges 1, 2, 5)
```bash
strings $F | grep -oiE '[a-z0-9._-]+@[a-z0-9.-]+\.[a-z]+' | sort | uniq -c
```
```
      3 admin@hacker.com
      1 john@synixon.com
      2 tony@synixon.com
```

### 2. URL-encoded form posts — signup / login (Challenges 1, 5)
```bash
strings $F | grep -i '%40'
```
```
user_name=i_am_hacker&user_mail=root%40hacker.com&user_pass=hack%40123&signup=
user_mail=root%40hacker.com&user_pass=hack%40123&signin=
user_mail=tony%40synixon.com&user_pass=hackpass&signin=
user_mail=admin%40hacker.com&user_pass=adminhack%40123&signin=
```
`%40` is the URL-encoding of `@`. This is why `strings | grep @` missed the signup email.

### 3. Ports with new SYN connections (Challenges 6, 8)
```bash
tshark -r $F -Y 'tcp.flags==0x002' -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c
```
```
      1 10.10.1.111     10.10.1.2       8998     <- reverse shell (server -> attacker)
      5 10.10.1.2       10.10.1.111     17645    <- hidden admin panel
     49 10.10.1.2       10.10.1.111     5000     <- Flask/legacy-feedback
     18 10.10.1.2       10.10.1.111     80        <- main ChatOps site
```

### 4. HTTP requests — the exploitation chain (Challenges 3, 4, 7)
```bash
tshark -r $F -Y http.request -T fields -e tcp.dstport -e http.request.method -e http.request.uri | uniq
```
Key lines:
```
80     GET   /syni_dev/debug-view.php?file=history.php
80     GET   /syni_dev/debug-view.php?file=../../../../../../../etc/passwd
80     GET   /syni_dev/debug-view.php?file=../../../../../../../opt/syni_dev/legacy_dev_keys.log
17645  GET   /admin_login_ERHG23W2.php
17645  POST  /admin_login_ERHG23W2.php
17645  GET   /admin_audit.php?filter=legacy&trace=true
5000   GET   /legacy-feedback
5000   GET   /legacy-feedback?__debugger__=yes&cmd=resource&f=debugger.js
5000   POST  /legacy-feedback
```

### 5. Flag + reverse shell indicators (Challenges 9, 10)
```bash
strings $F | grep -iE 'flag\{|dev/tcp|bash -i|nc -e|mkfifo|python -c'
```
```
flag{A1EL2L8P}
flag{A1EL2L8P}
```

### 6. Decode the WebSocket chat (Challenge 2)
WebSocket frames from the browser are masked, so `strings` won't show them — `tshark` unmasks them:
```bash
tshark -r $F -Y websocket -V | grep -iE '@|reset|password'
```
Relevant messages:
```
bot: "There is only one supervisor account available: tony@synixon.com"
root@hacker.com: "reset-password"
bot: "Use the format: reset-password:your_new_password"
tony@synixon.com: "reset-password:hackpass"
bot: "Password changed for tony@synixon.com."
...
tony@synixon.com: "alphaadmin:insert:admin@hacker.com"
bot: "Enter password for admin@hacker.com."
tony@synixon.com: "adminhack@123"
bot: "Enter role for admin@hacker.com."
tony@synixon.com: "admin"
bot: "User admin@hacker.com created as admin."
```

---

## Detailed answers

### Challenge 1 — `root@hacker.com`
Signup POST on port 80: `user_name=i_am_hacker&user_mail=root%40hacker.com&user_pass=hack%40123&signup=`.
The attacker registered as a technician using `root@hacker.com`.

### Challenge 2 — `tony@synixon.com`
The chatbot revealed tony as the only supervisor. The WebSocket chat **trusts the client-supplied `user` field**, so the attacker sent `reset-password:hackpass` claiming to be `tony@synixon.com`; the bot confirmed "Password changed for tony@synixon.com."

### Challenge 3 — `debug-view.php`
`/syni_dev/debug-view.php?file=...` is the LFI entry point (not `dev-debug.php`, which doesn't fit the `xxxxx-xxxx.xxx` mask and wasn't the vulnerable parameter page).

### Challenge 4 — `legacy_dev_keys.log`
`/syni_dev/debug-view.php?file=../../../../../../../opt/syni_dev/legacy_dev_keys.log` — traversal to read the dev key log.

### Challenge 5 — `admin@hacker.com`
Created via the hidden `alphaadmin:insert:admin@hacker.com` chat override command → "User admin@hacker.com created as admin."

### Challenge 6 — `17645`
After the admin login, a new web service answers on port 17645 (hidden admin panel `admin_login_ERHG23W2.php`, `admin_dashboard.php`, `admin_audit.php`, `admin_legacy_logs.php`).

### Challenge 7 — `admin_login_ERHG23W2.php`
GET and POST seen on port 17645 — the hidden admin login page.

### Challenge 8 — `5000`
The legacy feedback service runs on non-standard port 5000 (`/legacy-feedback`), a Flask app with the **Werkzeug debugger exposed** (`?__debugger__=yes&cmd=resource&...`), which is the RCE vector.

### Challenge 9 — `10.10.1.2:8998`
The only outbound connection from the server (`10.10.1.111`) is a SYN to `10.10.1.2:8998` — the reverse shell callback triggered through the Werkzeug debugger console.
Optional confirmation:
```bash
tshark -r $F -Y 'urlencoded-form' -T fields -e urlencoded-form.value | grep -iE '8998|10\.10'
```

### Challenge 10 — `flag{A1EL2L8P}`
Read in plaintext from the reverse-shell traffic; matches the `flag{XNXXNXNX}` mask.

---

## Attack chain (reconstruction)

1. **Foothold:** attacker signs up as technician `root@hacker.com`.
2. **Chatbot recon + IDOR:** bot discloses supervisor `tony@synixon.com`; the WebSocket `reset-password` feature trusts the client `user` field → attacker resets tony's password and logs in as supervisor.
3. **LFI:** as supervisor, `debug-view.php?file=` reads `/etc/passwd` and `/opt/syni_dev/legacy_dev_keys.log`.
4. **Privilege escalation:** hidden `alphaadmin:insert:` chat command creates admin `admin@hacker.com`.
5. **Pivot:** admin finds a hidden panel on **port 17645** (`admin_login_ERHG23W2.php`); its audit logs point to `/legacy-feedback` on **port 5000**.
6. **RCE:** exposed Werkzeug debug console on `/legacy-feedback` runs a reverse shell to **10.10.1.2:8998** → root → reads `flag{A1EL2L8P}`.

---

## Lessons learned
- `strings` misses URL-encoded (`%40`) and masked WebSocket data — use `tshark -Y websocket -V` for chat apps.
- Classic triage: enumerate emails, SYN'd ports, and HTTP requests first; much of a web-based intrusion is readable text.
- Trusting client-supplied identity fields (the WebSocket `user`) is an auth bypass / IDOR.
- An exposed Werkzeug debugger (`__debugger__=yes`) is instant RCE.
