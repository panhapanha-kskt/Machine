# Holmes CTF 2026: Sherlock 08 "Borrowed Name" (DIOGENES) — Full Writeup

**Educational Purpose Only** — This document details forensic analysis techniques and incident response methodology applied to a fictional Active Directory incident in the HTB Holmes CTF 2026 competition.

---

## Challenge Overview

**Challenge Name:** DIOGENES Active Directory Incident
**Difficulty:** Insane
**Scenario:** A sophisticated multi-stage attack chain targeting Active Directory infrastructure, involving C2 beacon deployment, local credential harvesting, privilege escalation via a custom Kerberos CVE, and lateral movement to a domain controller.

### Artifacts Provided
- Disk image: `Q3_Salary_Review.img` (FAT32 filesystem)
- Network capture: `capture.pcapng` (HTTP/TCP traffic)
- Event logs: `Microsoft-Windows-NTLM%4Operational.evtx`
- Supporting documentation: PDF describing attack phases (`Sherlock 08 - DIOGENES Active Directory Incident.pdf`, story chapters only, post-solve content locked)

---

## Investigation Methodology

### Phase 1: Initial Enumeration

Mount and examine the disk image for initial artifacts:

```bash
guestmount --ro -a Q3_Salary_Review.img -m /dev/sda1 /mnt/salary_img
ls -la /mnt/salary_img
```

**Files recovered:**
- `winupdate.exe` — C2 agent binary
- `version.dll` — DLL sideload vector
- `docviewer.exe` — Potential decoy/launcher
- `Salary_Review_Q3_2026.pdf.lnk` — Shortcut file (social engineering)
- `temp.pdf`, `README.txt` — Supporting files

The presence of both `winupdate.exe` and `version.dll` in the same directory strongly suggests **DLL search-order hijacking** — the executable looks for dependencies in its local directory first.

---

### Phase 2: Network Traffic Analysis — Finding the Beacon

```bash
tshark -r capture.pcapng -q -z follow,tcp,ascii,0 | grep "X-Beacon-Id"
```

**Sample beacon header:**
```
X-Beacon-Id: Cl7gY6So2/cT4yDjuRKh1/IIIliFthBvHdi8nHSIZZzsxjYE8JPn813viEOOLb5ZseRfO8DwChiYClLzDqjyf0eDVXoNvAc6Vfrqw/m0oGhyeHUBMdyO87QiBJ3T4BacpHsA0A2W8UW/vbcTyJE6BG+ByNMSSQMzNvQ=
```

Base64-encoded and encrypted — the key lives in the binary itself.

---

### Phase 3: Binary Analysis

```bash
r2 -A mnt/winupdate.exe
afl          # List all functions
izz          # Extract all strings
```

**Key findings:**
- No crypto imports → custom cipher implementation
- No direct exports → headless C2 agent
- Pipe reference: `\\.\pipe\%08lx`
- HTTP-based C2 communication

**High-entropy block found at offset 0x15904:**
```
4580221ac3fe51be1797524a048e552d
```

---

### Phase 4: Cryptographic Recovery (RC4 Profile Key)

```python
import base64

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

profile_key = bytes.fromhex("4580221ac3fe51be1797524a048e552d")
beacon_b64 = "Cl7gY6So2/cT4yDjuRKh1/IIIliFthBvHdi8nHSIZZzsxjYE8JPn813viEOOLb5ZseRfO8DwChiYClLzDqjyf0eDVXoNvAc6Vfrqw/m0oGhyeHUBMdyO87QiBJ3T4BacpHsA0A2W8UW/vbcTyJE6BG+ByNMSSQMzNvQ="
beacon_data = base64.b64decode(beacon_b64)
plaintext = rc4(profile_key, beacon_data)
print(plaintext.hex())
```

**Decoded first check-in:**
```
be4c0149 58debcbb                           <- Agent type ID, Beacon ID
00000010 53fc4c03c7b461befe5dcb268e3d9208   <- Session Key (16 bytes)
00000011 "core.diogenes.htb"                <- Domain
00000004 "WS02"                             <- Hostname
00000008 "afenwick"                         <- Username
0000000d "winupdate.exe"                    <- Process name
```

- **Profile Encryption Key:** `4580221ac3fe51be1797524a048e552d`
- **Agent-Generated Session Key:** `53fc4c03c7b461befe5dcb268e3d9208`
- **Agent Identity:** `afenwick` on `WS02` in domain `core.diogenes.htb`

---

### Phase 5: Decrypting Every C2 Task/Response Body

Rather than hand-picking frames, decrypt **every** HTTP body in the capture with the session key and dump printable strings per frame. This is what finally surfaced the Q6 evidence.

**Extraction helper (`http.txt`):** one line per HTTP frame, `frame#|method|json-or-hex-body`, produced from tshark HTTP object export + a small parser (frame numbers on the left match `tshark -Y http.request` frame numbers).

**`decrypt_all.py`:**
```python
import re

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

session_key = bytes.fromhex("53fc4c03c7b461befe5dcb268e3d9208")
text = open('http.txt', errors='ignore').read()

for line in text.splitlines():
    parts = line.split('|')
    if len(parts) < 3:
        continue
    frame = parts[0].split(':')[-1]
    body = parts[-1]
    m = re.search(r'"data":\s*"([0-9a-fA-F]+)"', body)
    hexdata = m.group(1) if m else None
    if not hexdata:
        continue
    try:
        raw = bytes.fromhex(hexdata)
    except ValueError:
        continue
    pt = rc4(session_key, raw)
    strs = re.findall(rb'[ -~]{6,}', pt)
    if strs:
        print(f"=== frame {frame} ===")
        for s in strs[:10]:
            print(' ', s.decode(errors='replace'))
```

```bash
python3 decrypt_all.py > result_decrypt.txt
grep -iE 'spray|brute|password|reset|new:|target|kerber|asrep' result_decrypt.txt
```

This produced readable BOF output for every task/response frame in one pass, which is what let every remaining flag (Q3, Q4, Q6, Q7, Q8, Q9, Q11) get confirmed directly from the decrypted plaintext instead of guesswork.

---

### Phase 6: BOF Payload Classification

| Frames | Purpose | Notes |
|---|---|---|
| 26/44/91 | Network recon BOF | `WS2_32`, `InetNtopW`, interface/route enumeration |
| 151/183/229/259/316/408/491 | LDAP recon (domain/user/computer enum, ACL dump) | Repeated task, same loader stub |
| **609** | **Local NetNTLMv2 hash extraction (SSPI)** | See Phase 7 — this is Q6 |
| 730/746 | ResetNightmare (UPN spoof + AS-REQ + kadmin/changepw) | ~70KB, CVE-2026-27912 |
| 823 | Token impersonation | `LogonUserW`, `BeaconUseToken` |
| 890/896 | Lateral movement / service hijack | SMB upload to `\\dc02\ADMIN$\svc_bkup`, hijacks `defragsvc` |

---

### Phase 7: Credential Theft — Q6, "Internal Monologue"

**Frame 611 (server response, decrypted):**
```
NTLMv2 Response:
afenwick::DIOCORE:1122334455667788:032b0b4aa446b7d68c6780135ef2ec24:0101000000000000b98318f89b40dd0188710ab71b4825d10000000008005000500000000000000000000000002...
```

This is a captured NetNTLMv2 hash for `afenwick`. Two details confirm exactly how it was obtained:

1. **The NTLM challenge is the well-known static value `1122334455667788`.** A real server always sends a random 8-byte challenge; this fixed value is the signature of a caller supplying its own challenge to a *local* SSPI negotiation rather than a live network server responding to a probe.
2. **`dec_609.bin` (the BOF behind frame 611) contains only SSPI/local Windows API imports** — no sockets, no listener code:

```bash
strings -a -n6 dec_609.bin | head -80
```
```
FormatNTLMv2Hash
%s::%s:%s:%s:%s
FormatNTLMv1Hash
ParseNTResponse: ...
GetNTLMCreds: ...
1122334455667788
__imp_SECUR32$AcquireCredentialsHandleA
__imp_SECUR32$InitializeSecurityContextA
```

`AcquireCredentialsHandleA` + `InitializeSecurityContextA`, fed a hardcoded challenge, asks the Windows NTLM security package (running as the logged-on user, `afenwick`) to compute *its own* NetNTLMv2 response — entirely in-process, no network traffic to a real authentication server. This is the **Internal Monologue Attack**: abusing SSPI locally to force the current user's NTLM security package to produce a crackable/relayable NetNTLMv2 response without touching LSASS memory or generating a real logon event.

**Timestamp correlation (two independent sources agree):**

*pcap — frame 611, the response carrying the hash:*
```bash
tshark -r capture.pcapng -Y "frame.number==611" -T fields -e frame.number -e frame.time
```
```
611   2026-09-10T03:44:11.702688213+0700
```
Converted to UTC (source is UTC+7): **2026-09-09 20:44:11**

*NTLM evtx — same second, same host, same process:*
```
2026-09-09 20:44:11.745 | EventID 4021 | afenwick | winupdate.exe
```

The local SSPI call inside `winupdate.exe` (running as afenwick) generates this NTLM evtx entry at the same moment frame 611 carries the resulting hash back to the C2 — confirming both the mechanism and the exact time.

**This hash is what feeds ResetNightmare.** Frame 749 (decrypted) states it outright:
```
[*] Sending AS-REQ to dc02.core.diogenes.htb:88 (RC4 pre-auth, key derived from afenwick's password)
```
The AS-REQ's RC4 pre-auth is only crackable/derivable because the attacker already had afenwick's NetNTLMv2 material from the Internal Monologue extraction — i.e. Q6 is the answer to "how did they get the password needed to perform ResetNightmare."

**Answer:**
```
Internal_Monologue:2026-09-09 20:44:11
```

---

### Phase 8: ResetNightmare — Q3/Q4/Q7/Q8/Q9 (CVE-2026-27912)

**Carving the BOF and hashing it (Q4):**

Frames 730 and 746 both decrypt to a 70,169-byte payload beginning with a Go-style COFF header. The task envelope wraps the COFF at a fixed offset; the length prefix confirms an exact carve:

```python
# carve.py dec_730.bin
import sys, struct, hashlib
d = open(sys.argv[1], 'rb').read()
print('whole blob md5:', hashlib.md5(d).hexdigest(), len(d))
for i in range(4, len(d) - 20):
    if d[i:i+2] == b'\x64\x86':
        ns = struct.unpack_from('<H', d, i+2)[0]
        sp, nsym = struct.unpack_from('<II', d, i+8)
        if 1 <= ns <= 30 and 0 < sp < len(d)-i and nsym < 20000:
            st = i + sp + nsym*18
            end = st + struct.unpack_from('<I', d, st)[0]
            b = d[i:end]
            print(f'off={i:#x} len={len(b)} u32_before={struct.unpack_from("<I", d, i-4)[0]} md5={hashlib.md5(b).hexdigest()}')
```
```bash
python3 carve.py dec_730.bin
# off=0x14 len=70169 u32_before=70169 md5=583236cc3ef2488fb133385bcd75825e
python3 carve.py dec_746.bin
# off=0x14 len=70169 u32_before=70169 md5=583236cc3ef2488fb133385bcd75825e   (same BOF, different args)
```

**Q4 answer:** `583236cc3ef2488fb133385bcd75825e`

**Task args tail (both frames), UTF-16LE decoded:**
```
/target:jreed /new:Aigohng8vai0seish4zi /upnuser:afenwick /upnpass:*Seash5lls*
```
(Frame 730 has a typo — `/targer:` — corrected in the re-run at frame 746.)

- **Q7** (creds used to perform the attack): `afenwick:*Seash5lls*`
- **Q8** (targeted user + resulting password): `jreed:Aigohng8vai0seish4zi`

**Frame 749 (decrypted) — full attack narration:**
```
[*] Action: ResetNightmare (CVE-2026-27912)
[*] UPN-write + enterprise AS-REQ + kadmin/changepw password reset
[*] Impersonating afenwick for LDAP operations
[*] Step 1: Setting fake UPN on afenwick -> jreed
[+] UPN set: afenwick -> jreed
[*] Step 2: AS-REQ enterprise for kadmin/changepw as jreed
[*] Sending AS-REQ to dc02.core.diogenes.htb:88 (RC4 pre-auth, key derived from afenwick's password)
[+] AS-REP received - KDC issued TGT for jreed
[+] TGT acquired (kadmin/changepw) for target
[*] Step 3: Clearing fake UPN from afenwick before changepw
```

**Q3 answer:** `CVE-2026-27912` (ResetNightmare)

**Frame 823 — token impersonation, confirming logon type (Q9):**
```
The user impersonated successfully: DIOCORE\jreed (logon: 9)
```
**Q9 answer:** `9`

---

### Phase 9: AD Permission Abuse — Q5

Security descriptor dump (frame 494 decrypted, 51 ACEs):
```
[*] Owner: S-1-5-21-2253468260-689643353-167204612-512
[*] Group: S-1-5-21-2253468260-689643353-167204612-512
```
```bash
strings -a dec_494_full.bin | grep -E 'CN=|S-1-5-21' | sort | uniq -c
```
```
51  ObjectSID  : S-1-5-21-2253468260-689643353-167204612-1125
51  ObjectDN   : CN=afenwick,OU=Analysts,OU=Staff,DC=core,DC=diogenes,DC=htb
```
`afenwick` has **self-write** (`WriteProperty`) on his own UPN attribute (`ObjectAceType GUID 28630ebb-41d5-11d1-a9c1-0000f80367c1`) — the property abused by ResetNightmare's UPN-spoof step.

**Q5 answer:** `S-1-5-21-2253468260-689643353-167204612-1125`

---

### Phase 10: Lateral Movement — Q10/Q11

**Frame 896 (decrypted):**
```
Trying to connect to dc02
Uploading binary (103936 bytes) to: \\dc02\ADMIN$\svc_bkup
Binary uploaded successfully (103936 bytes written)
SC_HANDLE Manager: 0x0000020AACB60FC0
Opening service: defragsvc
SC_HANDLE Service: 0x0000020AACB60A80
Original service binary path: "C:\Windows\system32\svchost.exe -k defragsvc"
Service path was changed to: "\\dc02\ADMIN$\svc_bkup"
Service was started
```

DC02's IP resolved from the beacon stream:
```bash
tshark -r capture.pcapng -Y 'http.request && http.request.line contains "X-Beacon-Id"' \
  -T fields -e ip.src -e tcp.stream | sort -u
```
```
192.168.56.11   1   <- DC02 (second beacon's stream)
192.168.56.22   0   <- WS02 (first beacon's stream)
```

**Q10 answer:** `\\192.168.56.11\ADMIN$\svc_bkup`
**Q11 answer:** `defragsvc`

---

### Phase 11: Second Beacon — Q1/Q2/Q12

```bash
tshark -r capture.pcapng -q -z follow,tcp,ascii,1 | grep "X-Beacon-Id"
```
```python
profile_key = bytes.fromhex("4580221ac3fe51be1797524a048e552d")
new_beacon_b64 = "Cl7gYyGw6OsT4yDjuRKh1/IIIliFthBvHdi8nHSSzaXAxjYny5Pn813viE+OLb5Zyokx9xmNd8GN3lrTwjie00eDVXoNvAc6Vfrqw/m0oGhyeHUBMdyO87QxFJ3T4Bacqkk/5jek1SbUvb9gs4UMCHGE3A=="
plaintext = rc4(profile_key, base64.b64decode(new_beacon_b64))
```
```
be4c0149 ddc68fa7                          <- Agent type ID, New Beacon ID
00000010 289122cf1ec91c67eb89c30642adfea4  <- New Session Key
00000011 "core.diogenes.htb"
00000004 "DC02"                            <- domain controller!
00000006 "SYSTEM"
00000008 "svc_bkup"                        <- the hijacked service, now the malicious binary
```

The `be4c0149` prefix is the **agent type ID**, shared across both beacons — it is not part of the beacon ID itself.

**Q1 answer:** `Adaptix` (beacon header format, pipe naming, HTTP framing, BOF staging pattern)
**Q2 answer:** `53fc4c03c7b461befe5dcb268e3d9208:4580221ac3fe51be1797524a048e552d`
**Q12 answer:** `ddc68fa7:289122cf1ec91c67eb89c30642adfea4`

---

## Complete Answer Key (12/12)

| # | Question | Answer |
|---|---|---|
| Q1 | C2 used for this attack | `Adaptix` |
| Q2 | SessionKey:EncryptionKey | `53fc4c03c7b461befe5dcb268e3d9208:4580221ac3fe51be1797524a048e552d` |
| Q3 | CVE used for privesc | `CVE-2026-27912` |
| Q4 | Custom BOF md5sum | `583236cc3ef2488fb133385bcd75825e` |
| Q5 | ObjectSID with WriteProperty right | `S-1-5-21-2253468260-689643353-167204612-1125` |
| Q6 | Named attack + timestamp used to get the password | `Internal_Monologue:2026-09-09 20:44:11` |
| Q7 | Credentials used to perform the attack | `afenwick:*Seash5lls*` |
| Q8 | Targeted user + resulting password | `jreed:Aigohng8vai0seish4zi` |
| Q9 | New token logon type after privesc | `9` |
| Q10 | Lateral movement upload path | `\\192.168.56.11\ADMIN$\svc_bkup` |
| Q11 | Service used to start the new agent | `defragsvc` |
| Q12 | New BeaconID:SessionKey | `ddc68fa7:289122cf1ec91c67eb89c30642adfea4` |

---

## Full Attack Chain Summary

1. **Initial access:** Phishing LNK (`Salary_Review_Q3_2026.pdf.lnk`) drops `winupdate.exe` + `version.dll` (DLL sideload) on `WS02`, running as `afenwick`.
2. **C2 establishment:** Adaptix beacon check-in, RC4-encrypted with a per-agent session key wrapped by a shared binary profile key.
3. **Recon:** Network config, LDAP domain/user/computer enumeration, ACL dump on `afenwick`'s own AD object.
4. **Credential theft (Q6):** **Internal Monologue** — local SSPI abuse (`AcquireCredentialsHandleA`/`InitializeSecurityContextA` with a fixed challenge `1122334455667788`) forces afenwick's own NTLM security package to emit a NetNTLMv2 response, captured entirely without network traffic to a real server or LSASS access. 2026-09-09 20:44:11 UTC.
5. **Privilege escalation (Q3/Q4/Q7/Q8/Q9):** **ResetNightmare (CVE-2026-27912)** — abuses afenwick's self-write UPN permission (Q5) to temporarily spoof his UPN to `jreed`, requests a Kerberos `kadmin/changepw` TGT (RC4 pre-auth derived from the harvested afenwick credential material), resets `jreed`'s password, then restores afenwick's real UPN. Resulting token is impersonated (logon type 9).
6. **Lateral movement (Q10/Q11):** SMB upload of `svc_bkup` to `\\192.168.56.11\ADMIN$`, hijacks the `defragsvc` service binary path, starts it (runs as SYSTEM), then restores the original path to cover tracks.
7. **Full compromise (Q1/Q2/Q12):** Second Adaptix beacon checks in from `DC02` running as `SYSTEM` — complete domain controller compromise.

---

## Key Forensic Techniques

1. **RC4 key reuse exploitation** — same profile key encrypts every beacon check-in; recovering it once from an in-binary high-entropy blob unlocks all future/past beacon headers.
2. **Bulk session-decrypt over an entire capture** — rather than hand-picking frames, decrypt every HTTP body with the recovered session key and grep the aggregate output; this is what actually surfaced Q6, since the single-frame guesses (LLMNR poisoning, NTLM relay, etc.) were all wrong.
3. **SSPI/local-only NTLM signatures** — a fixed/static challenge value (`1122334455667788`) plus `AcquireCredentialsHandle`/`InitializeSecurityContext` imports with no socket code is the fingerprint of Internal Monologue, distinguishing it from LLMNR poisoning, relay, or LSASS dumping.
4. **BOF carving via length-prefix validation** — matching the 4 bytes immediately preceding a COFF magic to the parsed symbol-table-derived length confirms an exact (not approximate) carve, critical for correct hash answers.
5. **Cross-source timestamp correlation** — pcap frame time (converted from local UTC+7 capture host to UTC) agreed with the NTLM evtx `SystemTime` for the same process/user/second, confirming both the mechanism and the exact attack time independently.

---

## Defensive Takeaways

1. **Monitor DLL loads** — detect unexpected sideloading via Sysmon/ETW.
2. **Detect Internal Monologue** — Sysmon can flag `InitializeSecurityContext` calls with attacker-controlled/static challenge values, or unusual local NTLM negotiation without a corresponding network authentication event.
3. **Service auditing** — alert on service binary path changes, especially rapid change-then-revert patterns (`ChangeServiceConfigA` called twice in quick succession).
4. **LDAP monitoring** — flag security descriptor reads/ACL enumeration at scale, and self-write UPN permissions as a standing misconfiguration to remediate.
5. **Credential hygiene** — remove self-write on schema attributes tied to authentication (UPN especially) to close off ResetNightmare-style attacks.
6. **Lateral movement prevention** — restrict `ADMIN$` access, monitor for `kadmin/changepw` AS-REQ traffic to unusual accounts.

---

**Document Version:** 2.0 (complete — 12/12 flags)
**Last Updated:** 2026-09-21
**Classification:** Educational - CTF Analysis
