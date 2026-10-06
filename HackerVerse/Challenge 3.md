# HackerVerse September 2026 — Level 3: Windows Credential Forensics

> **Challenge:** The ChromeCracker
> **Platform:** Windows Forensic VM (`LabUser` / `Passw0rd!`)
> **Artifact:** `chrome_cracker.zip` on the Desktop → contains `lsass.DMP` + `Google.zip` (Chrome profile)
> **Date:** 2026-10-05
> **Goal:** recover the credentials saved for `chaincrypto.com` by decrypting the Chrome DPAPI/AES key chain.

---

## Answer Summary

| # | Challenge | Answer | Status |
|---|-----------|--------|--------|
| 1 | Tool used to extract the MasterKey from `lsass.DMP` | `Mimikatz` | ✅ |
| 2 | Chrome file holding the Base64 `encrypted_key` | `Local State` | ✅ |
| 3 | Attacker's Windows username | `Admin` | ✅ (see note) |
| 4 | First 10 chars of the masterkey | `9c3bca41e3` | ✅ |
| 5 | First 10 chars of the Final Secret Key | `ab6f2709e6` (true AES key) — **mask conflict, see below** | ⚠️ open |
| 6 | chaincrypto.com username / password | *(pending Login Data decryption)* | ⏳ |

---

## Setup

```powershell
cd $env:USERPROFILE\Desktop
Expand-Archive chrome_cracker.zip -DestinationPath chrome_cracker -Force
Expand-Archive .\chrome_cracker\Google.zip -DestinationPath .\chrome_cracker\Google -Force
Get-ChildItem -Recurse .\chrome_cracker | Select FullName, Length
```
Contents:
- `chrome_cracker\lsass.DMP` (≈55 MB) — LSASS memory dump
- `chrome_cracker\Google\Google\Chrome\User Data\Local State` — holds `os_crypt.encrypted_key`
- `...\User Data\Default\Login Data` — SQLite DB of saved logins

Key paths:
```
Local State: C:\Users\LabUser\Desktop\chrome_cracker\Google\Google\Chrome\User Data\Local State
Login Data : C:\Users\LabUser\Desktop\chrome_cracker\Google\Google\Chrome\User Data\Default\Login Data
```

---

## Challenge 1 — Tool: `Mimikatz`
The standard tool to pull a DPAPI MasterKey from an LSASS dump. Prefetch on this VM confirms it ran:
```powershell
Get-ChildItem C:\ -Recurse -Filter *mimikatz* -ErrorAction SilentlyContinue | Select FullName
# C:\Windows\Prefetch\MIMIKATZ.EXE-0A6C6170.pf  (and others)
```
The binary itself wasn't on disk, so the actual extraction below was done with **pypykatz** (the offline equivalent) — but the intended answer is **`Mimikatz`** (8 chars → `Xxxxxxxx`).

Mimikatz workflow (intended):
```
sekurlsa::minidump lsass.DMP
sekurlsa::dpapi
```

---

## Challenge 2 — File: `Local State`
Chrome stores the Base64 `encrypted_key` in `...\User Data\Local State` under JSON key `os_crypt.encrypted_key`. (Format `Xxxxx Xxxxx`.)

---

## Challenge 3 — Username: `Admin`
Extracted with pypykatz (equivalent to `sekurlsa::logonpasswords`):
```powershell
pip install pypykatz
pypykatz lsa minidump "$HOME\Desktop\chrome_cracker\lsass.DMP" | Out-File dpapi.txt
```
The only interactive logon:
```
== LogonSession ==
session_id 1
username Admin
domainname WIN10
sid S-1-5-21-1077705597-68872450-308104863-1001   <- -1001 = first created user
```
Everything else is a system account (LOCAL SERVICE, WIN10$, DWM-1, UMFD-0/1, SYSTEM).

Cross-check from the Chrome profile — every embedded `C:\Users\<name>` path resolves to the same account:
```powershell
python -c "import os,re;p=r'C:\Users\LabUser\Desktop\chrome_cracker\Google';s=set();[s.update(re.findall(rb'Users[\\/]+([A-Za-z0-9_]{3,20})',open(os.path.join(d,f),'rb').read())) for d,_,fs in os.walk(p) for f in fs];print(sorted({x.decode(errors='ignore') for x in s}))"
# ['Admin']
```
**Note on the mask:** the challenge shows `XxxXxxx` (7 chars) and the lab hint claims a 7-character name, but two independent sources (LSASS + Chrome paths) show only **`Admin`**. The mask is inaccurate for this instance.

---

## Challenge 4 — Masterkey (first 10): `9c3bca41e3`
From the `sekurlsa::dpapi` / pypykatz DPAPI section (session_id 1, user Admin):
```
key_guid       f7ecfe82-d268-4507-8761-3ccdbef6496b
masterkey      9c3bca41e3e8ca91ce49a1837f2c2c6fbceb141578e0131e83ab64f81de05ffc56a43082969875842346c6f16a7fd6607a80f4565901293e0a96c48478237e48
sha1_masterkey ba949fbfac1ca1c484fc19fdb339ce3a5eed7bec
```
First 10 hex chars = **`9c3bca41e3`** — matches `NxNxxxNNxN` exactly (9=N, c=x, 3=N, b=x, c=x, a=x, 4=N, 1=N, e=x, 3=N).

---

## Challenge 5 — Final Secret Key (decrypted Chrome AES key)

### The decryption (done offline with the masterkey)
1. Read the Base64 `encrypted_key` from Local State, Base64-decode, strip the 5-byte `DPAPI` magic prefix → a DPAPI BLOB.
2. Verify integrity: the blob's masterkey GUID = `f7ecfe82-…` (matches C4), and `SHA1(masterkey)` = `ba949fbf…` matches the dump's `sha1_masterkey` — so the masterkey is exact.
3. DPAPI decrypt the BLOB:
   - `algCrypt = 0x6610` (AES-256-CBC), `algHash = 0x800e` (SHA-512), `saltLen = 32`, `dataLen = 48`.
   - `sessionKey = HMAC-SHA512(SHA1(masterkey), salt)` (DPAPI reduces the 64-byte masterkey to its SHA1 when >20 bytes).
   - For SHA-512, `CryptDeriveKey` returns the 64-byte HMAC output directly: `AESkey = sessionKey[:32]`, `IV = sessionKey[32:48]`.
   - AES-256-CBC decrypt the 48-byte `data`.

### Result (cryptographically proven)
```
decrypted = ab6f2709e64d35e025dc15703a5f2127d52877827e0942918df20456853c81ac  +  10101010101010101010101010101010
            └──────────────── 32-byte AES-256 key ────────────────┘     └── PKCS#7 padding (16×0x10) ──┘
```
The **clean `0x10`×16 padding is 1-in-2¹²⁸ proof** the key is correct:
```
AES key (hex)   : ab6f2709e64d35e025dc15703a5f2127d52877827e0942918df20456853c81ac
AES key (base64): q28nCeZNNeAl3BVwOl8hJ9Uod4J+CUKRjfIEVoU8gaw=
first 10 (hex)  : ab6f2709e6
```

### ⚠️ Open issue — mask conflict
The challenge mask is `NxxNxxxNxx` (digit at positions 1, 4, 8; lowercase letters elsewhere; e.g. `5ab6cde7fg`), and the lab confirmed the key must **start with a number**.

- `ab6f2709e6` (hex) was **rejected** by the lab.
- `q28nCeZNNe` (base64) was **rejected** by the lab.
- No standard encoding (hex/HEX/base64/base64url/base32/base32hex/base85/ascii85/base58/decimal) of the true key starts with a digit matching `NxxNxxxNxx`.
- No DPAPI intermediate (masterkey, sha1_masterkey, sessionkey, derivedkey, hmac-verify) matches the mask either.

**Working hypothesis:** modern Chrome keeps two keys in Local State — `encrypted_key` (v10) and `app_bound_encrypted_key` (v20). If the saved password is a **v20** blob, the "Final Secret Key" is the *app-bound* key, not the v10 key decrypted above. Confirm with:
```powershell
# which keys exist?
python -c "import json;d=json.load(open(r'...\Local State'));print('os_crypt keys:',list(d['os_crypt'].keys()))"
# password version prefix: 76313 0 = v10 ; 76323 0 = v20
python -c "import sqlite3;c=sqlite3.connect(r'...\Default\Login Data');[print(r[0],'|',r[1],'|',r[2][:4].hex()) for r in c.execute('select origin_url,username_value,password_value from logins')]"
```
If the password prefix is `76313 0` (v10), the true answer is `ab6f2709e6` and the mask is simply wrong for this instance. If `76323 0` (v20), the app-bound key must be derived and its first 10 hex chars are the answer.

### Reproducing the decryption (Python)
```python
import base64, struct, hashlib, hmac
from Crypto.Cipher import AES  # pip install pycryptodome

masterkey = bytes.fromhex("9c3bca41e3e8ca91ce49a1837f2c2c6fbceb141578e0131e83ab64f81de05ffc56a43082969875842346c6f16a7fd6607a80f4565901293e0a96c48478237e48")
# blob = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
blob = ...  # DPAPI blob (after stripping the 5-byte 'DPAPI' prefix)

pos = 0
def u32():
    global pos; v = struct.unpack_from('<I', blob, pos)[0]; pos += 4; return v
def take(n):
    global pos; v = blob[pos:pos+n]; pos += n; return v
u32(); take(16); u32(); take(16); u32()        # version, provider, mkver, mkguid, flags
take(u32())                                     # description
algCrypt = u32(); u32()                         # 0x6610 (AES-256), key bits
salt = take(u32())                              # 32-byte salt
take(u32())                                     # hmac key (len 0 here)
algHash = u32(); u32()                          # 0x800e (SHA-512)
take(u32())                                     # hmac2 key
data = take(u32())                              # 48-byte ciphertext

sk  = hmac.new(hashlib.sha1(masterkey).digest(), salt, 'sha512').digest()  # DPAPI: SHA1-reduce mk
pt  = AES.new(sk[:32], AES.MODE_CBC, sk[32:48]).decrypt(data)
aes_key = pt[:-pt[-1]]                           # strip PKCS#7 padding
print(aes_key.hex())                             # ab6f2709e64d35...
```

---

## Challenge 6 — chaincrypto.com username / password (pending)

Chrome logins live in `Login Data` (`logins` table). Each `password_value` is **AES-256-GCM**: `v10`/`v20` prefix (3 bytes) + 12-byte nonce + ciphertext + 16-byte tag, decrypted with the Final Secret Key (C5).

Extract:
```powershell
python -c "import sqlite3;c=sqlite3.connect(r'C:\Users\LabUser\Desktop\chrome_cracker\Google\Google\Chrome\User Data\Default\Login Data');[print(r[0],'|',r[1],'|',r[2].hex()) for r in c.execute('select origin_url,username_value,password_value from logins')]"
```
Then AES-GCM decrypt the `chaincrypto.com` row's `password_value`:
```python
from Crypto.Cipher import AES
blob = bytes.fromhex("<password_value hex>")
nonce, ct, tag = blob[3:15], blob[15:-16], blob[-16:]
key = bytes.fromhex("ab6f2709e64d35e025dc15703a5f2127d52877827e0942918df20456853c81ac")
print(AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag).decode())
```
Expected answer format: `XxxxXxxxxxxx / X@$$xNxx_XxxNxx!NN` (username / password).

---

## Hint validation (lab-provided hints vs. our findings)

| Hint claim | Verdict |
|---|---|
| C1: use Mimikatz on `lsass.DMP` | **True** — intended tool (we used pypykatz offline for the same result) |
| C3: mimikatz `sekurlsa::logonpasswords`, ignore system accounts | **True method**; but "7 characters" is **false for this instance** — the real user is `Admin` (5 chars) |
| C5: decrypt `encrypted_key` with masterkey → AES key → first 10 hex, N=digit/x=lowercase | **True method**; result `ab6f2709e6` doesn't start with a digit → mask/representation conflict under investigation |
| C6: Login Data `logins` table, chaincrypto row, AES-256-GCM with the key | **True** |

---

## Tools used
| Tool | Purpose |
|---|---|
| `Expand-Archive` | unzip artifact + Chrome profile |
| Mimikatz / **pypykatz** | extract DPAPI masterkey from `lsass.DMP` |
| Python + `pycryptodome` | DPAPI BLOB + AES-256-CBC/GCM decryption |
| `sqlite3` (Python) | read Chrome `Login Data` |
| `Get-FileHash` / SHA-256 | verify exact byte transcription of the `encrypted_key` |
