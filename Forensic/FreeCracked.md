# Free Cracked Software — Digital Forensics Walkthrough

**Challenge / Lab:** CyberTalents "History 102" (a.k.a. *Free Cracked Software*)
**Category:** Windows / Endpoint Forensics
**Evidence:** `Free Cracked Software.ad1` (531 MiB AccessData logical image)
**Prepared:** 2026-10-02
**Result:** all 5 questions solved + original CyberTalents flag recovered

---

## 1. Scenario

> "One of our designers attempted to download a cracked version of a program they
> typically use, but it seems they fell victim to one of the ads in the process.
> Could you look into it and determine what happened?"

The supplied `.ad1` is a logical image of a Windows 10 machine belonging to the
user **`Gojo`** (`E:\NONAME [NTFS]`, acquired 2023-10-08). The original
CyberTalents challenge flag format is:

```
Flag{<MD5 of the malicious file>_<IP address of the ad site>_<wallet address>}
```

---

## 2. Answers at a glance

| # | Question | Answer |
|---|----------|--------|
| 1 | Name of the malicious executable downloaded | **`AdobePhotoshopCrack.exe`** |
| 2 | URL the file was downloaded from | **`http://156.26.173.114/download/AdobePhotoshopCrack.rar`** (ad IP `156.26.173.114`) |
| 3 | Date/time UTC of the download `(YYYY-MM-DD HH:MM)` | **`2023-03-12 15:54`** (exact: `2023-03-12 15:54:34.979753 UTC`) |
| 4 | Registry location of the malicious string | **`SOFTWARE\Microsoft\Windows NT\CurrentVersion`** (HKLM; value name `secr3t`, XOR key `0x87`) |
| 5 | Attacker's wallet address | **`bc1qxy2kgdygjrsqtzq2n0yrf2493!83kkfjhx0wlh`** |

**Decrypted registry string (full):**

```
Send_Money_To_bc1qxy2kgdygjrsqtzq2n0yrf2493!83kkfjhx0wlh
```

**Original CyberTalents flag:**

```
Flag{316fcaf0160b0025e13187624d0ac081_156.26.173.114_bc1qxy2kgdygjrsqtzq2n0yrf2493!83kkfjhx0wlh}
```

> Note: the `!` in the wallet string is genuinely present in the challenge
> data (both public write-ups show it). The famous example Bitcoin address has
> `p` at that position — do not "correct" it.

---

## 3. Artefacts / IOCs

```text
Evidence image      : Free Cracked Software.ad1 (ADSEGMENTEDFILE, logical v4), 531 MiB
Victim user         : Gojo  (C:\Users\Gojo)
Victim machine      : Windows 10 Pro 21H1 (build 19043), SOFTWARE RegisteredOwner = xElessaway
Malicious archive   : C:\Users\Gojo\Downloads\AdobePhotoshopCrack.zip  (19,323 B)
Malicious executable: C:\Users\Gojo\Downloads\AdobePhotoshopCrack\AdobePhotoshopCrack.exe (60,783 B)
MD5 / SHA1          : 316fcaf0160b0025e13187624d0ac081 / c971c588cfe3fbb37647a3b6638674f220b43723
PE                  : PE32+ console, x86-64, MinGW-w64 GCC 8.1.0, TimeDateStamp 2023-03-12 21:03:28 (stomped)
Imports of interest : RegOpenKeyExA, RegQueryValueExA, RegCloseKey (ADVAPI32)
Strings             : SOFTWARE\Microsoft\Windows NT\CurrentVersion, secr3t
Download URL        : http://156.26.173.114/download/AdobePhotoshopCrack.rar
Download epoch      : 13323110074979753 (Chromium µs) = 2023-03-12 15:54:34.979753 UTC
Registry value      : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\secr3t
                      REG_SZ, 114 bytes, UTF-16LE, low byte XOR 0x87
Wallet              : bc1qxy2kgdygjrsqtzq2n0yrf2493!83kkfjhx0wlh
Redirect farms      : fundfirmnos.live, acegotdesk.live, appcloudlink.com,
                      dancepeople.es, percise-v.eu, horkymaliny.cz, f5h7.monster,
                      mo13.biz, 3almalt9nia.com
Browser profile     : C:\Users\Gojo\AppData\Local\Microsoft\Edge\User Data\Default\History
Registry hive       : C:\Windows\System32\config\SOFTWARE
```

---

## 4. Timeline (UTC)

| Time (UTC) | Event |
|------------|-------|
| 2023-03-12 15:48:24 | First Google search: "download adobe photoshop crack" |
| 2023-03-12 15:48:39–15:48:53 | Malvertising redirect farms ("Human Verification" pages) |
| 2023-03-12 15:54:24–15:54:31 | Second search: "download free tools for photoshop" + decoy sites |
| 2023-03-12 15:54:33 | `3almalt9nia.com` (Arabic "Photoshop with crack" page) |
| **2023-03-12 15:54:34.979753** | **Download URL visit: `http://156.26.173.114/download/AdobePhotoshopCrack.rar`** |
| 2023-03-12 15:54:36 | Last stop: archive.org "Adobe Photoshop 2022 Pre Cracked" page |
| 2023-03-12 23:03:28 | `AdobePhotoshopCrack.exe` extracted (NTFS ChangeTime in AD1) |
| 2023-03-12 23:22:41 | Edge `History` file last written (browser closed/idle flush) |
| 2023-03-12 23:29:25 | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` key modified — malware writes/reads `secr3t` |

---

## 5. Tools used

| Tool | Purpose |
|------|---------|
| `pcbje/pyad1` (Python, patched) | Parse the AccessData AD1 logical image on Linux |
| `al3ks1s/AD1-tools` (C) | Alternative AD1 reader (`ad1info`, `ad1extract`, `ad1verify`) |
| `sqlite3` | Query the Edge/Chromium `History` database |
| `pefile` (Python) | PE header / section / import analysis |
| `objdump -d -M intel` | Disassemble `main` |
| `strings -a` / `strings -el` | Locate registry path string |
| `python-registry` | Read values from the `SOFTWARE` registry hive |
| 7-Zip / `unzip` | Inspect/extract `AdobePhotoshopCrack.zip` |

Install the essentials:

```sh
# Kali/Debian
apt-get install -y sqlite3 binutils p7zip-full
pip install pefile python-registry
git clone --depth 1 https://github.com/pcbje/pyad1.git
```

---

## 6. Step-by-step workflow

### Step 1 — Read the AccessData AD1 image (no FTK Imager needed)

An AD1 file starts with `ADSEGMENTEDFILE` followed by `ADLOGICALIMAGE`. It is a
**logical** evidence container (item + metadata records), not a mountable disk
image. Two open-source readers exist.

#### 1a. pyad1 (Python)

`pyad1` has two bugs with single-segment v4 images:

1. `AD1Reader.__enter__` pops the only segment from `self.paths`, then
   `_ReadLastFrom(-372)` raises `IndexError`.
2. The iterator eventually raises `Incomplete read` on the root footer.

Apply a two-line patch to `/tmp/opencode/pyad1/pyad1/reader.py`:

```python
# AD1Reader.__enter__:
self._current_path = current_path      # remember the file we opened

# AD1Reader._ReadLastFrom:
path = self.paths[-1] if self.paths else self._current_path
```

Then iterate (wrap in `try/except` — the footer error is harmless once items
have been yielded):

```python
import pyad1.reader

with pyad1.reader.AD1Reader('Free Cracked Software.ad1') as ad1:
    for item_type, folder, filename, metadata, content in ad1:
        # item_type 0 = file, 5 = folder
        print(item_type, folder, filename, len(content) if content else 0)
```

Our run yielded **59,375 items**. The full tree was saved as:

```
type|folder|name|size           (e.g. 0|[root]/Users/Gojo/Downloads|b'AdobePhotoshopCrack.zip'|19323)
```

#### 1b. AD1-tools (C, alternative)

```sh
git clone --depth 1 https://github.com/al3ks1s/AD1-tools.git
cd AD1-tools
chmod +x autogen.sh          # the repo ships it non-executable
sh autogen.sh                 # needs autoconf/automake/libtool
cd build && ../configure      # needs libssl-dev + zlib1g-dev
make -C AD1Tools ad1info ad1extract ad1verify   # ad1mount needs fuse2
```

#### 1c. Extract the relevant artefacts

We extracted (preserving the folder layout):

```text
Users/Gojo/Downloads/AdobePhotoshopCrack.zip
Users/Gojo/Downloads/AdobePhotoshopCrack/AdobePhotoshopCrack.exe
Users/Gojo/AppData/Local/Microsoft/Edge/User Data/Default/History
Users/Gojo/AppData/Local/Microsoft/Edge/User Data/Default/Web Data
Users/Gojo/AppData/Local/Microsoft/Edge/User Data/Default/Preferences
Windows/System32/config/SOFTWARE
Windows/System32/config/SYSTEM
Windows/System32/config/DEFAULT
```

Quick triage one-liners on the tree text:

```sh
grep -iE 'downloads|/history\||ntuser|system32/config' tree.txt | grep -v WinSxS
```

Useful AD1 metadata facts (category 5 = TIMESTAMP):

| key | meaning |
|-----|---------|
| 7   | ACCESS (`$SI` LastAccessTime) |
| 8   | MODIFIED (`$SI` LastWriteTime) |
| 9   | CHANGE (`$SI` ChangeTime) |

In this image keys 7/8 were overwritten by the 2023-10-08 acquisition; key 9
survived and is useful for ordering events (e.g. `AdobePhotoshopCrack.exe`
ChangeTime `20230312T230328`, Edge `History` ChangeTime `20230312T232241`).

> `NTUSER.DAT` was not included in this logical image and the `SYSTEM` hive
> only contains `DriverDatabase`, so the `SOFTWARE` hive is the important one.

---

### Step 2 — Question 1: identify the malicious executable

Tree hits:

```text
0|[root]/Users/Gojo/Downloads/AdobePhotoshopCrack|b'AdobePhotoshopCrack.exe'|60783
0|[root]/Users/Gojo/Downloads|b'AdobePhotoshopCrack.zip'|19323
```

The ZIP contains the same file:

```sh
7z l AdobePhotoshopCrack.zip
# 2023-03-13 06:03:28 ....A  60783  19143  AdobePhotoshopCrack.exe
```

Verify both copies are identical:

```sh
md5sum AdobePhotoshopCrack.zip AdobePhotoshopCrack/AdobePhotoshopCrack.exe
# cd97f635d64407e14309798a2d13b6c0  AdobePhotoshopCrack.zip
# 316fcaf0160b0025e13187624d0ac081  AdobePhotoshopCrack/AdobePhotoshopCrack.exe
```

Sanity check the PE:

```sh
file AdobePhotoshopCrack.exe
# PE32+ executable for MS Windows 5.02 (console), x86-64, 15 sections
```

**Answer 1: `AdobePhotoshopCrack.exe`**

---

### Step 3 — Questions 2 & 3: find the download URL and UTC time in Edge history

The Edge profile lives under `AppData\Local\Microsoft\Edge\User Data\Default`
(the `Roaming` copy is a stub). The `History` file is SQLite.

#### 3a. Query the download-related tables

```sh
sqlite3 History ".tables"
sqlite3 -header -column History \
  "SELECT id,current_path,target_path,start_time,end_time,site_url,tab_url FROM downloads;"
# -> empty! The download row was deleted.
sqlite3 History "SELECT * FROM downloads_url_chains;"      # -> empty
sqlite3 History "SELECT * FROM downloads_slices;"          # -> empty
```

Do **not** stop here — Chromium keeps `urls.last_visit_time` even when the
associated visit/download row is removed. Search for Photoshop / the ad IP:

```sh
sqlite3 -header History "
  SELECT id,url,title,visit_count,typed_count,last_visit_time
  FROM urls
  WHERE url LIKE '%photoshop%' OR url LIKE '%crack%' OR url LIKE '%156.%'
  ORDER BY last_visit_time DESC;"
```

Relevant row:

```text
41|http://156.26.173.114/download/AdobePhotoshopCrack.rar|Download Photoshop free crack|1|0|13323110074979753
```

#### 3b. Convert the Chromium timestamp to UTC

Chromium/Edge timestamps are **microseconds since 1601-01-01 00:00:00 UTC**
(not Unix time, and not local time):

```python
import datetime
datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=13323110074979753)
# datetime.datetime(2023, 3, 12, 15, 54, 34, 979753)
```

The surrounding `urls`/`visits` rows show the classic malvertising chain
(all on 2023-03-12):

```text
15:48:24  google.com/search?q=download+adobe+photoshop+crack
15:48:27  quora.com "How to download and install Adobe Photoshop Crack"
15:48:32  free4pc.org/tag/photoshop-crack/
15:48:39  evunox.postadozione.it / 5.dancepeople.es          (Redirect)
15:48:42  bicfic.com "Adobe Photoshop CC 2023 Crack Full Version"
15:48:47  633132209.horkymaliny.cz "Human Verification"
15:48:49  f5h7j.monster "Human Verification"
15:48:50  2.dancepeople.es / cofa.generazionelombardia.it    (Redirect)
15:48:51  snrjt.percis-v.eu/adobe_photoshop_indir_crack.html
15:48:53  appcloudlink.com / 128.fundfirmnos.live / 128.acegotdesk.live
15:54:24  google.com/search?q=download+free+tools+for+photoshop
15:54:25  en.softonic.com/downloads/photoshop-tools[-free]
15:54:31  fixthephoto.com/free-photoshop-plugins.html
15:54:31  mo13.biz "Human Verification"
15:54:32  f5h7j.monster "Human Verification"
15:54:33  3almalt9nia.com (Arabic: Photoshop 2020 + activation crack)
15:54:34  http://156.26.173.114/download/AdobePhotoshopCrack.rar   <-- MALICIOUS
15:54:36  archive.org/details/adobe-photoshop-2022-v-23.0.0.36-x-64-pre-cracked
```

Note the file saved on disk (`AdobePhotoshopCrack.zip`) differs from the URL
extension (`.rar`); the server may have delivered a ZIP for the RAR path (or
the browser renamed it). The only recorded download URL is the `.rar` one.

**Answer 2: `http://156.26.173.114/download/AdobePhotoshopCrack.rar`**
(ad IP: `156.26.173.114`)

**Answer 3: `2023-03-12 15:54` UTC** (exact `15:54:34.979753`)

---

### Step 4 — Question 4: reverse the PE to find the registry location

#### 4a. PE triage

```sh
python3 - <<'EOF'
import pefile, datetime
pe = pefile.PE('AdobePhotoshopCrack.exe')
print('Timestamp:', datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp))
print('Subsystem:', pe.OPTIONAL_HEADER.Subsystem, 'EP:', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
for s in pe.sections:
    print(s.Name.rstrip(b'\x00').decode(), hex(s.VirtualAddress), s.SizeOfRawData)
for e in pe.DIRECTORY_ENTRY_IMPORT:
    print(e.dll.decode(), [i.name for i in e.imports])
EOF
```

Output highlights:

```text
Timestamp : 2023-03-12 21:03:28          (later than the download -> stomped/bogus)
Sections  : .text .data .rdata .pdata .xdata .bss .idata .CRT .tls
            /4 /19 /31 /45 /57 /70        (MinGW/ld artefacts, NOT packing)
Imports   : ADVAPI32.dll -> RegCloseKey, RegOpenKeyExA, RegQueryValueExA
            KERNEL32.dll, msvcrt.dll, libstdc++-6.dll, libgcc_s_seh-1.dll
```

#### 4b. Strings

```sh
strings -a AdobePhotoshopCrack.exe | grep -E 'SOFTWARE|secr3t|CurrentVersion'
# SOFTWARE\Microsoft\Windows NT\CurrentVersion
```

The raw `.rdata` shows both strings back-to-back:

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\x00secr3t\x00
```

#### 4c. Disassemble `main` (`0x401550`)

```sh
objdump -d -M intel --section=.text AdobePhotoshopCrack.exe | sed -n '/<main>:/,/^$/p'
```

Annotated logic:

```c
h = RegOpenKeyExA(HKEY_LOCAL_MACHINE           /* rcx = 0xffffffff80000002 */
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ /* r9d = 0x20019 */, &h);

RegQueryValueExA(h, "secr3t", NULL, &type, NULL, &size);   // size probe
std::string data(size, 0);
RegQueryValueExA(h, "secr3t", NULL, &type, data, &size);   // read data

for (char &c : data)
    c ^= 0x87;                                             // XOR key = 0x87
```

Key facts read straight off the disassembly:

* `0xffffffff80000002` = **HKEY_LOCAL_MACHINE**
* `0x20019` = `KEY_READ`
* Key path string = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
* Value name string = `secr3t`
* XOR key = **`0x87`**

> The question's answer format `********\*********\******* **\**************`
> maps exactly to `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
> (8 chars `SOFTWARE` \ 9 chars `Microsoft` \ `Windows` + space + `NT` \
> 14 chars `CurrentVersion`).

**Answer 4: `SOFTWARE\Microsoft\Windows NT\CurrentVersion`** (under HKLM)

---

### Step 5 — Question 5: read and XOR the value from the SOFTWARE hive

#### 5a. Load the hive with python-registry

```sh
pip install python-registry
python3 - <<'EOF'
from Registry import Registry
reg = Registry.Registry('SOFTWARE')
key = reg.open(r"Microsoft\Windows NT\CurrentVersion")
v = key.value('secr3t')
print('type:', v.value_type(), 'size:', len(v.raw_data()))
print('raw hex:', v.raw_data().hex())
EOF
```

Output:

```text
type: 1  size: 114                 # REG_SZ = 1
raw hex: d400e200e900e300d800ca00e800e900e200fe00d800d300e800d800e500e400b600f600ff00fe00b500ec00e000e300fe00e000ed00f500f400f600f300fd00f600b500e900b700fe00f500e100b500b300be00b400a600bf00b400ec00ec00e100ed00ef00ff00b700f000eb00ef000000
```

`python-registry` displays this as mojibake (`ÔâéãØÊèéâþ...`) — that is the
obfuscation, not a decoding failure.

#### 5b. Understand the encoding

The blob is UTF-16LE. Notice that **only the low byte of every wide char is
obfuscated** and the high bytes are `0x00`:

```
d4 00 e2 00 e9 00 e3 00 ...        low bytes: d4 e2 e9 e3 ...
```

The malware's compiled loop XORs *every* byte with `0x87`, which produces
`S 0x87 e 0x87 n 0x87 ...`. The readable string is recovered by XORing the low
byte of each code unit:

```python
raw = v.raw_data()
decoded = bytes(b ^ 0x87 for b in raw[::2])   # take every other byte
print(decoded.decode('latin1'))
```

Equivalent (and more explicit):

```python
b = bytearray(raw)
for i in range(0, len(b), 2):
    b[i] ^= 0x87
print(bytes(b).decode('utf-16-le'))
```

Result:

```
Send_Money_To_bc1qxy2kgdygjrsqtzq2n0yrf2493!83kkfjhx0wlh
```

**Answer 5 (wallet): `bc1qxy2kgdygjrsqtzq2n0yrf2493!83kkfjhx0wlh`**

---

### Step 6 — Assemble the original flag

```text
Flag{316fcaf0160b0025e13187624d0ac081_156.26.173.114_bc1qxy2kgdygjrsqtzq2n0yrf2493!83kkfjhx0wlh}
       └── MD5 of AdobePhotoshopCrack.exe ──┘ └── ad IP ──┘ └── attacker wallet ──────────────────┘
```

---

## 7. Lessons learned / pitfalls

1. **AD1 is logical, not a disk image.** `file` reports `ADSEGMENTEDFILE`.
   Parse item records with `pyad1`/`AD1-tools`; do not try to mount it.
2. **`pcbje/pyad1` needs a 2-line fix** for single-segment v4 images
   (`self._current_path` fallback in `_ReadLastFrom`) and always ends with a
   harmless `Incomplete read` on the root footer. Catch it and keep the items
   already yielded.
3. **Empty `downloads` != no download evidence.** Chromium deletes download
   rows and their visit rows independently; `urls.last_visit_time` persists.
   Check `downloads` → `downloads_url_chains` → `downloads_slices` → `urls` /
   `visits` → raw `strings` of the DB (free pages).
4. **Chromium timestamps are microseconds since 1601-01-01 UTC.** DB browsers
   show the raw integer; convert with
   `datetime(1601,1,1) + timedelta(microseconds=t)`.
5. **AD1 metadata key 9 = ChangeTime** survives when Access/Modified were
   clobbered by acquisition; use it to order extraction / profile-write events.
6. **Tiny PE + only registry imports = registry-secret reader.** The payload
   lives in the hive, not in the binary. Do not trust the PE compile timestamp
   (here it post-dates the download — stomped).
7. **XOR-obfuscated `REG_SZ`:** check the UTF-16 high bytes. If they are
   `0x00`, only the low byte of each wide char was XORed — XOR every other
   byte. XORing every byte (what the malware literally does) leaves alternating
   `0x87` bytes and hides the ASCII string.
8. **MinGW artefacts are not obfuscation.** Sections `/4 /19 /31 /45 /57 /70`,
   DWARF data in odd sections and `libstdc++-6.dll` imports are normal `ld`
   output.

---

## 8. Skill upgrade (reusable tooling)

This workflow was also saved into the OpenCode `forensics` skill:

* `~/.config/opencode/skills/forensics/SKILL.md`
  → section **"CyberTalents History 102 / Free Cracked Software (AD1 logical
  image + Edge history + XOR-registry wallet) — verified workflow"**
  plus updated description, summary bullet, one-liners and pitfalls.
* New reusable scripts
  (`~/.config/opencode/skills/forensics/scripts/`):

| Script | What it does | Example |
|--------|--------------|---------|
| `ad1_extract.py` | Clones+patches pyad1, lists an AD1 tree, extracts matching paths, dumps metadata | `python3 ad1_extract.py evidence.ad1 --list tree.txt --extract History -o out` |
| `edge_history_triage.py` | Dumps Chromium/Edge `downloads`, URL and visit tables with UTC conversion | `python3 edge_history_triage.py History --like 156.26` |
| `reg_value_xor.py` | Reads a hive value and XOR-decodes it (`--mode low` for UTF-16 REG_SZ) | `python3 reg_value_xor.py SOFTWARE "Microsoft\Windows NT\CurrentVersion" secr3t --xor 0x87 --mode low` |

---

## 9. Appendix — minimal reproduction script

```sh
#!/bin/sh
# Everything needed to reproduce the answers (Linux, no FTK)
set -e
AD1="${1:-Free Cracked Software.ad1}"
WORK="${2:-freecrack_work}"
mkdir -p "$WORK"

# 1) pyad1 (+2-line patch)
[ -d "$WORK/pyad1" ] || git clone --depth 1 https://github.com/pcbje/pyad1.git "$WORK/pyad1"
python3 - "$WORK/pyad1/pyad1/reader.py" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace("        current_path = self.paths.pop(0)\n        self.current_file = open(current_path, 'rb')",
              "        current_path = self.paths.pop(0)\n        self._current_path = current_path\n        self.current_file = open(current_path, 'rb')", 1)
s = s.replace("    def _ReadLastFrom(self, pos):\n        with open(self.paths[-1], 'rb') as inp:",
              "    def _ReadLastFrom(self, pos):\n        path = self.paths[-1] if self.paths else self._current_path\n        with open(path, 'rb') as inp:", 1)
open(p, 'w').write(s)
PY

# 2) extract the interesting files
python3 - "$AD1" "$WORK" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[2], 'pyad1'))
import pyad1.reader
ad1_path, out = sys.argv[1], sys.argv[2]
targets = ['/Downloads', 'Edge/User Data/Default/History', 'config/SOFTWARE']
with pyad1.reader.AD1Reader(ad1_path) as ad1:
    try:
        for t, folder, name, meta, data in ad1:
            name = name.decode() if isinstance(name, bytes) else str(name)
            if t == 5 or not any(x in folder + '/' + name for x in targets):
                continue
            dest = os.path.join(out, folder.replace('[root]', '').lstrip('/'), name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            open(dest, 'wb').write(data)
            print('saved', dest)
    except Exception as e:
        print('footer error (expected):', e)
PY

# 3) browser history
HIST="$WORK/Users/Gojo/AppData/Local/Microsoft/Edge/User Data/Default/History"
sqlite3 "$HIST" "SELECT url,title,last_visit_time FROM urls WHERE last_visit_time>0 ORDER BY last_visit_time DESC LIMIT 5;"
python3 - <<'PY'
import datetime
t = 13323110074979753
print('download time UTC:', datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=t))
PY

# 4) registry value
REG="$WORK/Windows/System32/config/SOFTWARE"
python3 - "$REG" <<'PY'
import sys
from Registry import Registry
v = Registry.Registry(sys.argv[1]).open(r"Microsoft\Windows NT\CurrentVersion").value('secr3t')
raw = v.raw_data()
print('wallet:', bytes(b ^ 0x87 for b in raw[::2]).decode('latin1'))
PY
```

Expected output:

```text
download time UTC: 2023-03-12 15:54:34.979753
wallet: Send_Money_To_bc1qxy2kgdygjrsqtzq2n0yrf2493!83kkfjhx0wlh
```

---

*End of walkthrough.*
