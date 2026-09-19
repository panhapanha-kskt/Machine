# Holmes CTF 2026 – Sherlock 04: Paper Ghost (The False Employee)

**Platform:** Hack The Box (Holmes CTF 2026) | **Difficulty:** Easy | **Category:** DFIR / Windows forensics
**Evidence:** KAPE triage collection of Clara Voss's workstation (`CO-LT-0469`, user `cvoss`)

---

## 1. Scenario

A "contractor" (Elias Venn) dropped a USB stick at Clara Voss's desk, presented as a driver/update package. Voss plugged it in and ran the "update". It was actually VON BORK spyware. It turned on her microphone and webcam, then shipped data out to a C2 server. Our job is to rebuild the whole thing from the triage image only.

Everything below was pulled from registry hives, SRUM and the Windows Search index. There are no event logs, no Amcache and no PDFs on disk in this collection, and that shapes which artifacts we can use.

---

## 2. Answer sheet

| # | Question | Answer |
|---|----------|--------|
| 1 | First time the planted USB was connected | `2026-08-19 15:35:50` |
| 2 | Serial number of the dropped USB | `RS200000000627E4` |
| 3 | Full path of the payload | `E:\CO-LT-0469 update package\update.exe` |
| 4 | When Voss executed it | `2026-08-19 15:36:25` |
| 5 | Asset name shown as the device name | `CO-USB-0091` |
| 6 | Microphone capture start | `2026-08-19 15:38:08` |
| 7 | Webcam stream duration (seconds) | `127` |
| 8 | Outbound decimal MB to the C2 | `172.064531` |
| 9 | Developer credentials surfaced | `tainsworth:D10g3n3s_T1ck3ts#2026` |

All times are **UTC**. The box is set to Pacific time (`ActiveTimeBias = 420`, so UTC-7). The platform accepted the UTC values.

---

## 3. Evidence layout

```
PaperGhost/Triage/
├── *_ConsoleLog.txt / *_CopyLog.csv / *_SkipLog.csv.csv   (KAPE logs)
└── C/
    ├── ProgramData/Microsoft/search/data/applications/windows/Windows.edb   <- Windows Search index (Q9)
    ├── Users/cvoss/NTUSER.DAT (+LOG1/LOG2)                                 <- UserAssist, CapabilityAccessManager (Q3, Q4, Q6, Q7)
    ├── Users/cvoss/AppData/Roaming/Microsoft/Windows/Recent/*.lnk           <- context only
    └── Windows/System32/
        ├── config/{SYSTEM,SOFTWARE}(+LOGs)                                  <- USB artifacts (Q1, Q2, Q5)
        └── SRU/SRUDB.dat                                                    <- SRUM network usage (Q8)
```

Artifact-to-question map:

| Artifact | Answers |
|----------|---------|
| SYSTEM `Enum\USBSTOR` (+ device properties `0064`) | Q1, Q2 |
| NTUSER `UserAssist` | Q3, Q4 |
| SOFTWARE `Windows Portable Devices\Devices` (also `wpdbusenum`) | Q5 |
| NTUSER `CapabilityAccessManager\ConsentStore` | Q6, Q7 |
| `SRUDB.dat` Network Data Usage table | Q8 |
| `Windows.edb` `SystemIndex_PropertyStore` -> `AutoSummary` | Q9 |

---

## 4. Environment setup

I was root on Kali, so `~` is `/root`. The evidence lives elsewhere, so I anchored everything on `$PWD` instead of `~`.

```bash
# unpack (from the challenge dir)
unzip PaperGhost.zip

# apt mirror served stale versions (404s), refresh first
sudo apt update
sudo apt install -y regripper libesedb-utils liblnk-utils libolecf-utils

# python venv + everything the scripts import
python3 -m venv venv && source venv/bin/activate
pip install regipy click tabulate pytz inflection construct \
            python-registry libesedb-python liblnk-python LnkParse3 dissect.esedb

# path variables used by all later steps
export BASE="$PWD/PaperGhost/Triage/C"
export WORK="$PWD/work"; mkdir -p "$WORK"
```

Gotchas I hit:

- `regipy` on its own is missing `click` and `tabulate`, so the CLI crashes until you install them.
- The Kali `regripper` package installs a `regripper` binary. There is no `rip.pl` on PATH.
- The Python module for `python-registry` is imported as `from Registry import Registry`.

---

## 5. Prep: stage the hives and replay transaction logs

The hives were collected "dirty" (unflushed changes sit in the `.LOG1/.LOG2` files). Replaying them recovers the latest data, and for SYSTEM it recovered 319 dirty pages, so it is worth doing.

```bash
cp "$BASE"/Windows/System32/config/{SYSTEM,SOFTWARE}* "$WORK"/
cp "$BASE"/Users/cvoss/NTUSER.DAT "$BASE"/Users/cvoss/ntuser.dat.LOG* "$WORK"/
cd "$WORK"

regipy-process-transaction-logs SYSTEM     -p SYSTEM.LOG1     -s SYSTEM.LOG2     -o SYSTEM.clean
regipy-process-transaction-logs SOFTWARE   -p SOFTWARE.LOG1   -s SOFTWARE.LOG2   -o SOFTWARE.clean

# ntuser.dat.LOG1 is 0 bytes in this triage, so use LOG2 only
regipy-process-transaction-logs NTUSER.DAT -p ntuser.dat.LOG2 -o NTUSER2.clean

ls -la *.clean
```

Then the timezone check, so we know how to read the timestamps:

```bash
regripper -r SYSTEM.clean -p timezone
# Bias 480, ActiveTimeBias 420, Pacific Standard Time -> box is UTC-7 (DST)
# Registry timestamps are stored in UTC, so all answers are UTC.
```

---

## 6. Solving each question

### Q1 and Q2: first connection time and serial of the USB

Quick look with RegRipper:

```bash
regripper -r SYSTEM.clean -p usbstor
regripper -r SYSTEM.clean -p usb
```

The one storage device is the Lexar stick:

```
Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00
  S/N: RS200000000627E4&0
    First InstallDate : 2026-08-19 15:35:50Z
    Last Arrival      : 2026-08-19 15:51:06Z
    Last Removal      : 2026-08-19 15:51:06Z
```

To get the exact first-install value from the device properties (property `0064`), and not just the key time:

```python
import struct, datetime
from Registry import Registry

def ft(b):
    q = struct.unpack("<Q", b[:8])[0] if isinstance(b, bytes) else b
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=q/10)

r = Registry.Registry("SYSTEM.clean")
for dev in r.open("ControlSet001\\Enum\\USBSTOR").subkeys():
    for inst in dev.subkeys():
        print("DEVICE:", dev.name(), "| SERIAL/INSTANCE:", inst.name())
        p = inst.subkey("Properties").subkey("{83da6326-97a6-4088-9453-a1923f573b29}")
        for sk in p.subkeys():
            if sk.name() in ("0064", "0065", "0066", "0067"):
                print("  ", sk.name(), ft(sk.value("(default)").value()))
```

Output:

```
0064 2026-08-19 15:35:50.428692   <- first install  (Q1)
0065 2026-08-19 15:35:50.428692
0066 2026-08-19 15:51:06.432549   <- last arrival
0067 2026-08-19 15:51:06.557507   <- last removal
```

- Property meaning: `0064` first install, `0065` install, `0066` last arrival, `0067` last removal.
- **Q1:** `2026-08-19 15:35:50`
- **Q2:** the USB descriptor serial, which matches the `Enum\USB\VID_21C4&PID_0CD1` key name, is `RS200000000627E4`. The USBSTOR instance ID adds a trailing `&0`, which is a Windows-generated suffix and not part of the serial.

Note: the REDRAGON Live Camera (`VID_0C45&PID_636B`) shows up at 13:44 and is a separate webcam. It is not the dropped device. It is also why webcam capture exists later.

### Q3 and Q4: payload path and execution time

The `.lnk` files in `Recent` are a trap. They all point to `C:\Users\cvoss\Desktop\DIOGENES_26\*.pdf` on the fixed local disk (decoy documents). The real execution evidence is in **UserAssist**:

```bash
regripper -r NTUSER2.clean -p userassist
```

```
2026-08-19 15:36:25Z
  E:\CO-LT-0469 update package\update.exe (1)
```

- **Q3:** `E:\CO-LT-0469 update package\update.exe`, launched from the removable drive `E:`
- **Q4:** `2026-08-19 15:36:25`, run count 1

That is 35 seconds after the USB was first connected. BAM has nothing for it here because BAM only tracks the local disk and this ran from removable media.

Standalone UserAssist decoder (names are ROT13, last-run FILETIME sits at offset 60 of the 72-byte record):

```python
import codecs, struct, datetime
from Registry import Registry

def ft(q): return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=q/10)

r = Registry.Registry("NTUSER2.clean")
ua = r.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
for guid in ua.subkeys():
    try: count = guid.subkey("Count")
    except Exception: continue
    for v in count.values():
        name = codecs.decode(v.name(), "rot_13")
        data = v.value()
        if isinstance(data, bytes) and len(data) >= 68:
            runs = struct.unpack("<I", data[4:8])[0]
            last = ft(struct.unpack("<Q", data[60:68])[0])
            if "update.exe" in name.lower():
                print(last, "|", name, "| runs:", runs)
```

### Q5: asset name shown as the device name

`wpdbusenum` (the RegRipper plugin name, not the answer!) reads Windows Portable Device enumeration. That's where the device's display name lives:

```bash
regripper -r SYSTEM.clean -p wpdbusenum
```

```
_??_USBSTOR#Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00#RS200000000627E4&0#{...}
  Friendly: CO-USB-0091

{61486a41-9be3-11f1-8640-000c29177a52}#0000000E65800000
  Friendly: VTOYEFI       <- Ventoy volume label, just the filesystem label
```

Same thing straight from the SOFTWARE hive:

```python
from Registry import Registry
r = Registry.Registry("SOFTWARE.clean")
for s in r.open("Microsoft\\Windows Portable Devices\\Devices").subkeys():
    print(s.name(), s.timestamp())
    for v in s.values():
        print("    ", v.name(), "=", v.value())
```

```
SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_LEXAR&...#RS200000000627E4&0#{...}  2026-08-19 15:35:50.949017
     FriendlyName = CO-USB-0091
```

**Q5:** `CO-USB-0091`. The `CO-` prefix matches the workstation name `CO-LT-0469`, so it is the tagged asset name.

### Q6 and Q7: microphone start and webcam duration

Windows Capability Access Manager records the last start/stop time of every app that touches the mic or camera. Non-packaged apps (like an exe run from `E:`) land under `NonPackaged`. Since `update.exe` ran as `cvoss`, the entries are in her **NTUSER** hive, not SOFTWARE. My first attempt against SOFTWARE printed nothing for exactly that reason.

```python
import struct, datetime
from Registry import Registry

def ft(q): return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=q/10) if q else None
def num(v):
    x = v.value()
    return struct.unpack("<Q", x[:8])[0] if isinstance(x, bytes) else x

def walk(k, path):
    d = {v.name(): v for v in k.values()}
    if "LastUsedTimeStart" in d:
        s = num(d["LastUsedTimeStart"])
        e = num(d["LastUsedTimeStop"]) if "LastUsedTimeStop" in d else 0
        print(path)
        print("   start:", ft(s), "| stop:", ft(e), "| secs:", (e-s)/1e7 if e else None)
    for sk in k.subkeys():
        walk(sk, path + "\\" + sk.name())

for hive, root in (
    ("NTUSER2.clean", "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore"),
    ("SOFTWARE.clean", "Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore"),
):
    print("=====", hive)
    try: walk(Registry.Registry(hive).open(root), root)
    except Exception as e: print("err:", e)
```

Output:

```
...\microphone\NonPackaged\E:#CO-LT-0469 update package#update.exe
   start: 2026-08-19 15:38:08.113180 | stop: 2026-08-19 15:41:03.258924 | secs: 175.1457449
...\webcam\NonPackaged\E:#CO-LT-0469 update package#update.exe
   start: 2026-08-19 15:42:28.681432 | stop: 2026-08-19 15:44:35.661982 | secs: 126.9805499
```

- **Q6:** mic capture began `2026-08-19 15:38:08`
- **Q7:** webcam streamed 126.98 s, which is **127** seconds

The `#` in the key name is how Windows stores `\` in the path, so `E:#CO-LT-0469 update package#update.exe` is our payload again.

### Q8: outbound traffic to the C2

SRUM's Network Data Usage table (`{973F5D5C-1D90-4944-BE8E-24B94231A174}`) keeps bytes sent and received per app. We map the `AppId` to a path through `SruDbIdMapTable`. `esedbexport` failed for me because the output directory didn't exist, so I read the DB directly with `pyesedb`:

```python
import pyesedb, os

db = pyesedb.file()
db.open(os.environ["BASE"] + "/Windows/System32/SRU/SRUDB.dat")

def names(t): return [t.get_column(i).name for i in range(t.number_of_columns)]
def geti(rec, i):
    try: return rec.get_value_data_as_integer(i) or 0
    except Exception: return 0

# AppId -> path
t = db.get_table_by_name("SruDbIdMapTable"); n = names(t)
idmap = {}
for i in range(t.number_of_records):
    r = t.get_record(i)
    blob = r.get_value_data(n.index("IdBlob")) or b""
    try: s = blob.decode("utf-16le").rstrip("\x00")
    except Exception: s = blob.hex()
    idmap[geti(r, n.index("IdIndex"))] = s

# Network Data Usage: sum per AppId
t = db.get_table_by_name("{973F5D5C-1D90-4944-BE8E-24B94231A174}"); n = names(t)
agg = {}
for i in range(t.number_of_records):
    r = t.get_record(i)
    a = geti(r, n.index("AppId"))
    s, rc = agg.get(a, (0, 0))
    agg[a] = (s + geti(r, n.index("BytesSent")), rc + geti(r, n.index("BytesRecvd")))

for a, (s, rc) in sorted(agg.items(), key=lambda x: -x[1][0])[:15]:
    print(f"{s:>14} {rc:>14}  {idmap.get(a, a)}")

for a, (s, rc) in agg.items():
    p = str(idmap.get(a, "")).lower()
    if "co-lt-0469 update package" in p:
        print("PAYLOAD:", idmap[a], "| BytesSent =", s, "| MB =", f"{s/1_000_000:.6f}")
```

Relevant line:

```
172064531   615595   \device\harddiskvolume5\co-lt-0469 update package\update.exe
PAYLOAD: ... | BytesSent = 172064531 | MB = 172.064531
```

**Q8:** `172064531 / 1,000,000 = 172.064531` (decimal MB, matches `***.******`).

Worth noting: it sent ~172 MB out and received only ~0.6 MB, which is what exfiltration looks like. `harddiskvolume5` is the USB volume, consistent with the `E:` drive.

### Q9: credentials for the DIOGENES developer

The story hint says the spyware "surfaced" what Voss was reviewing. No PDFs were collected (the KAPE CopyLog only has the `.lnk` files). But the Windows Search index (`Windows.edb`) stores an extracted **AutoSummary** of every indexed document, and that includes the text of the PDFs on her desktop.

My first regex pass over the raw table was too strict and missed it. Dumping the whole `SystemIndex_PropertyStore` with `dissect.esedb` and grepping the dump is what worked:

```python
import os
from dissect.esedb import EseDB

p = os.environ["BASE"] + "/ProgramData/Microsoft/search/data/applications/windows/Windows.edb"
db = EseDB(open(p, "rb"))
t = db.table("SystemIndex_PropertyStore")
cols = [c.name for c in t.columns]

out = open("propstore_dissect.txt", "w")
for rec in t.records():
    for c in cols:
        try: v = getattr(rec, c)
        except Exception: continue
        if v in (None, b"", ""): continue
        if isinstance(v, bytes):
            v = v.decode("utf-16le", "ignore") if b"\x00" in v[:20] else v.decode("utf-8", "ignore")
        out.write(f"{c}: {v}\n")
    out.write("-----\n")
out.close()
```

```bash
grep -a -i -n -E "pass|pwd|cred|login|username|ticket|NAPOLEON|jira" propstore_dissect.txt | cut -c1-300
# don't cut the AutoSummary line, my first pass chopped it before the credentials
sed -n '3678p' propstore_dissect.txt | fold -w 200
```

The hit is the AutoSummary of `C:\Users\cvoss\Desktop\DIOGENES_26\EXT-0419.pdf`:

```
Profile PERSONNEL & ACCESS FILE — EXTERNAL CONTRACTOR
DIOGENES Ticketing Support
Name:              Tom Ainsworth
Title:             Software Developer, DIOGENES Ticketing Support (External Contractor)
Contractor ID:     EXT-0419
Internal server:   srv-diogenes-tickets-01.internal
Username:          tainsworth
Password:          D10g3n3s_T1ck3ts#2026
Access scope:      EXT-3 (ticketing host only)
Assigned repository: parse_diogenese_tickets
```

`DIOGENES_Contractor_Assignments.csv` (also indexed) lists EXT-0419 as the developer working DIOGENES ticketing, which confirms this is the "developer working on DIOGENES tickets" the question wants.

**Q9:** `tainsworth:D10g3n3s_T1ck3ts#2026`

---

## 7. All-in-one solver

Everything above in one script. Run it after section 5 (the `.clean` hives must exist in `$WORK`).

```python
#!/usr/bin/env python3
"""
paperghost_solve.py  -  Holmes CTF 2026 / Sherlock 04 Paper Ghost
usage: python3 paperghost_solve.py <BASE .../Triage/C> <WORK dir with *.clean hives>
needs: python-registry, libesedb-python (pyesedb), dissect.esedb
"""
import sys, os, re, struct, codecs, datetime
from Registry import Registry
import pyesedb
from dissect.esedb import EseDB

BASE, WORK = sys.argv[1], sys.argv[2]
SYSTEM   = os.path.join(WORK, "SYSTEM.clean")
SOFTWARE = os.path.join(WORK, "SOFTWARE.clean")
NTUSER   = os.path.join(WORK, "NTUSER2.clean")     # LOG2-only replay (LOG1 is empty)

def ft(q):
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=q / 10) if q else None
def as_q(x):
    return struct.unpack("<Q", x[:8])[0] if isinstance(x, bytes) else x

# ---------- Q1 + Q2: USBSTOR ----------
sysr = Registry.Registry(SYSTEM)
for dev in sysr.open("ControlSet001\\Enum\\USBSTOR").subkeys():
    for inst in dev.subkeys():
        props = inst.subkey("Properties").subkey("{83da6326-97a6-4088-9453-a1923f573b29}")
        first = ft(as_q(props.subkey("0064").value("(default)").value()))
        serial = inst.name().rsplit("&", 1)[0]
        print(f"[Q1] first connect : {first:%Y-%m-%d %H:%M:%S}")
        print(f"[Q2] serial        : {serial}  (instance id: {inst.name()})")

# ---------- Q3 + Q4: UserAssist ----------
ua = Registry.Registry(NTUSER).open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
for guid in ua.subkeys():
    try: count = guid.subkey("Count")
    except Exception: continue
    for v in count.values():
        name = codecs.decode(v.name(), "rot_13")
        data = v.value()
        if isinstance(data, bytes) and len(data) >= 68 and re.match(r"^[A-Z]:\\", name):
            last = ft(struct.unpack("<Q", data[60:68])[0])
            print(f"[Q3] payload path  : {name}")
            print(f"[Q4] executed at   : {last:%Y-%m-%d %H:%M:%S}  (runs: {struct.unpack('<I', data[4:8])[0]})")

# ---------- Q5: WPD friendly name ----------
soft = Registry.Registry(SOFTWARE)
for s in soft.open("Microsoft\\Windows Portable Devices\\Devices").subkeys():
    for v in s.values():
        if v.name() == "FriendlyName" and "USBSTOR" in s.name().upper():
            print(f"[Q5] device name   : {v.value()}")

# ---------- Q6 + Q7: mic / webcam ----------
cam_root = "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore"
ntr = Registry.Registry(NTUSER)
for dev in ("microphone", "webcam"):
    base = ntr.open(f"{cam_root}\\{dev}\\NonPackaged")
    for app in base.subkeys():
        d = {v.name(): v for v in app.values()}
        if "update package" in app.name().lower() and "LastUsedTimeStart" in d:
            s = as_q(d["LastUsedTimeStart"].value()); e = as_q(d["LastUsedTimeStop"].value())
            if dev == "microphone":
                print(f"[Q6] mic start     : {ft(s):%Y-%m-%d %H:%M:%S}")
            else:
                print(f"[Q7] webcam secs   : {(e - s) / 1e7:.2f}  -> {round((e - s) / 1e7)}")

# ---------- Q8: SRUM BytesSent ----------
db = pyesedb.file(); db.open(os.path.join(BASE, "Windows/System32/SRU/SRUDB.dat"))
def names(t): return [t.get_column(i).name for i in range(t.number_of_columns)]
def geti(rec, i):
    try: return rec.get_value_data_as_integer(i) or 0
    except Exception: return 0
t = db.get_table_by_name("SruDbIdMapTable"); n = names(t); idmap = {}
for i in range(t.number_of_records):
    r = t.get_record(i); blob = r.get_value_data(n.index("IdBlob")) or b""
    try: s = blob.decode("utf-16le").rstrip("\x00")
    except Exception: s = blob.hex()
    idmap[geti(r, n.index("IdIndex"))] = s
t = db.get_table_by_name("{973F5D5C-1D90-4944-BE8E-24B94231A174}"); n = names(t); sent = {}
for i in range(t.number_of_records):
    r = t.get_record(i); a = geti(r, n.index("AppId"))
    sent[a] = sent.get(a, 0) + geti(r, n.index("BytesSent"))
for a, b in sent.items():
    if "update package" in str(idmap.get(a, "")).lower():
        print(f"[Q8] BytesSent     : {b}  -> {b / 1_000_000:.6f} MB")

# ---------- Q9: creds from Windows Search AutoSummary ----------
edb = EseDB(open(os.path.join(BASE, "ProgramData/Microsoft/search/data/applications/windows/Windows.edb"), "rb"))
t = edb.table("SystemIndex_PropertyStore")
col = "4625-System_Search_AutoSummary"
for rec in t.records():
    try: v = getattr(rec, col)
    except Exception: continue
    if isinstance(v, bytes): v = v.decode("utf-16le", "ignore")
    if v and "Password:" in v:
        m = re.search(r"Username:\s+(\S+)\s+Password:\s+(\S+)", v)
        if m:
            print(f"[Q9] credentials   : {m.group(1)}:{m.group(2)}")
```

Run it:

```bash
python3 paperghost_solve.py "$BASE" "$WORK"
```

Expected output:

```
[Q1] first connect : 2026-08-19 15:35:50
[Q2] serial        : RS200000000627E4  (instance id: RS200000000627E4&0)
[Q3] payload path  : E:\CO-LT-0469 update package\update.exe
[Q4] executed at   : 2026-08-19 15:36:25  (runs: 1)
[Q5] device name   : CO-USB-0091
[Q6] mic start     : 2026-08-19 15:38:08
[Q7] webcam secs   : 126.98  -> 127
[Q8] BytesSent     : 172064531  -> 172.064531 MB
[Q9] credentials   : tainsworth:D10g3n3s_T1ck3ts#2026
```

The pieces above were each run separately during the lab. This combined version stitches them together, so if a line misbehaves, run its section from above on its own.

---

## 8. Timeline (UTC)

| Time | Event | Source |
|------|-------|--------|
| 2026-08-19 ~13:42 | `DIOGENES_26` folder and its PDFs created on Voss's Desktop | LNK / shell item metadata |
| 13:44 | REDRAGON Live Camera hardware first appears | USB enum |
| 15:34 | `Driver Update Package.pdf` and `IT_SUPPORT.pdf` accessed | LNK access times |
| **15:35:50** | **Lexar USB (`CO-USB-0091`, S/N `RS200000000627E4`) first connected** | USBSTOR `0064` |
| **15:36:25** | **`E:\CO-LT-0469 update package\update.exe` executed** | UserAssist |
| **15:38:08 - 15:41:03** | **Microphone captured (~175 s)** | CAM ConsentStore |
| 15:38:27 | `EXT-0419.pdf` accessed (the Ainsworth profile with creds) while mic was live | LNK access time |
| **15:42:28 - 15:44:35** | **Webcam streamed (~127 s)** | CAM ConsentStore |
| 15:51:06 | USB removed | USBSTOR `0067` |
| 2026-08-20 08:21 | KAPE triage collected | KAPE CopyLog |

Over the whole run, `update.exe` sent ~172 MB out to the C2 (SRUM).

The 15:38:27 hit is my own correlation: the `EXT-0419.pdf` LNK access time falls inside the mic capture window. That ties the credentials to something Voss had on screen while the spyware was listening.

---

## 9. IOCs

| Type | Value |
|------|-------|
| Payload path | `E:\CO-LT-0469 update package\update.exe` |
| USB vendor / product | Lexar USB Flash Drive, `VID_21C4&PID_0CD1` |
| USB serial | `RS200000000627E4` |
| USB asset name | `CO-USB-0091` (volume label `VTOYEFI`) |
| Victim host / user | `CO-LT-0469` / `CO-LT-0469\cvoss` |
| Exfil volume | 172,064,531 bytes sent |
| Exposed account | `tainsworth` on `srv-diogenes-tickets-01.internal` |

Likely ATT&CK mapping (my read, not from the challenge): T1091 (removable media), T1204.002 (user execution), T1123 (audio capture), T1125 (video capture), T1041 (exfiltration over C2), T1552.001 (credentials in files).

---

## 10. Lessons and dead ends

- **The `.lnk` files were decoys for the payload.** They all point at PDFs on `C:\` in `DIOGENES_26`. They are useful for timing (what Voss opened and when) but they don't name the malware. The payload came from UserAssist.
- **BAM had nothing for the payload.** BAM only records local-disk executables, and this ran from `E:`. UserAssist and CAM are the ones that see removable-drive executions.
- **No PDFs and no Amcache in this triage.** Q9 only works because Windows Search stores extracted text (`AutoSummary`) for indexed documents.
- **Mic/webcam keys live in NTUSER for user-launched programs**, not in the SOFTWARE hive.
- **Plugin names aren't answers.** `wpdbusenum` and `esedbexport` are the tool names. The answers were the friendly name inside that plugin's output, and the summed `BytesSent` from SRUM.
- **Don't trim long lines with `cut`.** The AutoSummary line is one huge line and `cut -c1-300` hid the credentials until I printed it in full with `fold`.
- **Replay transaction logs**, and check they aren't empty first (`ntuser.dat.LOG1` was 0 bytes here, so LOG2-only was the way).
- **Timestamps:** registry is UTC. The host is UTC-7 (Pacific), so if a platform ever wants local time, subtract 7 hours (15:35:50 UTC = 08:35:50 local).
