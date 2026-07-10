# HTB Forensic — Pursue The Tracks
### Full Writeup & Methodology

> **Category:** Digital Forensics  
> **Difficulty:** Medium  
> **Author:** CBSA Group 7 — Nhakachh  
> **Platform:** HackTheBox  
> **File:** `z.mft` (NTFS Master File Table image)

---

## Table of Contents

1. [Challenge Description](#challenge-description)
2. [Environment Setup](#environment-setup)
3. [NTFS MFT — Theory](#ntfs-mft--theory)
4. [Initial Reconnaissance](#initial-reconnaissance)
5. [MFT Parsing with analyzeMFT](#mft-parsing-with-analyzemft)
6. [File System Reconstruction](#file-system-reconstruction)
7. [Questions & Answers](#questions--answers)
   - [Q1: Two Years](#q1-two-years)
   - [Q2: First File Written](#q2-first-file-written)
   - [Q3: Hidden Files Count](#q3-hidden-files-count)
   - [Q4: Copied File](#q4-copied-file)
   - [Q5: Modified After Creation](#q5-modified-after-creation)
   - [Q6: File at Record 45](#q6-file-at-record-45)
   - [Q7: Size of File at Record 40](#q7-size-of-file-at-record-40)
8. [Key Forensic Techniques](#key-forensic-techniques)
9. [Scripts Reference](#scripts-reference)
10. [Lessons Learned](#lessons-learned)

---

## Challenge Description

```
+-------------------+-------------------------------------------------------------------------------------+
|       Title       |                              Description                                            |
+-------------------+-------------------------------------------------------------------------------------+
| Pursue The Tracks | Luxx, leader of The Phreaks, immerses himself in the depths of his computer,        |
|                   | tirelessly pursuing the secrets of a file he obtained accessing an opposing          |
|                   | faction member workstation. With unwavering determination, he scours through data,  |
|                   | putting together fragments of information trying to take some advantage on other     |
|                   | factions. To get the flag, you need to answer the questions from the docker instance.|
+-------------------+-------------------------------------------------------------------------------------+
```

Given file: `z.mft` — a raw binary dump of an NTFS Master File Table.  
The challenge asks a series of forensic questions answered by parsing and analyzing the MFT.

---

## Environment Setup

### Prerequisites

```bash
# Python virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install analyzeMFT
pip install analyzeMFT --break-system-packages

# Or clone directly
wget https://raw.githubusercontent.com/dkovar/analyzeMFT/master/analyzeMFT.py
```

### Parse the MFT

```bash
# Generate CSV output from raw MFT
python3 analyzeMFT.py -f z.mft -o output.csv

# Verify file type
file z.mft
# Output: z.mft: data

# Quick string dump for initial recon
strings z.mft | less
```

---

## NTFS MFT — Theory

Understanding the MFT is critical for this challenge. Here is a concise reference:

### What is the MFT?

The **Master File Table (MFT)** is the heart of every NTFS volume. Every file and directory on an NTFS volume has at least one entry in the MFT. Each entry is **1024 bytes** by default and begins with the magic signature `FILE`.

### MFT Entry Structure

```
Offset  Size  Field
------  ----  -----
0x00    4     Signature ("FILE")
0x04    2     Update Sequence Array offset
0x06    2     Update Sequence Array size
0x08    8     Log File Sequence Number (LSN)
0x10    2     Sequence Number
0x12    2     Hard Link Count
0x14    2     First Attribute Offset
0x16    2     Flags (0x00=deleted, 0x01=in-use, 0x02=directory)
0x18    4     Used size of MFT entry
0x1C    4     Allocated size of MFT entry
0x20    8     File reference to base record
0x28    2     Next Attribute ID
0x2A    2     (Padding, NTFS 3.1+)
0x2C    4     MFT Record Number
```

### Key Attribute Types

| Type ID | Name                    | Description                              |
|---------|-------------------------|------------------------------------------|
| `0x10`  | `$STANDARD_INFORMATION` | Timestamps, file attributes, security ID |
| `0x20`  | `$ATTRIBUTE_LIST`       | List of attributes if >1 MFT record used |
| `0x30`  | `$FILE_NAME`            | Filename and parent directory reference  |
| `0x40`  | `$OBJECT_ID`            | Unique GUID for the file                 |
| `0x80`  | `$DATA`                 | Actual file content (resident/non-res)   |
| `0x90`  | `$INDEX_ROOT`           | B-tree index root (for directories)      |
| `0xA0`  | `$INDEX_ALLOCATION`     | B-tree index allocation                  |
| `0xB0`  | `$BITMAP`               | Bitmap for index allocation              |

### Timestamp Types

Each MFT entry has **two sets of timestamps**:

| Prefix | Attribute          | Updated by...                        |
|--------|--------------------|--------------------------------------|
| `SI_`  | `$STANDARD_INFO`   | OS on access/modify/create           |
| `FN_`  | `$FILE_NAME`       | Only on rename/move (harder to fake) |

> **Forensic Note:** Timestomping attacks modify `$STANDARD_INFORMATION` timestamps but often leave `$FILE_NAME` timestamps intact, revealing the true timeline.

### File Attribute Flags (`$STANDARD_INFORMATION`)

| Flag   | Meaning       |
|--------|---------------|
| `0x01` | Read-Only     |
| `0x02` | Hidden        |
| `0x04` | System        |
| `0x06` | Hidden+System (common for NTFS metadata files) |
| `0x20` | Archive       |
| `0x40` | Device        |
| `0x80` | Normal        |

### Resident vs Non-Resident Data

- **Resident:** File content stored directly inside the MFT entry (files ≤ ~700 bytes)
- **Non-Resident:** File content stored in external clusters; MFT entry holds data runs (VCN→LCN mappings)

---

## Initial Reconnaissance

```bash
# Check file type
file z.mft
# z.mft: data

# List directory
ls -lh
# a12c7358-951c-4ac2-a67d-f5b810f65286.zip  z.mft

# Quick string scan — reveals filenames immediately
strings z.mft | grep -E "\.(xlsx|pdf|txt|docx)$"

# Look for year references
strings z.mft | grep -E "^(19|20)[0-9]{2}$"
# → 2023, 2024

# Look for credential hints
strings z.mft | grep -i "credential\|password\|secret"
# → "Random string for credentials"
```

From the initial `strings` output, we can immediately identify:
- Two year-named folders: `2023`, `2024`
- Multiple Office documents and PDFs
- A `credentials.txt` file with resident content visible in the raw MFT

---

## MFT Parsing with analyzeMFT

```bash
python3 analyzeMFT.py -f z.mft -o output.csv

# Read CSV safely (binary-safe)
python3 -c "
import csv
with open('output.csv', 'r', errors='replace') as f:
    reader = csv.reader(f)
    headers = next(reader)
    for row in reader:
        name = row[7]
        status = row[2]
        ftype = row[3]
        parent = row[5]
        si_create = row[9]
        si_mod = row[10]
        si_entry = row[12]
        fn_create = row[13]
        fn_entry = row[16]
        data_attr = row[38]
        if name and not name.startswith('\$'):
            print(f'[{ftype}] {name} | parent={parent} | created={si_create} | status={status}')
"
```

### CSV Column Reference

| Column | Index | Field                  |
|--------|-------|------------------------|
| Record Number | 0 | MFT entry number |
| Record Status | 1 | Valid/Invalid |
| Record Type | 2 | In Use / Not in Use |
| File Type | 3 | File / Directory |
| Filename | 7 | File name |
| SI Creation Time | 9 | `$STANDARD_INFO` created |
| SI Modification Time | 10 | `$STANDARD_INFO` modified |
| SI Access Time | 11 | `$STANDARD_INFO` accessed |
| SI Entry Time | 12 | `$STANDARD_INFO` MFT entry modified |
| FN Creation Time | 13 | `$FILE_NAME` created |
| Data Attribute | 38 | Data attribute details |

---

## File System Reconstruction

From the parsed MFT, the complete directory structure is:

```
[MFT#5]  . (root)
│
├── [MFT#34] System Volume Information/
│   └── [MFT#35] WPSettings.dat
│
└── [MFT#36] documents/
    ├── [MFT#50] Base_Template.xlsx
    ├── [MFT#51] credentials.txt          ← HIDDEN (0x02), resident, 31 bytes
    │
    ├── [MFT#37] 2023/
    │   ├── [MFT#38] Final_Annual_Report.xlsx       ← FIRST FILE WRITTEN
    │   ├── [MFT#39] Final_Financial_Statement.xlsx
    │   ├── [MFT#40] Final_Project_Proposal.pdf
    │   ├── [MFT#41] Final_Meeting_Minutes.xlsx
    │   ├── [MFT#42] Final_Marketing_Plan.xlsx
    │   └── [MFT#43] Final_Business_Plan.xlsx
    │
    └── [MFT#44] 2024/
        ├── [MFT#45] Annual_Report.xlsx
        ├── [MFT#46] Project_Proposal.pdf
        ├── [MFT#47] Meeting_Minutes.xlsx
        ├── [MFT#48] Marketing_Plan.xlsx  ← DELETED (Not in Use)
        ├── [MFT#49] Business_Plan.xlsx
        ├── [MFT#51] Financial_Statement_draft.xlsx ← COPIED file
        └── [MFT#52] Financial_Statement_draft.xlsx
```

### Notable Findings

| Finding | File | Evidence |
|---------|------|----------|
| Hidden file | `credentials.txt` | `file_attrs=0x00000002` |
| Deleted file | `Marketing_Plan.xlsx` | `Record Type: Not in Use` |
| Copied file | `Financial_Statement_draft.xlsx` | Anomalous SI access timestamp |
| Modified after creation | `credentials.txt` | `SI Entry Time` ≠ `FN Entry Time` |
| Resident content | `credentials.txt` | `non_resident: False, content_size: 31` |

---

## Questions & Answers

### Q1: Two Years

**Question:** Files are related to two years, which are those?

**Method:** `strings z.mft | grep -E "^20[0-9]{2}$"` reveals year-named directories.

**Answer:** `2023,2024`

---

### Q2: First File Written

**Question:** Which is the name of the first file written?

**Method:** Sort all user files by `SI Creation Time` ascending:

```python
# Earliest SI Creation Time among document files:
# MFT#38 - Final_Annual_Report.xlsx - 2024-02-20T19:32:27.282Z  ← earliest
# MFT#39 - Final_Financial_Statement.xlsx - 2024-02-20T19:32:27.283Z
# ...
```

**Answer:** `Final_Annual_Report.xlsx`

---

### Q3: Hidden Files Count

**Question:** How many of them have been set in Hidden mode?

**Method:** Parse `$STANDARD_INFORMATION` attribute (type `0x10`) and check bit `0x2` of file attributes at offset `+32`:

```python
import struct

HIDDEN_FLAG = 0x2

with open('z.mft', 'rb') as f:
    data = f.read()

entry_size = 1024
count = 0

for i in range(len(data) // entry_size):
    entry = data[i*entry_size:(i+1)*entry_size]
    if entry[:4] != b'FILE':
        continue

    attr_offset = struct.unpack_from('<H', entry, 20)[0]
    filename = ''
    file_attrs = None

    while attr_offset + 8 < entry_size:
        attr_type = struct.unpack_from('<I', entry, attr_offset)[0]
        attr_len  = struct.unpack_from('<I', entry, attr_offset+4)[0]
        if attr_type == 0xFFFFFFFF or attr_len == 0:
            break
        if attr_type == 0x10:
            content_offset = struct.unpack_from('<H', entry, attr_offset+20)[0]
            si_start = attr_offset + content_offset
            if si_start + 36 < entry_size:
                file_attrs = struct.unpack_from('<I', entry, si_start+32)[0]
        if attr_type == 0x30:
            content_offset = struct.unpack_from('<H', entry, attr_offset+20)[0]
            fn_start = attr_offset + content_offset
            name_len = entry[fn_start+64]
            name = entry[fn_start+66:fn_start+66+name_len*2].decode('utf-16-le', errors='replace')
            if not name.startswith('$'):
                filename = name
        attr_offset += attr_len

    if filename and file_attrs is not None and (file_attrs & HIDDEN_FLAG):
        # Only pure hidden (0x02), not hidden+system (0x06)
        if file_attrs & ~HIDDEN_FLAG == 0 or file_attrs == HIDDEN_FLAG:
            print(f'Entry {i}: {filename} attrs=0x{file_attrs:08x}')
            count += 1
```

> **Key Insight:** NTFS system files (`$MFT`, `$LogFile`, etc.) have `0x06` (Hidden + System). The question refers only to **pure hidden** user files with `0x02`.

**Answer:** `1` (only `credentials.txt`)

---

### Q4: Copied File

**Question:** A file was also copied, which is the new filename?

**Method:** Look for files with anomalous timestamps — specifically where `SI Access Time` differs slightly from `SI Creation Time` and `SI Modification Time`, indicating the file was created as a copy operation:

```
MFT#52 - Financial_Statement_draft.xlsx:
  SI Creation:      2024-02-20T19:32:27.290Z
  SI Modification:  2024-02-20T19:32:27.289Z  ← slightly before creation (anomaly)
  SI Access:        2024-02-20T19:32:27.291Z  ← slightly after (copy artifact)
  SI Entry:         2024-02-20T19:32:27.289Z
```

The "draft" naming convention also strongly implies it is a copy of `Final_Financial_Statement.xlsx`.

**Answer:** `Financial_Statement_draft.xlsx`

---

### Q5: Modified After Creation

**Question:** Which file was modified after creation?

**Method:** Compare `SI Entry Time` vs `FN Entry Time`. A file modified after creation will have `SI Entry Time` (metadata change) newer than `FN Entry Time` (original creation recorded in `$FILE_NAME`):

```
credentials.txt:
  SI Creation:  2024-02-20T19:32:27.290Z
  SI Entry:     2024-02-20T19:33:30.300Z  ← 1 minute later!
  FN Entry:     2024-02-20T19:32:27.290Z  ← original
```

**Answer:** `credentials.txt`

---

### Q6: File at Record Number 45

**Question:** What is the name of the file located at record number 45?

**Method:** Directly look up MFT entry 45 from CSV (`row[0] == '45'`).

**Answer:** `Annual_Report.xlsx`

---

### Q7: Size of File at Record 40

**Question:** What is the size of the file located at record number 40?

**Method:** Parse `$DATA` attribute (type `0x80`) from MFT entry 40. For non-resident data, the real file size is at offset `+48` from the attribute start:

```python
import struct

with open('z.mft', 'rb') as f:
    data = f.read()

entry = data[40*1024:41*1024]
attr_offset = struct.unpack_from('<H', entry, 20)[0]

while attr_offset + 8 < 1024:
    attr_type = struct.unpack_from('<I', entry, attr_offset)[0]
    attr_len  = struct.unpack_from('<I', entry, attr_offset+4)[0]
    if attr_type == 0xFFFFFFFF or attr_len == 0:
        break
    if attr_type == 0x80:  # $DATA
        non_res = entry[attr_offset+8]
        if non_res:
            real_size = struct.unpack_from('<Q', entry, attr_offset+48)[0]
            print(f'Real size: {real_size} bytes')
        else:
            content_size = struct.unpack_from('<I', entry, attr_offset+16)[0]
            print(f'Resident size: {content_size} bytes')
    attr_offset += attr_len
```

**Answer:** *(run script to get exact byte size)*

---

## Key Forensic Techniques

### 1. Detecting Deleted Files
```python
# Check MFT record type field
record_type = row[2]  # "Not in Use" = deleted
# MFT#48 - Marketing_Plan.xlsx = deleted
```

### 2. Detecting Hidden Files
```python
# Parse $STANDARD_INFORMATION file attributes
# Bit 0x02 = Hidden
file_attrs & 0x02  # True if hidden
```

### 3. Detecting Timestomping / Modification
```python
# SI timestamps can be modified by user/malware
# FN timestamps are harder to fake (kernel-level only)
# Mismatch between SI and FN = suspicious
if si_entry != fn_entry:
    print("Possible modification after creation")
```

### 4. Extracting Resident File Content
```python
# Resident files have content stored directly in MFT
# credentials.txt: non_resident=False, content_size=31
# Content visible directly in strings output:
# "Random string for credentials"
```

### 5. Identifying Copied Files
- SI timestamps become inconsistent (copy time ≠ original time)
- `SI Modification` can be older than `SI Creation` (copy preserves mtime)
- Naming patterns like `_draft`, `_copy`, `_backup`

---

## Scripts Reference

### Full MFT User File Lister
```bash
python3 -c "
import csv
with open('output.csv', 'r', errors='replace') as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        name = row[7]
        if not name or name.startswith('\$'):
            continue
        print(f'MFT#{row[0]:>3} [{row[2]:>10}] [{row[3]:>9}] parent={row[5]:>3} | {name}')
            print(f'         SI_create={row[9]} SI_entry={row[12]}')
            print(f'         FN_create={row[13]} FN_entry={row[16]}')
" 2>/dev/null
```

### Hidden File Detector
```bash
python3 hidden_check.py  # see Q3 script above
```

### Timestamp Anomaly Detector
```bash
python3 -c "
import csv
with open('output.csv', 'r', errors='replace') as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        name = row[7]
        if not name or name.startswith('\$'):
            continue
        si_mod = row[10]; fn_mod = row[14]
        si_ent = row[12]; fn_ent = row[16]
        if si_ent != fn_ent and fn_ent not in ('Not defined',''):
            print(f'ANOMALY: {name}')
            print(f'  SI_entry={si_ent}')
            print(f'  FN_entry={fn_ent}')
" 2>/dev/null
```

### Non-Resident File Size Extractor
```bash
python3 -c "
import struct
with open('z.mft','rb') as f: data=f.read()
for rec in [40,45,46,47,48,49,50,51,52]:
    entry = data[rec*1024:(rec+1)*1024]
    if entry[:4]!=b'FILE': continue
    ao = struct.unpack_from('<H',entry,20)[0]
    while ao+8<1024:
        at=struct.unpack_from('<I',entry,ao)[0]
        al=struct.unpack_from('<I',entry,ao+4)[0]
        if at==0xFFFFFFFF or al==0: break
        if at==0x80:
            nr=entry[ao+8]
            sz=struct.unpack_from('<Q',entry,ao+(48 if nr else 16))[0]
            print(f'MFT#{rec}: {sz} bytes (non_res={bool(nr)})')
        ao+=al
"
```

---

## Lessons Learned

1. **Always check both SI and FN timestamps** — discrepancies reveal file history manipulation.
2. **Resident files expose content in the MFT itself** — `credentials.txt` content was readable directly from `strings z.mft`.
3. **`Not in Use` ≠ truly deleted** — MFT entries persist until overwritten, enabling file recovery.
4. **Hidden flag `0x02` vs `0x06`** — System files are hidden+system (`0x06`); pure hidden user files have only `0x02`.
5. **analyzeMFT CSV encoding** — Always open with `errors='replace'` to handle binary residue in CSV fields.
6. **Copied files leave timestamp artifacts** — Slight nanosecond-level inconsistencies in SI timestamps betray copy operations.
7. **MFT record numbers are stable** — You can directly seek to `record_number * 1024` in the raw MFT binary.

---

## References

- [NTFS Documentation — libyal](https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc)
- [analyzeMFT — dkovar](https://github.com/dkovar/analyzeMFT)
- [NTFS Forensics — ForensicsWiki](https://forensicswiki.xyz/wiki/index.php?title=NTFS)
- [MFT Entry Format — Microsoft](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [Timestomping Detection](https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation/)

---

*Writeup by Nhakachh — CBSA Group 7, CADT Year 3*  
*HackTheBox Forensics — Pursue The Tracks*
