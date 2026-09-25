# Silent Room — Forensics (Medium)

**CTF:** CSCV Jeopardy 2026
**Category:** Forensics
**Flag:** `CSCV2026{F04nd_h3r_4t_401_HanaRiverSide_DaNang_fm0923812}`

## Scenario

A 17-year-old girl ("A") left home under unclear circumstances. Family lost contact
and reported it. We're given a 2 GiB EWF (E01) disk image extracted from her
laptop and asked to determine her current room, hotel, and province/city.

## Provided Evidence

- `evidence.E01` — EnCase 6 format disk image, 2.0 GiB, NTFS
- `evidence.E01.txt` — ewfinfo acquisition metadata (MD5: `abb90c7772c153b2d37633065e71f670`)
- `evidence_acquire.log` — MD5/SHA256 of the acquired data
- `SHA256SUMS.txt` — hashes for all provided files
- `README.txt` — challenge brief

## Step 1 — Verify and Mount the Image

```bash
ewfverify evidence.E01
# MD5 matches evidence.E01.txt -> integrity confirmed

mkdir /mnt/ewf
ewfmount evidence.E01 /mnt/ewf

mmls /mnt/ewf/ewf1
# NTFS partition starts at sector 128
```

Mount the NTFS partition read-only:

```bash
mkdir -p /mnt/case
mount -t ntfs-3g -o ro,remove_hiberfile,offset=$((128*512)) /mnt/ewf/ewf1 /mnt/case
```

(The kernel `ntfs3` driver rejected `show_sys_files` as an unknown mount
option — `ntfs-3g` in FUSE space handled it fine.)

## Step 2 — Triage the File System

```bash
tree -L 4 /mnt/case/Users
```

Single user profile, `A`:

```
Users/A
├── AppData/Local/Google/Chrome/...      # browser history + cache
├── AppData/Local/Programs/ChatApp/      # custom chat client (app.bundle.js)
├── AppData/Roaming/ChatApp/             # Local State + msg_cache.db
├── Documents/Personal/todo.txt
├── Documents/Scholarship/application_autosave.txt
├── Downloads/booking_BAB_403_receipt.html
├── Downloads/notice_217.pdf
└── Pictures/Camera Roll/IMG_2026080[1-13]_personal.jpg   # 13 decoy JPEGs
```

The 13 "personal" photos were checked for GPS EXIF and steganography
(`exiftool`, `xxd`, `binwalk`) — all came back as plain, unremarkable
JPEGs. **Dead end / red herring**, confirmed and abandoned early.

## Step 3 — Reconstruct the Narrative

**`notice_217.pdf`** (Vietnamese): a fraudulent "financial verification" notice
impersonating an investigation unit ("Tổ công tác FI-217"), demanding a video
call, camera on, no contact with family — a textbook **scam/social-engineering
script** used to isolate and control a victim.

**`booking_BAB_403_receipt.html`**: an early hotel booking — Babarian Hotel,
Room 403, Da Nang, status `CONFIRMED`. This looked like the answer on the
surface, but the ChatApp messages later explicitly warn this is an **outdated
decoy** — the reservation was cancelled and superseded.

**Chrome History** (`sqlite3` query on `urls`/`visits`, converting WebKit
epoch with `datetime(ts/1000000-11644473600,'unixepoch')`) laid out the
timeline:

1. Scholarship portal submission
2. Fake verification notice opened
3. Panic searches ("làm việc với công an qua video call có đúng không",
   "tài khoản ngân hàng liên quan rửa tiền phải làm sao")
4. Search for flights/buses Hanoi → Da Nang
5. Bus ticket booked (NorthStar Express, PNR `NSE1842`)
6. **First** hotel booking: `BAB-403DN` (Babarian Hotel, Room 403) — later cancelled
7. **Second** hotel booking: `HSR-260820-0401` (the real, current one)
8. A `cyberchef xor file utf8 key` search — the biggest tell that something
   later in the case needs manual XOR decryption

## Step 4 — Decrypt the ChatApp Messages (AES-256-CBC)

`msg_cache.db` (SQLite) held 15 messages between the victim and
`fi-operator-73` (the scammer), each encrypted as:

```json
{"v":2,"kid":"chatapp-web-v2","alg":"AES-256-CBC","iv":"...","ct":"..."}
```

The client's own source, `app.bundle.js`, revealed the key derivation:

```js
deriveKey(peer, caseId) {
  return sha256([kid, peer, caseId].join("|"))
}
```

`peer` (`fi-operator-73`) and `caseId` (`FI-217`) were both recoverable from
`Local State` and the notice PDF. Full decryption script:

```python
import sqlite3, json, base64
from hashlib import sha256
from Crypto.Cipher import AES

DB = ".../ChatApp/msg_cache.db"
KID, PEER, CASE_ID = "chatapp-web-v2", "fi-operator-73", "FI-217"

def derive_key():
    return sha256(f"{KID}|{PEER}|{CASE_ID}".encode()).digest()

def unpad(d):
    return d[:-d[-1]]

def decrypt_msg(body, key):
    m = json.loads(body)
    iv, ct = base64.b64decode(m["iv"]), base64.b64decode(m["ct"])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct)).decode()

conn = sqlite3.connect(DB)
for mid, direction, body, ts in conn.execute(
        "SELECT id, direction, body, created_at FROM messages ORDER BY id"):
    print(mid, direction, decrypt_msg(body, derive_key()))
```

The decrypted conversation is the scammer's full isolation script (classic
"stay silent, don't call family, don't leave camera" coercion) — and message
15 is the critical pivot:

> *"Thứ tự chuỗi đối chiếu: Mã PNR vé xe | trạng thái đặt phòng bằng chữ |
> Số phòng | tên nơi ở viết liền | tỉnh thành viết liền."*

Translation: the XOR key is built by pipe-joining, **in this exact order**:

```
BusTicketPNR | BookingStatus(word) | RoomNumber | AccommodationNameNoSpaces | ProvinceNoSpaces
```

Earlier messages also confirm the old Babarian booking is a stale decoy and
that only the **current** reservation state is valid — the trap most solvers
would fall into by using the first booking they find.

## Step 5 — Find the Real, Current Reservation

The cache metadata file `f_000088` pointed at the target:

```
object=f_000089
content=image/png after byte transform
operation=XOR
key_format=UTF-8
key_recipe=decrypt ChatApp messages before building the XOR key
```

The second reservation (`HSR-260820-0401`) was never downloaded to disk —
only cached by Chrome. Recovering the raw cache blobs:

```bash
for f in .../Cache/Cache_Data/*; do file "$f"; done
```

turned up two rendered PNGs (`f_000033`, `f_000054`) plus supporting JSON
(`f_000041`). OCR (`tesseract`) on the screenshots gave the missing pieces:

- Bus ticket: **PNR `NSE1842`**
- Hotel confirmation: **Property `Hana River Side`**, **Province `Da Nang`**,
  reservation `HSR-260820-0401`, booking token `R8QK-72M-19`
- The room number itself is only in the *live* reservation state JSON
  (`f_000041`): **`roomNumber: 401`**, `state: 2` (→ `confirmed` per the
  state-enum script in `f_000020`)

## Step 6 — Build the XOR Key and Decrypt

```
NSE1842|confirmed|401|HanaRiverSide|DaNang
```

```python
key = "NSE1842|confirmed|401|HanaRiverSide|DaNang".encode()

with open(".../Cache/Cache_Data/f_000089", "rb") as f:
    data = f.read()

out = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

with open("/tmp/proof.png", "wb") as f:
    f.write(out)
```

Output validated as a clean PNG (`89 50 4E 47 0D 0A 1A 0A` magic bytes
intact) — no offset correction needed.

## Step 7 — Flag

The recovered PNG was a "recovered note on room desk" image confirming the
victim was located, containing the flag directly:

```
CSCV2026{F04nd_h3r_4t_401_HanaRiverSide_DaNang_fm0923812}
```

## Key Takeaways / Technique Summary

| Stage | Artifact | Technique |
|---|---|---|
| Recon | E01 image | `ewfverify`, `ewfmount`, `mmls`, `ntfs-3g` mount |
| Red herring | 13 Camera Roll JPEGs | EXIF/binwalk check — confirmed clean, no payload |
| Narrative | PDF, HTML receipt, browser history | Vietnamese scam-script OSINT, WebKit timestamp conversion |
| Decoy detection | Old vs. new hotel reservation | Don't trust the first/only booking found — cross-reference chat context |
| Crypto layer 1 | `msg_cache.db` | AES-256-CBC, key = `SHA256(kid\|peer\|caseId)` reconstructed from app source + Local State |
| Data recovery | Chrome disk cache | Recovered un-downloaded page state (JSON + rendered PNG screenshots) via `file` + `tesseract` OCR |
| Crypto layer 2 | `f_000089` | XOR with a key **derived from unlocked plaintext of layer 1**, built from a precise pipe-delimited recipe |
| Final flag | Decoded PNG | Direct text in recovered image |

**Core lesson:** this challenge chains two independent crypto layers where
the key for the second is only derivable *after* solving the first, and
deliberately plants a plausible-but-stale decoy (cancelled reservation) to
punish solvers who stop at the first lead instead of validating against the
live/current state.
