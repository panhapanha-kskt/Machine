# HackerVerse September 2026 — Level 1: Cryptic Canvas

> **Event:** HackerVerse September 2026 (EC-Council iLabs), Digital Forensics edition
> **Level:** 1 — Cryptic Canvas (audio, image and encoded-text steganography)
> **Platform:** Kali Linux VM (`root` / `toor`)
> **Artifacts:** `/root/Stego Artifacts/Audio.wav`, `/root/Stego Artifacts/Cat.jpg`, `/root/Encoded Artifact/Encoded_Dump.txt`
> **Date solved:** 2026-10-05

---

## Answer Summary

| # | Challenge | Answer |
|---|-----------|--------|
| 1 | The Hidden Voice — Morse in `Audio.wav` | `flag{binary_audio_secrets}` |
| 2 | Stego Cat — JFIF start marker | `FF D8 FF E0` |
| 3 | Stego Cat — flag in corrupted `Cat.jpg` | `CTF{steg0_1s_co0l}` |
| 4 | Camouflage — decoding sequence from the 2nd hint | `Base58 → ROT13 → Base64 → XOR (Hex Key: 342120)` |
| 5 | Camouflage — final hidden flag | `FLAG{ViCtOrYaChIeVeD}` |

---

## Challenge 1 — The Hidden Voice

### Scenario
> An audio file named `Audio.wav` was recovered during an investigation. It is suspected that the file contains a hidden message encoded using Morse code. Decode the flag.
> **Answer format:** `flag{xxxxxx_xxxxx_xxxxxxx}`

### TL;DR
The audio is Morse code, but every Morse character is either `-----` (**0**) or `.----` (**1**). The Morse spells out **binary**: 208 digits, which are 26 bytes of ASCII, which give `flag{binary_audio_secrets}`.

### Step 1 — Look at the file
```bash
cd "/root/Stego Artifacts"
ls -la
audacity Audio.wav &
```
- `Audio.wav` is **5,423,588 bytes**.
- Audacity showed a waveform about **8 minutes** long that looks loud almost everywhere, with only thin gaps. That's far too long to transcribe by ear or from screenshots, so I decoded it with a script.

> ⚠️ Run Audacity with `&` at the end. Without it, the terminal is blocked until Audacity closes. If it starts playing, press **Space** to stop it.

### Step 2 — Find the real audio format (the key discovery)
The first decoder attempts gave garbage: a single `E`, then a long repeating `.- - - - … --` pattern. Printing the WAV parameters showed why:

```python
import wave
w = wave.open('Audio.wav'); print(w.getparams())
```
```
_wave_params(nchannels=1, sampwidth=1, framerate=11050, nframes=5423544,
             comptype='NONE', compname='not compressed')
```

| Field | Value | Meaning |
|---|---|---|
| `nchannels` | 1 | mono |
| `sampwidth` | **1** | **8-bit unsigned PCM** (samples 0–255, silence = 128) |
| `framerate` | 11050 Hz | |
| `nframes` | 5,423,544 | 5,423,544 / 11050 ≈ **490.8 s ≈ 8 min 11 s** |

**Root cause of the garbage output:** the script read the samples as `int16`. With 8-bit audio, that glues pairs of samples together and destroys the on/off envelope. The fix is to read them as `uint8` and subtract the mean to remove the 128 DC offset.

### Step 3 — Measure the timing
After switching to `uint8`, a histogram of the tone (ON) and silence (OFF) lengths, rounded to 10 ms, gave clean groups:

```
ON  [(50, 115), (200, 925)]
OFF [(10, 1), (100, 832), (1020, 207)]
```

| Element | Length | Count | Interpretation |
|---|---|---|---|
| Short tone | ~50 ms | 115 | **dot** (`.`) |
| Long tone | ~200 ms | 925 | **dash** (`-`) |
| Short gap | ~100 ms | 832 | gap between elements of one character |
| Long gap | ~1020 ms | 207 | gap **between characters** |

207 character gaps means **208 Morse characters**.

### Step 4 — Decode the Morse
The decoded stream contains only two distinct characters:

```
- - - - - / . - - - - / . - - - - / - - - - - / - - - - - / . - - - - / . - - - - / - - - - - / ...
```

| Morse | Character |
|---|---|
| `-----` | `0` |
| `.----` | `1` |

So the Morse message is a string of **208 binary digits** (208 = 26 × 8), which is **26 ASCII bytes**. The flag format `flag{xxxxxx_xxxxx_xxxxxxx}` is also exactly 26 characters long.

### Step 5 — Binary to ASCII

| Bits | Morse | Char |
|---|---|---|
| 01100110 | ----- .---- .---- ----- ----- .---- .---- ----- | f |
| 01101100 | ----- .---- .---- ----- .---- .---- ----- ----- | l |
| 01100001 | ----- .---- .---- ----- ----- ----- ----- .---- | a |
| 01100111 | ----- .---- .---- ----- ----- .---- .---- .---- | g |
| 01111011 | ----- .---- .---- .---- .---- ----- .---- .---- | { |
| 01100010 | ----- .---- .---- ----- ----- ----- .---- ----- | b |
| 01101001 | ----- .---- .---- ----- .---- ----- ----- .---- | i |
| 01101110 | ----- .---- .---- ----- .---- .---- .---- ----- | n |
| 01100001 | ----- .---- .---- ----- ----- ----- ----- .---- | a |
| 01110010 | ----- .---- .---- .---- ----- ----- .---- ----- | r |
| 01111001 | ----- .---- .---- .---- .---- ----- ----- .---- | y |
| 01011111 | ----- .---- ----- .---- .---- .---- .---- .---- | _ |
| 01100001 | ----- .---- .---- ----- ----- ----- ----- .---- | a |
| 01110101 | ----- .---- .---- .---- ----- .---- ----- .---- | u |
| 01100100 | ----- .---- .---- ----- ----- .---- ----- ----- | d |
| 01101001 | ----- .---- .---- ----- .---- ----- ----- .---- | i |
| 01101111 | ----- .---- .---- ----- .---- .---- .---- .---- | o |
| 01011111 | ----- .---- ----- .---- .---- .---- .---- .---- | _ |
| 01110011 | ----- .---- .---- .---- ----- ----- .---- .---- | s |
| 01100101 | ----- .---- .---- ----- ----- .---- ----- .---- | e |
| 01100011 | ----- .---- .---- ----- ----- ----- .---- .---- | c |
| 01110010 | ----- .---- .---- .---- ----- ----- .---- ----- | r |
| 01100101 | ----- .---- .---- ----- ----- .---- ----- .---- | e |
| 01110100 | ----- .---- .---- .---- ----- .---- ----- ----- | t |
| 01110011 | ----- .---- .---- .---- ----- ----- .---- .---- | s |
| 01111101 | ----- .---- .---- .---- .---- .---- ----- .---- | } |

### ✅ Flag
```
flag{binary_audio_secrets}
```
It matches the format: `binary` (6), `audio` (5), `secrets` (7).

### Full solver script (`solve.py`)
This is a cleaned-up version of the script used during the solve. It handles 8-bit and 16-bit audio and does the Morse → binary → ASCII steps in one run.

```python
import wave
import numpy as np

w = wave.open('Audio.wav')
p = w.getparams()                      # (nchannels, sampwidth, framerate, nframes, ...)
dtype = 'uint8' if p[1] == 1 else 'int16'
a = np.frombuffer(w.readframes(p[3]), dtype=dtype).astype(float)
a = a.reshape(-1, p[0])[:, 0]          # first channel only
a = abs(a - a.mean())                  # remove DC offset (8-bit audio is centred on 128)
k = int(p[2] / 100)                    # 10 ms smoothing window
e = np.convolve(a, np.ones(k) / k, 'same')
on = e > (np.percentile(e, 10) + np.percentile(e, 99)) / 2

# run-length encode the on/off signal
r = []
n = 1
for i in range(1, len(on)):
    if on[i] == on[i-1]:
        n += 1
    else:
        r.append((on[i-1], n))
        n = 1
r.append((on[-1], n))

u = min(n for v, n in r if v)          # shortest tone = one Morse unit
c = ''
for v, n in r:
    if v:
        c += '.' if n < 2*u else '-'
    elif n > 5*u:
        c += ' / '
    elif n > 2*u:
        c += ' '

groups = [g.replace(' ', '') for g in c.split('/') if g.strip()]
bits = ''.join('0' if g == '-----' else '1' for g in groups)
print('Morse groups:', len(groups))
print('Bits:', bits)
print('Flag:', ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits) - 7, 8)))
```
```bash
python3 solve.py
```

### Troubleshooting log (what went wrong along the way)
| Symptom | Cause | Fix |
|---|---|---|
| `SyntaxError` on `code += sym = ' '` | typo while retyping | `code += sym + ' '` |
| `AttributeError: ... 'getchannels'` | missing `n` | `getnchannels()` or `getparams()[0]` |
| Output was only `E` | data read as `int16` + threshold `max*0.3` | percentile threshold, then `uint8` |
| Endless ` / - / - / - ...` | `n += 1` instead of `n = 1` after appending a run | reset `n = 1` |
| Repeating `.- - - … --` pattern | **8-bit audio read as 16-bit** | `dtype='uint8'` |
| `sed: unterminated 's' command` | missing `/` delimiter | retype carefully, or skip that step |

> 💡 The lab VM does **not** allow clipboard paste, so every command had to be typed by hand. Keep scripts short, use `nano`, and check with `cat file` after editing. Use `| head -1` and `| tail -3` to keep long output manageable.

### Lessons learned
- **Check the WAV parameters first** (`sampwidth`, `framerate`, `nchannels`). Many decoding bugs come from reading the wrong sample width.
- 8-bit WAV is **unsigned**, so silence is 128, not 0. Remove the DC offset before thresholding.
- If decoded Morse only uses `0` and `1`, the message is **binary in Morse**, a second encoding layer. Here 208 digits ÷ 8 = 26 bytes, the same length as the flag.
- Use the answer format (`flag{6_5_7}` = 26 chars) to sanity-check results before spending one of your limited attempts.

---

## Challenge 2 — JFIF Start Marker

**Q:** What is the hexadecimal marker that starts a JPEG File Interchange Format file? (Format `XX XN XX XN`)

| Bytes | Name | Meaning |
|---|---|---|
| `FF D8` | SOI | Start Of Image — every JPEG starts with this |
| `FF E0` | APP0 | JFIF application segment (followed by `4A 46 49 46 00` = `JFIF\0`) |

### ✅ Answer
```
FF D8 FF E0
```

---

## Challenge 3 — Stego Cat

### Scenario
> A suspicious image `Cat.jpg` is believed to contain data hidden with steganography. Analyse the file structure, recover the hidden artifact, and decode the flag.
> **Answer format:** `CTF{xxxxN_Nx_xxNx}`

### Step 1 — Inspect the header
```bash
xxd Cat.jpg | head -5
```
```
00000000: 00d8 ffe0 0010 4a46 4946 0001 0100 0001  ......JFIF......
00000010: 0001 0000 ffdb 0043 0009 0607 0807 0609  .......C........
```
The first byte is **`00`** but should be **`FF`**. The SOI marker `FF D8` is broken, so image viewers and `steghide` refuse the file. Everything else (`FF E0`, `JFIF`, `FF DB` quantisation table) is intact.

### Step 2 — Repair the first byte
```bash
cp Cat.jpg f.jpg                                  # work on a copy; the original is read-only
printf '\xff' | dd of=f.jpg conv=notrunc          # overwrite byte 0 with 0xFF
xxd f.jpg | head -1
```
```
00000000: ffd8 ffe0 0010 4a46 4946 0001 0100 0001  ......JFIF......
```
The image now opens (`xdg-open f.jpg`). It shows a 197×148 photo of a kitten raising its paw on a blue background, with no visible text. `strings` and `binwalk` showed nothing appended to the file.

### Step 3 — Extract the hidden artifact with steghide
```bash
steghide extract -sf f.jpg -p ""
```
```
wrote extracted data to "flag.txt".
```
The passphrase was **empty**. (`steghide info f.jpg` reports a capacity of 244 bytes.)

### Step 4 — Decode
```bash
cat flag.txt
# Q1RGe3N0ZWcwXzFzX2NvMGx9
echo Q1RGe3N0ZWcwXzFzX2NvMGx9 | base64 -d
# CTF{steg0_1s_co0l}
```

### ✅ Flag
```
CTF{steg0_1s_co0l}
```
It matches the format `CTF{xxxxN_Nx_xxNx}`: `steg0`, `1s`, `co0l`.

### Lessons learned
- Corrupting the **magic bytes** is a common way to stop tools from working. Always compare the header against the expected signature.
- `steghide` only works on valid JPEG/BMP/WAV/AU files, so repair the file first, then extract.
- Try an **empty passphrase** first. If that fails, use `stegseek` with `rockyou.txt`.

---

## Challenges 4 & 5 — Camouflage

### Scenario
> A leaked paste dump contains five Base64-looking strings: decoys, hints, and one genuine secret. Find the correct decoding sequence and recover the flag.
> **Artifact:** `/root/Encoded Artifact/Encoded_Dump.txt`

### The dump
```
--- BEGIN TRANSMISSION ---
Z3ZkRG9mSXdlTFVRazF2
2A6fz3V1RQkk4RgpctzF5bPYFCaCXsLLb7Jxot4
R3E5aUR0YlFoeFdFeVla
LmVubyB0c3VqIHNpIGV1cnQgLHN5b2NlZCBlcmEgb3dU                                   #You are your own reflection
UHJvY2VzczogQmFzZTU4IOKGkiBST1QxMyDihpIgQkFTRTY0IOKGkiBYT1IgKEhleCBLZXk6IDM0MjEyMCk  #Ai is good, but you are the best with CyberChef
--- END TRANSMISSION ---
```

### Classifying each line (Base64-decode first)
| Line | Base64 decoded | Role |
|---|---|---|
| 1 | `gvdDofIweLUQk1v` | decoy (random) |
| 2 | *(binary garbage, not valid Base64 text)* | **the secret**, written in the Base58 alphabet |
| 3 | `Gq9iDtbQhxWEyYZ` | decoy (random) |
| 4 | `.eno tsuj si eurt ,syoced era owT` | **hint 1**, reversed ("You are your own reflection") → *"Two are decoys, true is just one."* |
| 5 | `Process: Base58 → ROT13 → BASE64 → XOR (Hex Key: 342120)` | **hint 2**, the recipe |

### ✅ Challenge 4 answer
```
Base58 → ROT13 → Base64 → XOR (Hex Key: 342120)
```

### Applying the recipe to line 2
| Step | Operation | Output |
|---|---|---|
| 0 | input | `2A6fz3V1RQkk4RgpctzF5bPYFCaCXsLLb7Jxot4` |
| 1 | Base58 decode | `pz1up1c2KJWHr1A5IJWVsHE2HJIq` |
| 2 | ROT13 | `cm1hc1p2XWJUe1N5VWJIfUR2UWVd` |
| 3 | Base64 decode | `rmasZv]bT{SyUbH}DvQe]` |
| 4 | XOR with key `34 21 20` (repeating) | `FLAG{ViCtOrYaChIeVeD}` |

The XOR check on the first bytes: `r`(0x72)⊕0x34 = `F`, `m`(0x6D)⊕0x21 = `L`, `a`(0x61)⊕0x20 = `A`, and so on.

### Solver (Python)
```python
import base64, codecs
A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58(s):
    n = 0
    for c in s: n = n * 58 + A.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

s = b58('2A6fz3V1RQkk4RgpctzF5bPYFCaCXsLLb7Jxot4').decode()
s = codecs.encode(s, 'rot13')
s = base64.b64decode(s)
k = bytes.fromhex('342120')
print(bytes(c ^ k[i % 3] for i, c in enumerate(s)).decode())
# FLAG{ViCtOrYaChIeVeD}
```
**CyberChef recipe:** `From Base58` → `ROT13` → `From Base64` → `XOR (key 342120, HEX)`.

### ✅ Challenge 5 flag
```
FLAG{ViCtOrYaChIeVeD}
```

### Lessons learned
- A string that won't Base64-decode cleanly but uses only `1-9A-HJ-NP-Za-km-z` (no `0`, `O`, `I`, `l`) is a strong sign of **Base58**.
- Comments in the dump were hints ("reflection" means reversed text, "CyberChef" means a chained recipe).
- Decode every line first and classify them before you commit to an MCQ answer (only 2 attempts).

---

## Tools Used
| Tool | Purpose |
|---|---|
| `xxd`, `strings`, `binwalk`, `exiftool` | file structure / header inspection |
| `dd`, `printf` | byte-level header repair |
| `steghide` | JPEG steganography extraction |
| `audacity` | waveform / spectrogram inspection |
| Python 3 + `wave` + `numpy` | Morse audio decoding |
| `base64`, Python, CyberChef | Base58 / ROT13 / Base64 / XOR chain |
