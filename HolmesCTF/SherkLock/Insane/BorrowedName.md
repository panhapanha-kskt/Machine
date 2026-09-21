# Holmes CTF 2026: Sherlock DIOGENES Challenge Analysis

**Educational Purpose Only** — This document details forensic analysis techniques and incident response methodology applied to a fictional Active Directory incident in the HTB Holmes CTF 2026 competition.

---

## Challenge Overview

**Challenge Name:** DIOGENES Active Directory Incident  
**Difficulty:** Insane  
**Scenario:** A sophisticated multi-stage attack chain targeting Active Directory infrastructure, involving C2 beacon deployment, lateral movement, and privilege escalation through custom exploitation.

### Artifacts Provided
- Disk image: `Q3_Salary_Review.img` (FAT32 filesystem)
- Network capture: `capture.pcapng` (HTTP/TCP traffic)
- Event logs: `Microsoft-Windows-NTLM%4Operational.evtx`
- Supporting documentation: PDF describing attack phases

---

## Investigation Methodology

### Phase 1: Initial Enumeration

#### Filesystem Analysis
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

#### Key Observation
The presence of both `winupdate.exe` and `version.dll` in the same directory strongly suggests **DLL search-order hijacking** — a classic sideload technique where the executable looks for dependencies in its local directory first.

---

### Phase 2: Network Traffic Analysis

#### Beacon Traffic Extraction

Using packet analysis on `capture.pcapng`:

```bash
tshark -r capture.pcapng -q -z follow,tcp,ascii,0 | grep "X-Beacon-Id"
```

**Sample beacon header:**
```
X-Beacon-Id: Cl7gY6So2/cT4yDjuRKh1/IIIliFthBvHdi8nHSIZZzsxjYE8JPn813viEOOLb5ZseRfO8DwChiYClLzDqjyf0eDVXoNvAc6Vfrqw/m0oGhyeHUBMdyO87QiBJ3T4BacpHsA0A2W8UW/vbcTyJE6BG+ByNMSSQMzNvQ=
```

This header is base64-encoded and encrypted — the key to decryption lies in the binary itself.

---

### Phase 3: Binary Analysis

#### PE File Inspection

Using `radare2` and `pefile`:

```bash
r2 -A mnt/winupdate.exe
afl          # List all functions
izz          # Extract all strings
```

**Key findings:**
- **No crypto imports** — indicates custom cipher implementation (not using CNG/CAPI)
- **No direct exports** — typical for headless C2 agent
- **Pipe reference:** `\\.\pipe\%08lx` — named pipe for inter-process communication
- **HTTP header:** Suggests HTTP-based C2 communication

#### High-Entropy Block Identification

Scanning for constants and keys in `.rdata` section:

```bash
hexdump -C mnt/winupdate.exe | grep -A 5 "high-entropy region"
```

**Discovery at offset 0x15904:**
```
4580221ac3fe51be1797524a048e552d
```

This 16-byte sequence shows high entropy consistent with a cryptographic key (RC4 key or similar).

---

### Phase 4: Cryptographic Recovery

#### RC4 Key Testing

RC4 encryption reuses the same keystream for each message when using a fixed key, making it vulnerable if you can find the key.

**Hypothesis:** Test if the high-entropy block at 0x15904 is the profile encryption key for the C2.

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

# Test the key against beacon header
profile_key = bytes.fromhex("4580221ac3fe51be1797524a048e552d")
beacon_b64 = "Cl7gY6So2/cT4yDjuRKh1/IIIliFthBvHdi8nHSIZZzsxjYE8JPn813viEOOLb5ZseRfO8DwChiYClLzDqjyf0eDVXoNvAc6Vfrqw/m0oGhyeHUBMdyO87QiBJ3T4BacpHsA0A2W8UW/vbcTyJE6BG+ByNMSSQMzNvQ="
beacon_data = base64.b64decode(beacon_b64)
plaintext = rc4(profile_key, beacon_data)
print(plaintext.hex())
```

**Result:**
```
be4c0149 58debcbb                           <- Agent type ID, Beacon ID
00000010 53fc4c03c7b461befe5dcb268e3d9208   <- Session Key (16 bytes)
00000011 "core.diogenes.htb"                <- Domain
00000004 "WS02"                             <- Hostname
00000008 "afenwick"                         <- Username
0000000d "winupdate.exe"                    <- Process name
```

**Success!** The decryption reveals:
- **Profile Encryption Key:** `4580221ac3fe51be1797524a048e552d`
- **Agent-Generated Session Key:** `53fc4c03c7b461befe5dcb268e3d9208`
- **Agent Identity:** Running as `afenwick` on `WS02` in domain `core.diogenes.htb`

---

### Phase 5: Payload Decryption

#### Session Key Usage

Once the session key is recovered, decrypt all C2 response payloads:

```python
session_key = bytes.fromhex("53fc4c03c7b461befe5dcb268e3d9208")

# Extract all server responses from HTTP frames
frames_to_decrypt = [26, 44, 91, 151, 183, 229, 259, 286, 316, 408, 441, 491, 609, 730, 746, 823, 890]

for frame_num in frames_to_decrypt:
    encrypted_blob = extract_frame_payload(frame_num)
    plaintext = rc4(session_key, encrypted_blob)
    strings = extract_ascii_strings(plaintext)
    save_binary(f"dec_{frame_num}.bin", plaintext)
    print(f"Frame {frame_num}: {len(plaintext)} bytes")
    for s in strings[:15]:
        print(f"  {s}")
```

#### Payload Classifications

**Frame 26/44/91: Network Reconnaissance BOF**
- Strings: `WS2_32`, `InetNtopW`, `inet_pton`, `Interface List`, `Active Routes`
- Purpose: Enumerate network configuration and routing table
- Type: Go-compiled BOF with .xdata, .pdata, .rdata sections

**Frame 151/183/229/259/316/408/491: LDAP Query BOF (repeated)**
- Identical headers across multiple frames
- Likely shared loader stub or duplicated task
- Size: ~11KB average

**Frame 730/746: Credential/Security Descriptor Enumeration**
- Size: ~70KB (largest payload)
- Distinct .rdata layout
- Likely reads and parses security descriptors

**Frame 823: Token Impersonation BOF** ⭐ *Critical*
- Strings: "The user impersonated successfully: %ls\%s (logon: %d) [elevated]"
- Strings: "Failed to impersonate user. Error: %d", "Failed to create token. Error: %d"
- Imports: `GetTokenInformation`, `LogonUserW`, `BeaconUseToken`, `BeaconUseToken`
- Purpose: Privilege escalation via token impersonation
- Size: 2286 bytes

**Frame 890: Lateral Movement / Service Hijack BOF** ⭐ *Critical*
- Strings: "Trying to connect to %s", "Uploading binary (%lu bytes) to: %s"
- Strings: "OpenSCManagerA failed", "Opening service: %s", "SC_HANDLE Manager: 0x%p"
- Imports: CreateFileA, WriteFile, OpenSCManagerA, OpenServiceA, ChangeServiceConfigA, StartServiceA
- Purpose: SMB-based file upload + service path hijacking + execution
- Size: ~107KB

---

### Phase 6: Active Directory Analysis

#### Security Descriptor Extraction

From decrypted frame 494 (41KB of pure ACL enumeration):

**Target:** `CN=afenwick,OU=Analysts,OU=Staff,DC=core,DC=diogenes,DC=htb`  
**ObjectSID:** `S-1-5-21-2253468260-689643353-167204612-1125`

**Critical ACE (ACE #4):**
```
ACEType:                  ACCESS_ALLOWED_OBJECT_ACE
ACEFlags:                 None
ActiveDirectoryRights:    WriteProperty
ObjectAceType GUID:       28630ebb-41d5-11d1-a9c1-0000f80367c1
SecurityIdentifier:       S-1-5-21-2253468260-689643353-167204612-1125 (afenwick himself)
```

**Interpretation:**
- `afenwick` has **self-write** rights on a schema property
- The GUID `28630ebb-41d5-11d1-a9c1-0000f80367c1` maps to an attribute relevant for account manipulation
- This enables **UPN spoofing** — the core technique of ResetNightmare

---

### Phase 7: Lateral Movement Tracking

#### Service Hijacking Details

From Frame 896 (896 bytes, service hijack payload):

**Strings extracted:**
```
Trying to connect to %s
Uploading binary (%lu bytes) to: \\dc02\ADMIN$\svc_bkup
Binary uploaded successfully (%lu bytes written)
Opening service: defragsvc
SC_HANDLE Manager: 0x%p
SC_HANDLE Service: 0x%p
LPQUERY_SERVICE_CONFIGA needs 0x%08x bytes
Original service binary path: "%s"
ChangeServiceConfigA failed to update the service path: %ld
Service path was changed to: "%s"
StartServiceA failed to start the service: %ld
Service was started
ChangeServiceConfigA failed to revert the service path: %ld
Service path was restored to: "%s"
```

**Attack Flow:**
1. Connect to target via SMB (`\\dc02\ADMIN$`)
2. Upload malicious binary (svc_bkup) to ADMIN share
3. Open Service Control Manager handle
4. Locate existing service: `defragsvc`
5. Query current service configuration
6. **Hijack:** Replace binary path with uploaded malware
7. Start the compromised service (now runs malware)
8. **Cover tracks:** Restore original service path
9. Service continues running under SYSTEM context

---

### Phase 8: Second Beacon Discovery

#### New C2 Agent on DC02

Extract from stream 1 (DC02 victim):

```bash
tshark -r capture.pcapng -q -z follow,tcp,ascii,1 | grep "X-Beacon-Id"
```

**Decrypt with profile key (same as first beacon):**

```python
profile_key = bytes.fromhex("4580221ac3fe51be1797524a048e552d")
new_beacon_b64 = "Cl7gYyGw6OsT4yDjuRKh1/IIIliFthBvHdi8nHSSzaXAxjYny5Pn813viE+OLb5Zyokx9xmNd8GN3lrTwjie00eDVXoNvAc6Vfrqw/m0oGhyeHUBMdyO87QxFJ3T4Bacqkk/5jek1SbUvb9gs4UMCHGE3A=="
plaintext = rc4(profile_key, base64.b64decode(new_beacon_b64))
```

**Result:**
```
be4c0149 ddc68fa7                          <- New Beacon ID
00000004 00000000                          <- Flags
0000000f 00
00000010 289122cf1ec91c67eb89c30642adfea4  <- New Session Key
00000011 "core.diogenes.htb"               <- Same domain
00000004 "DC02"                            <- New host (domain controller!)
00000006 "SYSTEM"                          <- Running as SYSTEM
00000008 "svc_bkup"                        <- Process name (uploaded service)
```

**Significance:**
- Second beacon confirms successful lateral movement
- Agent now running as SYSTEM on domain controller
- Maintains communication on separate session key
- Complete compromise of infrastructure

---

## Answer Key

| Question | Answer | Evidence |
|----------|--------|----------|
| **Q1: C2 Framework** | Adaptix | Beacon header format, pipe naming, HTTP-based communication, BOF staging pattern |
| **Q2: Encryption Keys** | `53fc4c03c7b461befe5dcb268e3d9208:4580221ac3fe51be1797524a048e552d` | SessionKey:ProfileKey extracted from decrypted beacon check-in |
| **Q3: Privesc CVE** | CVE-2026-27912 (ResetNightmare) | Frame 732 plaintext: `[*] Action: ResetNightmare (CVE-2026-27912)` |
| **Q4: Impersonation BOF Hash** | `9c0628eb5cda2fe4f6aea9032f3b9f8c` | md5sum of decrypted frame 823 |
| **Q5: UPN Write SID** | `S-1-5-21-2253468260-689643353-167204612-1125` | ACE #4 SecurityIdentifier with WriteProperty right on afenwick |
| **Q9: Logon Type** | 9 | Frame 823 output: "logon: 9" — Network logon type |
| **Q10: Lateral Move Path** | `\\192.168.56.11\ADMIN$\svc_bkup` | Frame 896 upload path, resolved DC02 IP from DNS resolution |
| **Q11: Service Name** | `defragsvc` | Frame 896: "Opening service: defragsvc" |
| **Q12: Second Beacon ID** | `be4c0149ddc68fa7:289122cf1ec91c67eb89c30642adfea4` | Decrypted check-in from DC02, BeaconID:SessionKey format |

---

## Key Forensic Techniques

### 1. **Cryptographic Key Recovery from Binaries**
- Scan .rdata sections for high-entropy blocks
- Cross-reference against network traffic
- RC4 key reuse creates exploitable patterns

### 2. **C2 Beacon Protocol Reverse Engineering**
- Extract HTTP headers and JSON/plaintext encoding
- Map protocol structure: length prefixes, field ordering
- Session keys are agent-generated and sent in first check-in

### 3. **Binary Artifact Classification**
- PE headers, sections (.xdata, .pdata, .rdata)
- String extraction for functionality identification
- Import table analysis (ADVAPI32 = privilege/service operations)

### 4. **Active Directory Attack Chain Reconstruction**
- Security descriptor parsing reveals permission abuse
- Object ACEs (ObjectAceType GUID) map to schema attributes
- Property-level permissions enable targeted exploitation (UPN spoofing, credential manipulation)

### 5. **Lateral Movement Forensics**
- Service hijacking leaves traces in service configuration
- Binary upload indicators: temp files, ADMIN$ shares
- Second beacon confirms success and persistence

---

## Technical References

**Frameworks & Tools:**
- radare2 (binary analysis)
- pefile (PE parsing)
- tshark (packet extraction)
- guestmount (filesystem mounting)
- RC4 cryptanalysis (stream cipher)

**Techniques:**
- DLL Sideloading (DLL search order hijacking)
- Service Path Hijacking (lateral movement)
- Token Impersonation (privilege escalation)
- ResetNightmare/UPN Spoofing (credential manipulation)
- LDAP-based enumeration (Active Directory reconnaissance)

**C2 Concepts:**
- Beacon Check-in Protocol (agent registration)
- Session Key Negotiation (per-agent encryption)
- Profile Key (shared configuration key in binary)
- BOF Staging (downloading and executing compiled offensive functions)

---

## Defensive Takeaways

1. **Monitor DLL Loads** — Detect unexpected DLL sideloading via ProcessMonitor, ETW
2. **Service Auditing** — Alert on unexpected service binary path changes
3. **LDAP Monitoring** — Unusual security descriptor queries indicate reconnaissance
4. **C2 Detection** — Baseline HTTP user-agents, detect anomalous beacon patterns
5. **Credential Hygiene** — Limit Write permissions on schema attributes (especially UPN)
6. **Lateral Movement Prevention** — Restrict ADMIN$ access, use Session 0 isolation

---

**Document Version:** 1.0  
**Last Updated:** 2026-09-21  
**Classification:** Educational - CTF Analysis
