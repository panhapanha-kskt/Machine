# Sherlock Lab Writeup — "2: Bottle Out"

**Category:** Digital Forensics / DFIR
**Scenario:** Bottle Out
**Analysis VM:** BLUEBOX (Windows 10.0.17763.2114)
**Evidence Source:** `DESKTOP-QMTIG5I.E01` (13.9 GB EnCase disk image, target host)
**Target user profile identified:** `spur`
**Tools used:** FTK Imager 4.7.3.81, Autopsy 4.23.1, PowerShell 5.1, `reg.exe`

---

## 1. Scenario Setup

Access was provided via RDP into an analysis workstation (`BLUEBOX`), pre-loaded with a
DFIR toolkit under `C:\Tools\` (Forensics, EZ-Tools, Networking, Security, Utilities,
etc.). The actual evidence was not on the live filesystem of BLUEBOX itself — it was a
single disk image sitting on the Administrator's Desktop:

```
C:\Users\Administrator\Desktop\DESKTOP-QMTIG5I.E01   (13,916,086,049 bytes)
```

The box is air-gapped (no internet egress — confirmed when `Get-ZimmermanTools.ps1`
failed to resolve `raw.githubusercontent.com`), so all analysis was done with the
tools already present in `C:\Tools`.

### Evidence acquisition / mounting
The `.E01` was opened directly in **FTK Imager** (`File → Add Evidence Item → Image
File`), which parsed it as an NTFS volume and exposed a `spur` user profile (in
addition to the default Windows accounts), identifying `spur` as the target user of
the investigation.

---

## 2. Investigation Timeline & Methodology

### 2.1 Recon of the target user profile
Enumerated `Users\spur\AppData`, `Program Files`, `Program Files (x86)`, and
`ProgramData` to identify non-stock software. Key artifacts found:

| Location | Finding |
|---|---|
| `spur\Downloads` | `OpenVPN-2.7.6-I001-amd64.msi`, `Gajim-Portable-2.6.0-64bit.exe` |
| `Program Files\TacticalAgent` | Remote monitoring & management (RMM) agent install |
| `Windows\Prefetch` | `OPENVPN.EXE`, `OPENVPN-GUI.EXE`, `GAJIM-PORTABLE...EXE`, `GAJIM.EXE` — all executed 2026-09-01 |
| `Users\spur\NTUSER.DAT` | Registry hive for the `spur` user profile |

### 2.2 RMM Agent identification (Q4–Q6)

**Q4 — Agent name & version**

Command:
```powershell
(Get-Item "D:\Program Files\TacticalAgent\tacticalrmm.exe").VersionInfo | Format-List *
```

Evidence (relevant fields):
```
ProductName        : Tactical RMM Agent
ProductVersion     : v2.11.0.0
CompanyName        : AmidaWare Inc
FileDescription    : Tactical RMM Agent
```

✅ **Answer: `Tactical RMM Agent v.2.11.0`** *(confirmed correct)*

**Q5 — RMM callback domain & Q6 — Auth token**

The Tactical RMM Windows agent stores its live configuration in the registry, not a
flat file. The image's `SOFTWARE` hive was loaded read-only and queried directly:

```powershell
reg load HKLM\sw_temp2 "D:\Windows\System32\config\SOFTWARE"
reg query "HKLM\sw_temp2\TacticalRMM" /s
reg unload HKLM\sw_temp2
```

Evidence:
```
HKEY_LOCAL_MACHINE\sw_temp2\TacticalRMM
    BaseURL    REG_SZ    https://api.antimattercommunication.xyz
    AgentID    REG_SZ    HYlezOqYIjpJGWxfUkEQgUbYzDzReiejGHslxkTH
    ApiURL     REG_SZ    api.antimattercommunication.xyz
    Token      REG_SZ    98ec588da683c01820232943a6151e8e7772419b
    AgentPK    REG_SZ    4
```

✅ **Q5 Answer: `api.antimattercommunication.xyz`**
✅ **Q6 Answer: `98ec588da683c01820232943a6151e8e7772419b`** (40-hex-char SHA-1)

### 2.3 "Operation Vanish" — malicious cleanup script (Q7)

PowerShell console-host event logs (`Windows PowerShell.evtx`) were copied off the
read-only image to a writable location and parsed with `Get-WinEvent`, since `.evtx`
files cannot be opened directly from a read-only mounted volume:

```powershell
mkdir C:\Temp -Force
Copy-Item "D:\Windows\System32\winevt\Logs\Windows PowerShell.evtx" "C:\Temp\WindowsPowerShell.evtx" -Force
Get-WinEvent -Path "C:\Temp\WindowsPowerShell.evtx" |
  Where-Object { $_.Message -match "Remove-Item|pipeline" } |
  Select-Object TimeCreated, Message | Format-List
```

This surfaced a provider-start event logging the full `HostApplication` command line —
a base64 `-EncodedCommand` invocation, timestamped **2026-09-01 05:37:40 PDT**:

```
HostApplication=powershell -NonI -NoP -W 1 -Enc IwAgAE8AcABlAHIAYQB0AGkAbwBuACAAVgBhAG4A...
```

Decoded (UTF-16LE, standard PowerShell `-EncodedCommand` format):

```powershell
$b64 = "IwAgAE8AcABlAHIAYQB0AGkAbwBuACAAVgBhAG4AaQBzAGgACgAkAGYAbwBsAGQAZQByAHMAIAA9ACAAQAAoAAoAIAAgACAAIAAiAEMAOgBcAFUAcwBlAHIAcwBcAHMAcAB1AHIAXABHAGEAagBpAG0AIgAsAAoAIAAgACAAIAAiAEMAOgBcAFUAcwBlAHIAcwBcAHMAcAB1AHIAXABPAHAAZQBuAFYAUABOACIALAAKACAAIAAgACAAIgBDADoAXABWAFAATgAiAAoAKQAKAGYAbwByAGUAYQBjAGgAIAAoACQAZgBvAGwAZABlAHIAIABpAG4AIAAkAGYAbwBsAGQAZQByAHMAKQAgAHsACgAgACAAIAAgAFIAZQBtAG8AdgBlAC0ASQB0AGUAbQAgAC0ATABpAHQAZQByAGEAbABQAGEAdABoACAAJABmAG8AbABkAGUAcgAgAC0AUgBlAGMAdQByAHMAZQAgAC0ARgBvAHIAYwBlAAoAfQAKAA=="
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64))
```

Decoded output:
```powershell
# Operation Vanish
$folders = @(
    "C:\Users\spur\Gajim",
    "C:\Users\spur\OpenVPN",
    "C:\VPN"
)
foreach ($folder in $folders) {
    Remove-Item -LiteralPath $folder -Recurse -Force
}
```

This is an anti-forensic cleanup script that deleted the Gajim (IM client) config, the
OpenVPN client config, and a `C:\VPN` staging folder — explaining why none of those
locations existed on the live filesystem during initial triage.

Matching against the given mask `*********** ************ *:\*****\****\***** ******** ******`:
- `Remove-Item` (11) / `-LiteralPath` (12) / `C:\`+`Users`(5)+`spur`(4)+`Gajim`(5) / `-Recurse`(8) / `-Force`(6) — exact character-count fit for the **first** loop iteration.

✅ **Answer: `Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force`** *(confirmed correct)*

*(For reference, the full three commands executed by the loop were, in order:*
1. *`Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force`*
2. *`Remove-Item -LiteralPath C:\Users\spur\OpenVPN -Recurse -Force`*
3. *`Remove-Item -LiteralPath C:\VPN -Recurse -Force`)*

### 2.4 VPN artifacts (Q1–Q3) — in progress

Confirmed via Prefetch that `openvpn.exe` and `openvpn-gui.exe` executed on
2026-09-01 ~05:20–05:21 AM. Registry evidence (`HKU\spur\Software\OpenVPN-GUI`,
loaded from `NTUSER.DAT`) confirmed a saved connection profile named `spur`:

```
HKEY_USERS\spur_hive\Software\OpenVPN-GUI
    auto_restart_list    REG_MULTI_SZ    spur
```

However, per Section 2.3, the actual `.ovpn` config directory
(`C:\Users\spur\OpenVPN`) and the `C:\VPN` staging folder were deleted by "Operation
Vanish" and are no longer present in the live filesystem view. Live-view checks
confirmed this:

```powershell
Test-Path "D:\Users\spur\Gajim"    # False
Test-Path "D:\Users\spur\OpenVPN"  # False
Test-Path "D:\VPN"                 # False
```

**Next step:** deleted-file recovery via **Autopsy 4.23.1**, ingesting the same
`.E01` and using the *Deleted Files* / keyword search views to recover the orphaned
`.ovpn` config (or fragments of it) from unallocated space, in order to extract:
- Q1: VPN server remote address:port (`remote` directive / connection log)
- Q2: Issuing CA of the client certificate (`<ca>` block / cert `Issuer CN`)
- Q3: Client IP assigned by the VPN server (`ifconfig`/`push` reply or lease)

*(Status: Autopsy case created, `DESKTOP-QMTIG5I.E01` added as data source, ingest
in progress at time of writing. Deleted-file recovery not yet completed.)*

### 2.5 Instant messaging client (Q8–Q10) — in progress

Identified from Prefetch and Downloads:
```
D:\Users\spur\Downloads\Gajim-Portable-2.6.0-64bit.exe
D:\Windows\Prefetch\GAJIM-PORTABLE-2.6.0-64BIT.EX-9B24BAA7.pf   (executed 2026-09-01 01:50 AM)
D:\Windows\Prefetch\GAJIM.EXE-EDCE70B8.pf                        (executed 2026-09-01 05:25 AM)
```

**Gajim** is an XMPP/Jabber instant-messaging client. Its live config directory
(`C:\Users\spur\Gajim`) was the first target deleted by the "Operation Vanish"
script (Section 2.3), so:
- Q8 (XMPP account / JID used to connect)
- Q9 (account password)
- Q10 (full name of "the jailer", expected to be recoverable from chat history or
  contact roster within the same deleted config)

are all pending recovery of the deleted `C:\Users\spur\Gajim` folder via Autopsy's
deleted-file view or unallocated-space carving, same as the VPN artifacts above.

---

## 3. Findings Summary

| # | Question | Status | Answer |
|---|---|---|---|
| 1 | VPN server remote address:port | ⏳ Pending | Deleted config — pending Autopsy recovery |
| 2 | VPN client cert issuing CA | ⏳ Pending | Deleted config — pending Autopsy recovery |
| 3 | IP assigned by VPN server | ⏳ Pending | Deleted config — pending Autopsy recovery |
| 4 | RMM agent name & version | ✅ Solved | `Tactical RMM Agent v.2.11.0` |
| 5 | RMM agent FQDN | ✅ Solved | `api.antimattercommunication.xyz` |
| 6 | RMM agent auth token (SHA-1) | ✅ Solved | `98ec588da683c01820232943a6151e8e7772419b` |
| 7 | First command in Operation Vanish | ✅ Solved | `Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force` |
| 8 | IM account (email/JID) | ⏳ Pending | Deleted config — pending Autopsy recovery |
| 9 | IM account password | ⏳ Pending | Deleted config — pending Autopsy recovery |
| 10 | Full name of the jailer | ⏳ Pending | Deleted config — pending Autopsy recovery |

---

## 4. Key Artifacts Referenced

- `C:\Users\Administrator\Desktop\DESKTOP-QMTIG5I.E01` — primary evidence container
- `D:\Program Files\TacticalAgent\tacticalrmm.exe` — RMM agent binary
- `D:\Windows\System32\config\SOFTWARE` (registry hive) — `TacticalRMM` config key
- `D:\Users\spur\NTUSER.DAT` (registry hive) — `OpenVPN-GUI` MRU
- `D:\Windows\System32\winevt\Logs\Windows PowerShell.evtx` — encoded command execution log
- `D:\Windows\Prefetch\OPENVPN*.pf`, `GAJIM*.pf` — execution evidence for both deleted apps
- `D:\Users\spur\Downloads\OpenVPN-2.7.6-I001-amd64.msi`, `Gajim-Portable-2.6.0-64bit.exe`

---

## 5. Lessons / Notes for Future Runs

- The analysis VM's own OpenVPN connection (used to reach the lab infrastructure
  itself) is **not** part of the case evidence — it's easy to mistake its live
  connection log for the target's VPN artifact. Always distinguish the analyst
  workstation's own network state from the evidence contained in the mounted image.
- `.lnk` shortcuts under `C:\Tools\*` frequently point to `scoop`-installed binaries
  under `C:\ProgramData\scoop\apps\<name>\current\`, not standard `Program Files`
  paths. When a shortcut fails to launch as expected, resolve its real `TargetPath`
  with:
  ```powershell
  (New-Object -ComObject WScript.Shell).CreateShortcut("<path-to-lnk>").TargetPath
  ```
- `.evtx` files cannot be parsed by `Get-WinEvent` directly from a read-only mounted
  image — copy them to a writable path first.
- Attackers/threat actors cleaning up with `Remove-Item -Recurse -Force` via an
  encoded PowerShell command is a common anti-forensic technique; the deleted data
  is frequently still recoverable from unallocated NTFS clusters as long as the
  volume hasn't seen significant write activity since deletion — hence the pivot to
  Autopsy for carving once live-view paths came back empty.

---

*Writeup compiled during live investigation; VPN and IM sections will be updated
with final confirmed answers once deleted-file recovery in Autopsy completes.*
