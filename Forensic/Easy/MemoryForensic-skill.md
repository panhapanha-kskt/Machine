---
name: memory-forensics-volatility3
description: Answer memory-forensics / CTF questions (processes, network, registry, users, hidden files, flags) from a Windows memory dump using Volatility 3 on Windows PowerShell. Use when the user has a .raw/.mem/.vmem/.dmp memory image or a MemLabs-style quiz.
---

# Memory Forensics with Volatility 3 (Windows)

Use this skill to answer quiz or CTF questions about a Windows memory image (`.raw`, `.mem`, `.vmem`, `.dmp`). It covers setup, one recipe per common question type, and the mistakes that cost time in practice.

## 0. Ground rules for the agent

- **Answer from command output, never from memory.** Write-ups for public labs (e.g. MemLabs) exist, but the quiz may change questions. Every answer must trace to a plugin output line.
- **Never leave placeholders in commands.** Text like `0xOFFSET`, `{PASTE-GUID-HERE}` or `dump.raw` causes errors or empty results. Substitute real values from earlier output before giving a command.
- **If the user wants guidance, guide.** Give commands for the user to run and interpret what they paste back. Run tools yourself only when asked ("do another way", "run it", "find it for me").
- **Say when a question can't be answered from this image.** If a named process or file doesn't appear in pslist, psscan, pstree, netscan or filescan, report that and suggest the user ask which image the question uses. Don't invent an answer.
- Keep a running answer sheet. When the user asks for "only the answer" or "all answers", give a bare numbered list.

## 1. Setup

### 1.1 Volatility 3 standalone build
The Windows build (`volatility3-win-exes-x.y.z`) contains `vol.exe` and `volshell.exe`. They are command-line tools: double-clicking only flashes a window.

```powershell
cd "C:\path\to\volatility3-win-exes-2.28.2"
.\vol.exe -h
```

- `.\vol.exe` only works **from that folder**. "The term '.\vol.exe' is not recognized" means the shell is in another folder, so `cd` back.
- Quote any path that contains spaces.
- The first run on an image downloads Microsoft symbol files (PDBs). It needs internet and can take minutes.

### 1.2 Extract the image
Labs usually ship as `.7z`:
```powershell
cd C:\path\to\lab
tar -xf Lab.7z                      # built into Windows 11, may fail on some 7z
winget install 7zip.7zip            # if needed
& "C:\Program Files\7-Zip\7z.exe" x Lab.7z
```
Check that the extracted size matches the size the archive lists.

### 1.3 Convenience variable
```powershell
$img = "C:\path\to\MemoryDump.raw"
.\vol.exe -f $img windows.info
```
If `windows.info` prints the OS version, the image is readable.

## 2. Plugin cheat sheet

| Goal | Plugin |
|---|---|
| OS and image info | `windows.info` |
| Running processes (linked list) | `windows.pslist` |
| All process objects, incl. terminated or hidden | `windows.psscan` |
| Parent/child tree, with **Cmd** and **Path** columns | `windows.pstree` |
| Command line of a process | `windows.cmdline --pid N` |
| Console history | `windows.consoles`, `windows.cmdscan` |
| Network sockets | `windows.netscan` |
| Registry hives | `windows.registry.hivelist` |
| Registry key or values | `windows.registry.printkey --key "..." [--offset HIVE] [--recurse]` |
| Password hashes | `windows.registry.hashdump` (old name `windows.hashdump` is deprecated) |
| Files in memory | `windows.filescan` |
| Extract a file | `windows.dumpfiles --physaddr 0x...` / `--virtaddr 0x...` |
| Dump a process's memory | `windows.memmap --pid N --dump` |
| Injected code | `windows.malfind` |

Useful global options: `-q` (no progress line), `-r csv` (machine-readable), `-o DIR` (output folder for dumped files).

### Counting and filtering in PowerShell
```powershell
.\vol.exe -q -r csv -f $img windows.pslist > pslist.csv
$p = Import-Csv pslist.csv
$p.Count
$p | Where-Object { $_.ImageFileName -like "*name*" } | Format-Table PID, PPID, ImageFileName, CreateTime, ExitTime
$p[0]                                # shows the exact column names
Select-String -Path pslist.csv -Pattern "name"   # search every column
```

## 3. Recipes by question type

### 3.1 "What IP address did the machine get from DHCP?"
The address is stored in the SYSTEM hive:
`ControlSet001\Services\Tcpip\Parameters\Interfaces\{GUID}\DhcpIPAddress`

```powershell
.\vol.exe -f $img windows.registry.hivelist          # note the \REGISTRY\MACHINE\SYSTEM offset
.\vol.exe -f $img windows.registry.printkey --offset 0x<SYSTEM> --key "ControlSet001\Services\Tcpip\Parameters\Interfaces" --recurse | Select-String "Dhcp"
```
- Use **`ControlSet001`**, not `CurrentControlSet`. CurrentControlSet is a link Windows creates at boot and is often missing from images.
- Neighbouring values: `DhcpServer`, `DhcpSubnetMask`, `DhcpDefaultGateway`, `DhcpNameServer`, `DhcpDomain`.
- Cross-check with `windows.netscan`: the same IP should own NetBIOS ports 137, 138 and 139.
- `10.0.2.15` with server `10.0.2.2` is VirtualBox NAT. `VBoxService.exe` in pslist confirms a VirtualBox guest.

### 3.2 "How many active processes in pslist?"
Active means **ExitTime = N/A**.
```powershell
.\vol.exe -q -r csv -f $img windows.pslist > pslist.csv
$p = Import-Csv pslist.csv
"Total: " + $p.Count
"Active: " + ($p | Where-Object { $_.ExitTime -eq 'N/A' -or $_.ExitTime -eq '' }).Count
```

### 3.3 "How many processes, incl. terminated and hidden, found by psscan?"
```powershell
.\vol.exe -q -r csv -f $img windows.psscan > psscan.csv
$s = Import-Csv psscan.csv
$s.Count
```
- The quiz answer is normally the **raw psscan row count**.
- psscan can list the **same process several times**, because leftover copies of the process structure remain in memory. Explain the difference from pslist by grouping:
  ```powershell
  $s | Group-Object PID, ImageFileName | Where-Object Count -gt 1 | Format-Table Count, Name
  ```
- Don't compare pslist and psscan by `Offset(V)`. psscan's offsets are **physical** (`0x3e…`) and pslist's are **virtual** (`0xfa80…`), so they never match.
- Terminated processes have an ExitTime. Hidden processes are in psscan but not in pslist and have no ExitTime.

### 3.4 "What is the PID of process X?"
```powershell
$s | Where-Object { $_.ImageFileName -like "*X*" } | Format-Table PID, PPID, ImageFileName, CreateTime, ExitTime
```
Search psscan, not just pslist. `ImageFileName` is cut to 14 characters (e.g. `VBoxService.ex`, `SearchProtocol`), so use wildcards. If the name is absent everywhere, say so (see Ground rules).

### 3.5 "Which compressed file is being extracted?" / "What did process X open?"
```powershell
.\vol.exe -f $img windows.pstree          # Cmd column shows full command lines
.\vol.exe -f $img windows.cmdline --pid <WinRAR/7z PID>
```
The archive path is the argument after `WinRAR.exe` / `7zFM.exe`.

### 3.6 "Identify the users" (format `user1:user2`)
- In pstree's **Path/Cmd** columns, look for `C:\Users\<name>\…` paths.
- Confirm with `windows.registry.hivelist` (each user's `ntuser.dat`) or `windows.registry.hashdump`.
- Map sessions: each `explorer.exe` is a logged-on user's desktop. Its SessionId says which session the user's processes belong to.

### 3.7 "What IP does process X connect to?"
```powershell
.\vol.exe -f $img windows.netscan | Select-String "X"
```
Read the **ForeignAddr** column. If every foreign address is `*`, `0.0.0.0` or loopback, the image has no outbound connections, so the question can't be answered from it.

### 3.8 "Find the flag in the compressed file"
1. Locate the file: `.\vol.exe -f $img windows.filescan | Select-String "file.rar"`. Several offsets may appear; any of them may work.
2. Dump it:
   ```powershell
   mkdir out
   .\vol.exe -f $img -o out windows.dumpfiles --physaddr 0x<offset>
   ```
   If nothing is written, try `--virtaddr` or another offset.
3. Rename the `…DataSectionObject.<name>.dat` file to its real extension.
4. The password is often a user's **NTLM hash in uppercase**. The archive comment may say so: 7-Zip prints it as `Comment = …`.
   ```powershell
   .\vol.exe -f $img windows.registry.hashdump
   ```
   Take the **last** hash column (`nthash`) of the target user and convert it to uppercase.
5. Extract:
   ```powershell
   & "C:\Program Files\7-Zip\7z.exe" x file.rar -p<UPPERCASE_NTHASH>
   ```
   The warning "There are data after the end of archive" is harmless: it's memory padding.
6. Open the extracted image and read the flag. Check characters that are easy to confuse in handwriting (`3`/`e`, `0`/`o`, `l`/`1`).

### 3.9 "Find the flag in what was drawn in mspaint.exe"
mspaint keeps its canvas in process memory as a raw **BGRA, bottom-up** bitmap.

1. Dump the process memory (a few hundred MB):
   ```powershell
   .\vol.exe -f $img -o out windows.memmap --pid <mspaint PID> --dump
   Rename-Item out\pid.<PID>.dmp pid.<PID>.data
   ```
2. **Manual way (GIMP):** File → Open → *Raw image data*, set Image type **RGB Alpha**, start width around 1280, and drag **Offset** until a white canvas with strokes appears. Adjust **Width** until the strokes stop slanting, then Image → Transform → **Flip Vertically**.
3. **Automated way (Python + numpy + Pillow):** find the canvas, work out the row width, render the image.
   ```python
   import numpy as np
   from PIL import Image
   d = np.fromfile('pid.2424.data', dtype=np.uint8)
   P = 4096; n = len(d)//P
   white = (d[:n*P].reshape(n, P) == 255).mean(1)

   # 1) canvas candidates: long runs of mostly-white pages that contain some strokes
   runs, i = [], 0
   while i < n:
       if white[i] > 0.6:
           j = i
           while j < n and white[j] > 0.6: j += 1
           if j - i >= 64: runs.append((i*P, (j-i)*P, (white[i:j] < 0.999).sum()))
           i = j
       else:
           i += 1
   print([(hex(o), size//1024, mixed) for o, size, mixed in runs])

   # 2) row width: dark pixels line up one row apart (autocorrelation)
   def width(off, size):
       m = (d[off:off+size].reshape(-1, 4)[:, :3].min(1) < 128).astype(np.float32)
       return max(range(300, 2100), key=lambda w: (m[:-w]*m[w:]).sum())

   # 3) render: BGRA -> RGB, flip vertically
   def render(off, size, w, out):
       seg = d[off:off+size]; h = len(seg)//(w*4)
       px = seg[:h*w*4].reshape(h, w, 4)[:, :, [2, 1, 0]]
       Image.fromarray(px).transpose(Image.FLIP_TOP_BOTTOM).save(out)
   ```
   Pick the run with many "mixed" pages (strokes), compute `width()`, call `render()` and look at the PNG. If the result looks like a multiple of the true width (two copies side by side), halve the width. The GIMP offset is the run's offset in decimal.

## 4. Common errors

| Symptom | Cause / fix |
|---|---|
| `'.\vol.exe' is not recognized` | Shell isn't in the Volatility folder: `cd` there. |
| `invalid <lambda> value: '0xOFFSET'` | A placeholder was left in. Use the real hex offset. |
| printkey shows `{PASTE-GUID-HERE}` under every hive | The placeholder was run literally. Use the real GUID or `--recurse`. |
| printkey returns nothing | Used `CurrentControlSet`: use `ControlSet001`. Add `--offset` for the SYSTEM hive. |
| PowerShell count is 0 | Wrong column name. Inspect `$s[0]`, or use `Select-String` on the CSV. |
| `FutureWarning ... hashdump renamed` | Harmless. Use `windows.registry.hashdump`. |
| `7z.exe` not found | `winget install 7zip.7zip`. |
| 7-Zip "data after the end of archive" | Harmless padding from memory. |

## 5. Answer format

- Give the bare value first, then one line of evidence (plugin + the line it came from).
- For a write-up: `<answer> — from <plugin>: <key evidence>`.
- Example:
  > 10.0.2.15 — `windows.registry.printkey`: `ControlSet001\Services\Tcpip\Parameters\Interfaces\{14BE490A-…}\DhcpIPAddress`; confirmed by `windows.netscan` (NetBIOS 137/138/139 on 10.0.2.15).

## Appendix: Worked example (MemLabs Lab 1, `MemoryDump_Lab1.raw`)

Use it to check the method, not as a source of answers for a different image.

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | DHCP IP | 10.0.2.15 | printkey `DhcpIPAddress`, server 10.0.2.2 |
| 2 | Active processes (pslist) | 48 | all ExitTime = N/A |
| 3 | Processes found by psscan | 56 | 48 unique + 8 duplicate copies (WinRAR, SearchProtocolHost, DumpIt, conhost × 3 each) |
| 4 | PID of mspaint.exe | 2424 | pslist / pstree |
| 5 | Archive being extracted | Important.rar | cmdline PID 1512: `C:\Users\Alissa Simpson\Documents\Important.rar` |
| 6 | Users | SmartNet:Alissa Simpson | pstree paths, hivelist ntuser.dat |
| 7 | IP that `update.exe` connects to | Not in this image | no `update.exe`, no outbound sockets in netscan |
| 8 | Flag in archive | flag{w3ll_3rd_stage_was_easy} | dumpfiles 0x3fa3ebc0, password = uppercase NT hash of Alissa Simpson |
| 9 | Flag in mspaint | flag{G00d_BoY_good_girL} | memmap PID 2424, canvas at 0x578000, width 615, flipped vertically |
