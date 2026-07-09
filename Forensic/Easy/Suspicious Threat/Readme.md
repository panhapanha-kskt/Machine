# Suspicious Threat — HTB Forensics Writeup

> **Category:** Forensics  
> **Type:** Live Linux System Analysis  
> **Topic:** Userland Rootkit via `ld.so.preload` hijacking  
> **Difficulty:** Medium

---

## Table of Contents

1. [Overview](#overview)
2. [How the Rootkit Works](#how-the-rootkit-works)
3. [File Structure & Key Paths](#file-structure--key-paths)
4. [Step-by-Step Analysis](#step-by-step-analysis)
   - [Step 1: Discover the Preload Hook](#step-1-discover-the-preload-hook)
   - [Step 2: Confirm Injection via ldd](#step-2-confirm-injection-via-ldd)
   - [Step 3: Extract Strings from the .so](#step-3-extract-strings-from-the-so)
   - [Step 4: Understand the Hooking Logic](#step-4-understand-the-hooking-logic)
   - [Step 5: Find the Hidden Directory](#step-5-find-the-hidden-directory)
   - [Step 6: System Persistence Check](#step-6-system-persistence-check)
   - [Step 7: Network Analysis](#step-7-network-analysis)
5. [Key Indicators of Compromise](#key-indicators-of-compromise)
6. [Bypass Techniques](#bypass-techniques)
7. [Key Takeaways](#key-takeaways)

---

## Overview

We are given SSH access to a live compromised Linux system. The attacker has installed a **userland rootkit** using the `ld.so.preload` mechanism — a technique that forces a malicious shared library to load into **every process** before the standard C library, allowing it to intercept and manipulate standard library calls system-wide.

---

## How the Rootkit Works

```
┌─────────────────────────────────────────────────────────────┐
│                    Every Process Launch                      │
│                                                             │
│   /etc/ld.so.preload  ──→  libc.hook.so.6  ──→  libc.so.6  │
│         (config)            (malicious)        (real libc)  │
└─────────────────────────────────────────────────────────────┘
```

The rootkit (`hider.c` compiled to `libc.hook.so.6`) hooks three functions:

| Hooked Function | Real Purpose | Malicious Behavior |
|----------------|-------------|-------------------|
| `readdir()` | List directory entries | Skips any entry containing `pr3l04d_` |
| `readdir64()` | 64-bit version of above | Same — hides files/dirs with `pr3l04d_` |
| `fopen()` | Open a file | Blocks reading of `/etc/ld.so.preload` to hide itself |

The hiding keyword `pr3l04d_` is a **hardcoded string constant** inside the `.so` binary, used via `strstr()` to filter directory listing results.

**Pseudocode of the hook logic:**
```c
// In hooked readdir():
struct dirent *readdir(DIR *dirp) {
    struct dirent *entry;
    while ((entry = orig_readdir(dirp)) != NULL) {
        if (strstr(entry->d_name, "pr3l04d_") == NULL)
            return entry;  // show this entry
        // else: skip it — hidden from ls, find, etc.
    }
    return NULL;
}

// In hooked fopen():
FILE *fopen(const char *path, const char *mode) {
    if (strstr(path, "ld.so.preload") != NULL)
        return NULL;  // block reading — hides the hook config
    return orig_fopen(path, mode);
}
```

---

## File Structure & Key Paths

```
/
├── etc/
│   ├── ld.so.preload               ← ROOTKIT ENTRY POINT
│   │                                  Contains: /lib/x86_64-linux-gnu/libc.hook.so.6
│   ├── ld.so.conf                  ← Legitimate linker config
│   ├── ld.so.cache                 ← Linker cache (updated Jul 24 2024)
│   ├── shadow                      ← Check for backdoor accounts
│   ├── passwd                      ← Check for new users
│   ├── ssh/
│   │   └── sshd_config             ← Check for PermitRootLogin, backdoor ports
│   ├── cron.d/                     ← Persistence check (only legit e2scrub jobs found)
│   └── systemd/system/
│       └── multi-user.target.wants/← Persistence check
│
├── lib/x86_64-linux-gnu/
│   └── libc.hook.so.6              ← MALICIOUS SHARED LIBRARY (15688 bytes)
│                                      Created: Jun 3 2024
│                                      Permissions: -rw-rw-r-- (world-readable!)
│
├── usr/lib/x86_64-linux-gnu/
│   └── libc.hook.so.6              ← SECOND COPY of malicious library
│                                      (found via find, same file)
│
└── [hidden]/
    └── pr3l04d_*/                  ← HIDDEN DIRECTORY/FILES
                                       Invisible to ls/find due to readdir hook
                                       Contains: flag or attacker artifacts
```

---

## Step-by-Step Analysis

### Step 1: Discover the Preload Hook

```bash
cat /etc/ld.so.preload
```

**Output:**
```
/lib/x86_64-linux-gnu/libc.hook.so.6
```

**What this means:** Every process on this system loads `libc.hook.so.6` before anything else. This is the classic `ld.so.preload` rootkit injection technique.

---

### Step 2: Confirm Injection via ldd

```bash
ldd $(which sshd)
```

**Key output line:**
```
/lib/x86_64-linux-gnu/libc.hook.so.6 (0x00007f77455c2000)
```

**What this means:** The hook appears first in the library load order — before `libc.so.6`. This confirms every process (including `sshd`) has the malicious library injected.

---

### Step 3: Extract Strings from the .so

Most forensic tools (`strings`, `readelf`, `file`, `objdump`) are unavailable on the stripped system. Use Python as a replacement:

```bash
python3 -c "
data = open('/usr/lib/x86_64-linux-gnu/libc.hook.so.6','rb').read()
cur = b''
for b in data:
    if 32 <= b < 127:
        cur += bytes([b])
    else:
        if len(cur) >= 5:
            print(cur.decode())
        cur = b''
"
```

**Critical strings found:**

```
orig_readdir          ← saves pointer to real readdir
orig_readdir64        ← saves pointer to real readdir64
orig_fopen            ← saves pointer to real fopen
dlsym                 ← used to resolve original function pointers
strcmp                ← string comparison
strstr                ← used to match hidden names
readdir               ← hooked function
readdir64             ← hooked function
fopen                 ← hooked function
pr3l04d_              ← !! HIDDEN KEYWORD — files with this name are invisible
ld.so.preload         ← blocked from fopen — hides the hook config
hider.c               ← SOURCE FILE NAME — attacker compiled this
GCC: (Debian 13.2.0-13) 13.2.0  ← compiled on Debian
```

---

### Step 4: Understand the Hooking Logic

From the strings, the complete rootkit behavior is clear:

```
strstr(entry->d_name, "pr3l04d_")  →  hide directory entries
strstr(path, "ld.so.preload")      →  block fopen on preload config
dlsym(RTLD_NEXT, "readdir")        →  get real function pointer
```

The rootkit was compiled from a file called **`hider.c`** using standard Debian GCC. It is a minimal userland rootkit — no kernel modules, no syscall table patching. Purely userspace via `ld.so.preload`.

---

### Step 5: Find the Hidden Directory

Since `readdir` is hooked, normal `ls` and `find` won't show `pr3l04d_` entries. Use these bypass techniques:

```bash
# Method 1: Direct find (may still work on some kernel paths)
find / -name "*pr3l04d*" 2>/dev/null

# Method 2: Python os.listdir (same glibc readdir — may be hooked)
python3 -c "
import os
for path in ['/', '/tmp', '/var', '/opt', '/home', '/root', '/srv', '/var/tmp']:
    try:
        entries = os.listdir(path)
        for e in entries:
            if 'pr3l04d' in e:
                print(f'FOUND: {path}/{e}')
    except: pass
"

# Method 3: Read /proc/1/fd to find open file descriptors to hidden files
ls -la /proc/1/fd/ 2>/dev/null

# Method 4: Check process maps for hidden path references
for pid in 1 7 8 19 50 51; do
    grep pr3l04d /proc/$pid/maps 2>/dev/null && echo "Found in PID $pid"
done

# Method 5: Direct memory read bypassing readdir entirely
python3 -c "
import os, ctypes, ctypes.util

# Use raw getdents64 syscall via ctypes to bypass hooked readdir
libc_path = ctypes.util.find_library('c')
libc = ctypes.CDLL(libc_path)
print('Trying raw syscall approach...')
"
```

---

### Step 6: System Persistence Check

```bash
# Cron jobs (only legitimate e2scrub jobs found)
cat /etc/cron.d/*
# Output: standard Debian e2scrub maintenance jobs — clean

# Systemd services
ls -la /etc/systemd/system/multi-user.target.wants/
cat /etc/systemd/system/multi-user.target.wants/*.service

# Init.d (only standard services)
ls -la /etc/init.d/
# Output: dbus, procps, ssh — all standard

# SUID binaries (potential privesc)
find / -perm -4000 -not -path "/proc/*" 2>/dev/null

# Backdoor accounts
cat /etc/passwd | grep -vE "/nologin|/false|/sync"
cat /etc/shadow

# SSH backdoor
cat /etc/ssh/sshd_config | grep -vE "^#|^$"
cat /root/.ssh/authorized_keys 2>/dev/null
```

---

### Step 7: Network Analysis

Decode `/proc/net/tcp` hex entries manually:

```bash
python3 -c "
import socket, struct

def decode_addr(hex_addr):
    addr, port = hex_addr.split(':')
    addr = socket.inet_ntoa(struct.pack('<I', int(addr, 16)))
    port = int(port, 16)
    return f'{addr}:{port}'

# From /proc/net/tcp output
entries = [
    ('00000000:08AE', '00000000:0000', 'LISTEN'),
    ('5E12F40A:08AE', '44716D1B:1E76', 'ESTABLISHED'),
]
for local, remote, state in entries:
    print(f'[{state}] Local: {decode_addr(local)}  Remote: {decode_addr(remote)}')
"
```

**Decoded:**
```
[LISTEN]      Local: 0.0.0.0:2222        Remote: 0.0.0.0:0
[ESTABLISHED] Local: 10.244.18.94:2222   Remote: 27.109.113.68:7798
```

Port `0x08AE` = **2222** — SSH running on non-standard port (or attacker-modified `sshd`).

---

## Key Indicators of Compromise

| Indicator | Location | Detail |
|-----------|----------|--------|
| Malicious preload | `/etc/ld.so.preload` | Points to `libc.hook.so.6` |
| Hook library (copy 1) | `/lib/x86_64-linux-gnu/libc.hook.so.6` | 15688 bytes, Jun 3 2024 |
| Hook library (copy 2) | `/usr/lib/x86_64-linux-gnu/libc.hook.so.6` | Same file, second location |
| Source file name | embedded in binary | `hider.c` |
| Hidden keyword | embedded in binary | `pr3l04d_` |
| Hooked functions | `readdir`, `readdir64`, `fopen` | Hides files + blocks preload reads |
| Compiler | embedded in binary | GCC Debian 13.2.0-13 |
| Unusual permissions | `-rw-rw-r--` on `.so` | World-writable — attacker convenience |

---

## Bypass Techniques

When standard tools are missing or hooked, use these alternatives:

| Blocked Tool | Bypass |
|---|---|
| `strings` | `python3 -c "data=open(f,'rb').read(); ..."` |
| `readelf` | Parse ELF header manually with `struct.unpack` |
| `ls` / `find` | Read `/proc/PID/fd`, `/proc/PID/maps`, raw `getdents64` syscall |
| `file` | Check magic bytes: `python3 -c "print(open(f,'rb').read(4))"` |
| `cat /etc/ld.so.preload` | Hook blocks `fopen` on this path — read via `/proc/self/fd` or `dd` |
| `busybox` | Not installed — use Python `os` module equivalents |

---

## Key Takeaways

| Concept | Detail |
|---------|--------|
| **`ld.so.preload` abuse** | The #1 userland rootkit technique — loads attacker code into every process |
| **No kernel required** | This rootkit is 100% userspace — no kernel modules, no exploits needed |
| **Strings analysis** | Hardcoded constants in binaries reveal hiding keywords, source filenames, and logic |
| **`dlsym(RTLD_NEXT)`** | Standard technique to get the real function pointer after hooking |
| **Detection** | Compare `cat /etc/ld.so.preload` output vs what `fopen` returns — discrepancy = hook |
| **Bypass** | Use raw syscalls (`getdents64`) or `/proc` filesystem to see past userland hooks |
| **Artifact** | `hider.c` source name + `pr3l04d_` keyword = the hidden directory to find |
