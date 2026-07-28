# The Corroded Crown — Heap UAF to Remote Code Execution

**Category:** Pwn / Binary Exploitation
**Component:** `corroded_crown` (x86-64 ELF, dynamically linked, glibc 2.31)
**Class:** CWE-416 (Use After Free) → CWE-787 (Out-of-Bounds Write) → Remote Code Execution
**Severity:** Critical (CVSS 3.1: 9.8 — Network / Low complexity / No privileges / No user interaction / Full C:I:A impact)

---

## Summary

`corroded_crown` is a heap-note style service exposing four operations — **Forge**, **Inscribe**, **Inspect**, **Destroy** — that manage up to 64 heap allocations ("relics") tracked in a fixed-size global array. The **Inscribe** (write) and **Inspect** (read) handlers fail to verify that a relic's slot is still marked in-use before operating on it. Once a relic is freed via **Destroy**, its stale pointer and size fields remain in the tracking array and are fully reachable via Inscribe/Inspect — a textbook **use-after-free** with arbitrary read/write on freed heap memory.

This primitive is sufficient to leak a heap address and a libc address, corrupt the `tcache` freelist to allocate a chunk directly on top of `__free_hook`, and overwrite that hook with `system()`. Triggering a subsequent free of a chunk containing the string `/bin/sh` then yields command execution as the service's user.

**Impact:** Full remote code execution with the privileges of the vulnerable process.

---

## Root Cause

Decompiled logic (relevant handlers only):

```c
// forge_relic() and destroy_relic() correctly gate on the in-use flag:
if (relic[idx*0x10 + 0xc] == 0) { /* forge: malloc + mark in-use */ }
if (relic[idx*0x10 + 0xc] == 1) { /* destroy: free + clear in-use */ }

// inscribe_relic() — NO in-use check before writing through the stored pointer:
void inscribe_relic(void) {
    int idx = read_int();
    if (idx < 0 || idx > 0x3f) { /* bounds check only */ }
    read(0, *(void**)(relic + idx*0x10), *(int*)(relic + idx*0x10 + 8));
}

// inspect_relic() — NO in-use check before reading through the stored pointer:
void inspect_relic(void) {
    int idx = read_int();
    if (idx < 0 || idx > 0x3f) { /* bounds check only */ }
    write(1, *(void**)(relic + idx*0x10), *(int*)(relic + idx*0x10 + 8));
}
```

Destroying a relic (`destroy_relic`) frees the chunk and clears the in-use byte, but **does not zero the stored pointer or size fields**. Since `inscribe_relic`/`inspect_relic` only bounds-check the index and never consult the in-use flag, both operations remain fully functional against a freed slot — providing an attacker-controlled read and write into freed heap memory of arbitrary length (bounded only by the original allocation's tracked size, which is itself never cleared and can be leveraged for oversized reads/writes if not re-forged).

This is the mechanism referenced in the challenge's narrative framing: the validation gate that should reject a "dead" relic is simply absent on two of the four code paths.

---

## Exploitation Chain

Target: glibc 2.31 (Ubuntu 20.04, tcache-based allocator, no safe-linking).

### Stage 1 — Heap address leak
1. Allocate two same-size chunks (`0x88`) to avoid top-chunk consolidation on free.
2. Free the first chunk. In an unpatched tcache (2.31, no safe-linking), the freed chunk's `fd`/`key` metadata is written in place — including a heap pointer.
3. **Inspect** the freed slot via the UAF (no in-use check) to read that metadata back and recover a heap address.

### Stage 2 — libc address leak
1. Allocate a chunk large enough (`> 0x410`) to bypass tcache and land in the unsorted bin on free.
2. Allocate a "barrier" chunk of a **distinct, not-yet-freed size class**, forcing it to come from fresh top memory rather than being served from an existing tcache entry — this guarantees physical adjacency and prevents the large chunk from being silently consolidated into the top chunk on free (which would produce a leak of un-initialized zero bytes instead of a libc pointer).
3. Free the large chunk. glibc writes `main_arena`-relative `fd`/`bk` pointers into it as part of unsorted-bin bookkeeping.
4. **Inspect** the freed slot via the UAF to leak a libc address, then compute the libc base using the well-known glibc 2.31 x86-64 offset: `main_arena = __malloc_hook + 0x10`, and the unsorted-bin head offset `+0x60`, giving a fixed `+0x70` delta from `__malloc_hook`.

### Stage 3 — Tcache poisoning
1. Allocate and free two more same-size chunks, chaining them in the tcache freelist.
2. **Inscribe** into the first freed chunk via the UAF to overwrite its `fd` pointer with the address of `__free_hook`.
3. Two subsequent allocations of the same size pop the freelist: the first reclaims the poisoned chunk, the second is served **at `__free_hook` itself**.

### Stage 4 — Hook hijack
**Inscribe** into the chunk now aliasing `__free_hook`, overwriting it with the address of `system()`.

### Stage 5 — Trigger
Allocate a final chunk containing the string `/bin/sh\x00`, then **Destroy** it. `free()` invokes `__free_hook(ptr)`, which is now `system(ptr)` — yielding `system("/bin/sh")` and an interactive shell.

Full annotated proof-of-concept exploit: [`exploit.py`](./exploit.py).

```
$ python3 exploit.py
...
[+] __free_hook -> system() written
[+] Shell incoming!
$ ls
corroded_crown  flag.txt  glibc
$ cat flag.txt
HTB{th3_cr0wn_h45_b33n_p01s0n3d_c9bfb94124f9470bbeac7da2811eabeb}
```

---

## Proof of Concept

See attached `exploit.py`. Key requirements to reproduce:
- Target binary and matching `libc.so.6` / `ld-linux-x86-64.so.2` (glibc 2.31).
- `pwntools`.
- No interaction beyond running the script against the listed host/port; the entire chain is unauthenticated and requires no prior state.

---

## Impact

- **Confidentiality:** Arbitrary read of freed heap contents, extendable to arbitrary process memory via the same primitive (heap/libc infoleak already demonstrated).
- **Integrity:** Arbitrary write of freed heap contents, demonstrated by hijacking a libc function pointer (`__free_hook`).
- **Availability / Code Execution:** Full command execution as the service process, demonstrated by spawning an interactive shell.

Any network-reachable deployment of this service is fully compromised by an unauthenticated remote attacker with no prerequisites beyond network access.

---

## Remediation

1. **Enforce the in-use flag on every operation that dereferences a relic's stored pointer**, not just Forge/Destroy. `inscribe_relic()` and `inspect_relic()` must check `relic[idx*0x10 + 0xc] == 1` before reading or writing through the stored pointer, mirroring the check already present in `destroy_relic()`.
2. **Clear stored pointer and size fields on free** (defense in depth): after `free()`, zero out the corresponding 16-byte record so that even a logic error elsewhere cannot yield a stale, dereferenceable pointer.
3. **Adopt a hardened allocator posture**: enabling tcache double-free/safe-linking protections (present by default in glibc ≥ 2.32) would not fix this specific logic bug but reduces the blast radius of similar UAF primitives in general.
4. **Consider `__free_hook`/`__malloc_hook` deprecation exposure**: these hooks are removed entirely in glibc ≥ 2.34, which independently closes off this specific hook-hijack technique regardless of the application-level fix above. Upgrading the runtime libc is recommended alongside the source fix, not as a substitute for it.

---

## Timeline

| Date | Event |
|---|---|
| TBD | Vulnerability identified during authorized testing |
| TBD | Report submitted |
| TBD | Vendor acknowledgment |
| TBD | Fix verified |
| TBD | Public disclosure (if applicable, per program policy) |

---

## Disclosure Note

This writeup was produced as part of solving a HackTheBox pwn lab/CTF challenge for training purposes. If adapting this template for an actual bug bounty submission against a real target, replace the timeline placeholders, confirm the target's authorized-testing scope, and follow the specific program's disclosure policy before publishing any technical details externally.
