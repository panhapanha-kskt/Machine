# HTB Sherlock: Iron Feather — Q1 to Q6 (Mission Vault Crypto)

## Scenario

A PX4 flight-controller build (`px4`, a stripped, dynamically-linked x86_64 ELF used for
PX4 SITL) stores its dataman key/value store and its ULog flight recording behind a custom
authenticated-encryption "vault" format. Two encrypted files are provided:

- `dataman.encrypted` (magic `PX4DMENC`)
- `flight.ulg.encrypted` (magic `PX4ULENC`)

The goal of Q1–Q6 is to fully reverse the vault format and recover the AES key needed to
decrypt both files.

## Tools used

- `xxd` — raw hex inspection of the encrypted file headers
- `strings -a` — locating embedded literals in the binary
- `nm -D`, `objdump -T` — enumerating dynamic/exported symbols
- `radare2` (`r2 -A`) — disassembly, string cross-referencing (`axt`), function analysis
- `gdb` + `pwndbg` — live dynamic analysis, breakpoints, register/memory inspection
- Python 3 (`hashlib`, `cryptography`) — reimplementing and verifying the derivation and
  decryption

---

## Q1 — Eight-byte ASCII magic identifying the encrypted datastore format

**Method:** Raw hex dump of the encrypted files.

```bash
xxd dataman.encrypted | head -5
```

```
00000000: 5058 3444 4d45 4e43 0100 0000 d070 1200  PX4DMENC.....p..
```

The first 8 bytes decode directly to ASCII `PX4DMENC`. This was independently confirmed
inside the binary's decrypt routine (`fcn.0016fe10`), which does a direct 8-byte magic
comparison:

```
0x0016ff1e   movabs rax, 0x434e454d44345850   ; little-endian bytes = "PX4DMENC"
0x0016ff28   cmp qword [var_e0h], rax
```

**Answer: `PX4DMENC`**

(The companion file `flight.ulg.encrypted` uses the sibling magic `PX4ULENC` for the ULog
variant of the same container format — same structure, different tag.)

---

## Q2 — Authenticated encryption algorithm protecting the datastore

**Method:** Following the decrypt routine (`fcn.0016fe10`) past the header-magic check in
radare2 (`r2 -A px4`, `axt` to find the string's caller, then `pdf` to disassemble the
function):

```
call sym.EVP_CIPHER_CTX_new
call sym.EVP_aes_256_gcm
call sym.EVP_DecryptInit_ex
...
mov esi, 9          ; EVP_CTRL_AEAD_SET_IVLEN
mov edx, 0xc         ; 12-byte IV
call sym.EVP_CIPHER_CTX_ctrl
...
mov esi, 0x11        ; EVP_CTRL_AEAD_SET_TAG
mov edx, 0x10         ; 16-byte tag
call sym.EVP_CIPHER_CTX_ctrl
call sym.EVP_DecryptUpdate    ; AAD pass
call sym.EVP_DecryptUpdate    ; ciphertext pass
call sym.EVP_DecryptFinal_ex  ; tag verification
```

This is the canonical OpenSSL EVP sequence for AES-256 in Galois/Counter Mode: cipher =
`EVP_aes_256_gcm`, a 12-byte nonce/IV, and a 16-byte authentication tag.

**Answer: `AES-256-GCM`**

---

## Q3 — RVA of the custom key-derivation function

**Method:** Traced the call graph from the decrypt routine backward with radare2:

```
r2 -A px4
/ invalid encrypted image header      # locate the header-error string
axt <string_addr>                     # -> fcn.0016fe10 (decrypt/open routine)
axt fcn.0016fe10                      # -> caller at 0x16f79a
axt sym.PKCS5_PBKDF2_HMAC              # -> called from fcn.00170af0
```

`fcn.00170af0` is called directly from inside the decrypt/open routine, immediately before
the AES-256-GCM cipher context is initialized, and its failure path leads straight to the
error string `"key derivation ... failed"`. Disassembling it (`s fcn.00170af0; pdf`) reveals
it as a two-stage custom mixing function (TEA/XTEA-style ARX construction using the golden
ratio constants `0x9e3779b9` / `0x61c88647`) that produces the password material subsequently
fed into `PKCS5_PBKDF2_HMAC`.

Since this is a non-PIE-relocated file offset (the binary is a PIE, but radare2's static
addresses in this analysis map 1:1 to file-relative virtual addresses because the load bias
is 0 for this disassembly), the function's address is directly usable as its RVA.

**Answer: `0x170af0`**

---

## Q4 — Rounds performed by the custom 32-bit mixing loop

**Method:** Disassembly of the main loop inside `fcn.00170af0`:

```
; loop body performs XOR/ROL/ADD across 32-bit words using
; TEA/XTEA delta constants 0x9e3779b9 and 0x61c88647
0x00170ba0   add edx, 4
...
0x00170c8b   cmp edx, 0x17f      ; 0x17f = 383 decimal
0x00170c91   jne 0x170ba0
```

The loop counter `edx` is compared against `0x17f` (383) **before** incrementing for the
next pass — i.e. the comparison tests the value that was just processed, not the
about-to-be-processed one. Because the loop starts at `edx = 0` and the exit check fires
only once `edx` reaches 383 (inclusive, since that iteration still executes fully before the
branch is evaluated), the loop body runs for every integer `0, 1, 2, ..., 383` — 384 total
executions.

An initial reading of "compares to 0x17f (383), so 383 rounds" undercounts by one because
the comparison is post-processing on an inclusive bound, not a pre-check exclusive bound.

**Answer: `384`**

---

## Q5 — Standard KDF that produces the AES key

**Method:** Same disassembly of `fcn.00170af0`, tail end:

```
call sym.EVP_sha256          ; digest = SHA-256
...
mov r8d, 0x2000              ; iterations = 8192
mov esi, 0x68                ; password length = 104 bytes
mov ecx, 0x10                ; salt length = 16 bytes
push 0x20                    ; derived key length = 32 bytes (AES-256 key size)
call sym.PKCS5_PBKDF2_HMAC
```

The explicit digest argument passed is `EVP_sha256()`. Combined with the `PKCS5_PBKDF2_HMAC`
call, the KDF is PBKDF2 using HMAC-SHA256 as its pseudorandom function.

**Answer: `PBKDF2-HMAC-SHA256`**

(Submitting bare `PBKDF2` was rejected by the checker — it wants the fully-qualified
digest-included name.)

---

## Q6 — AES-256 key derived for the supplied encrypted image

Static reconstruction of the exact 104-byte PBKDF2 password (which mixes the 384-round ARX
output with several hardcoded/obfuscated string constants copied in via `movdqa`/`movaps`)
is impractical to get byte-perfect purely from disassembly. Instead, the process was
dynamically captured with gdb at the exact call site.

### Step 1 — Get PX4 SITL to a running shell

The binary is PX4's SITL server. It needs a startup script to reach its `pxh>` shell:

```bash
mkdir -p etc/init.d-posix
echo '#!/bin/sh' > etc/init.d-posix/rcS
./px4
```

```
pxh> dataman start -f dataman.encrypted
INFO  [dataman] dataman file set to: dataman.encrypted
```

This invocation reaches the vault decrypt path (which the challenge intends to be triggered
via the dataman module).

### Step 2 — Attach gdb and set the breakpoint

Since attaching gdb directly to a `run` command inside the same process caused issues with
vfork/exec during startup-script execution, PX4 was instead started plainly and gdb attached
to the *already-running* process from a second terminal:

```bash
pgrep -a px4                 # find the live PID
sudo gdb -p <PID>
```

Inside gdb, the process's actual (ASLR-randomized) load base was found:

```
pwndbg> info proc mappings
```

```
0x00005630d98c5000 ... r-xp  .../px4
```

The static RVA for the call site (the instruction immediately before
`call sym.PKCS5_PBKDF2_HMAC`, at static offset `0x170d74` inside `fcn.00170af0`) was added
to this base:

```bash
python3 -c "print(hex(0x5630d98c5000 + 0x170d74))"
# 0x5630d9a35d74
```

```
pwndbg> b *0x5630d9a35d74
pwndbg> continue
```

Then, back in the first terminal, the dataman command was issued to trigger the decrypt
path, hitting the breakpoint:

```
Thread 8 "dataman" hit Breakpoint 1, 0x00005630d9a35d74 in ?? ()
RIP  0x5630d9a35d74 ◂— call PKCS5_PBKDF2_HMAC
        pass: 0x7f7def7a3990
        passlen: 0x68
        salt: 0x7f7def7a3b30
        saltlen: 0x10
        iter: 0x2000
        digest: 0x5630da1c5f20
        keylen: 0x20
        out: 0x7f7def7a3b00
```

pwndbg's calling-convention argument annotation confirmed every parameter matched what the
static disassembly predicted (`passlen=0x68=104`, `saltlen=0x10=16`, `iter=0x2000=8192`,
`keylen=0x20=32`).

### Step 3 — Dump the actual argument bytes

```
pwndbg> x/104xb $rdi      # password (rdi = 1st arg = pass)
pwndbg> x/16xb $rdx       # salt (rdx = 3rd arg = salt)
```

Password (104 bytes):
```
69 6a 87 65 f4 3a b7 49 75 72 8e 71 3e cd d6 d2
1c ff 4e 65 ae 18 67 69 e8 54 70 9f d0 b6 1c 87
74 13 d9 2e a8 65 0c f1 3b 97 42 cd 58 e6 21 8a
b4 0f 73 da 36 9c 51 e2 17 e2 49 83 2c b5 61 0e
d8 34 9f 72 05 c1 5a ed 68 13 a7 4d f0 2b 96 5e
bc 41 0a d3 7f 25 e9 84 56 ab 30 c7 1d 92 6b f4
08 75 de 23 99 4a b1 6f
```

Salt (16 bytes) — also directly visible as bytes `0x10..0x1f` of the encrypted file's
plaintext header:
```
60 c2 00 30 9e 3f 46 4c 11 d1 46 45 a3 55 bf e8
```

### Step 4 — Reproduce the derivation in Python

```python
import hashlib

pw   = bytes.fromhex("696a8765f43ab7497572...")   # 104 bytes, from above
salt = bytes.fromhex("60c200309e3f464c11d14645a355bfe8")

key = hashlib.pbkdf2_hmac("sha256", pw, salt, 0x2000, dklen=32)
print(key.hex())
```

Output:
```
a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce
```

### Step 5 — Verify end-to-end by actually decrypting both files

A small Python script (`decrypt_vault.py`) was written implementing the recovered header
layout:

| Offset | Size | Field |
|---|---|---|
| 0x00 | 8 | magic |
| 0x08 | 4 | version (== 1) |
| 0x0c | 4 | ciphertext length |
| 0x10 | 16 | PBKDF2 salt |
| 0x20 | 12 | AES-GCM nonce |
| 0x2c | 16 | AES-GCM tag |
| 0x3c | … | ciphertext |

The first 0x2c (44) bytes of the header are passed as GCM additional authenticated data
(AAD), matching the `EVP_DecryptUpdate(ctx, NULL, &outl, header, 0x2c)` call seen in the
disassembly.

```bash
pip install cryptography --break-system-packages
python3 decrypt_vault.py dataman.encrypted a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce dataman.bin
python3 decrypt_vault.py flight.ulg.encrypted a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce flight.ulg
```

```
magic=b'PX4DMENC' version=1 ct_len=1208528 (file has 1208528)
OK: GCM tag verified, wrote 1208528 bytes -> dataman.bin

magic=b'PX4ULENC' version=1 ct_len=68828059 (file has 68828059)
OK: GCM tag verified, wrote 68828059 bytes -> flight.ulg
```

Both files decrypted with GCM authentication passing — cryptographic proof the key, salt,
and header layout are all correct.

**Answer: `a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce`**

---

## Summary Table

| Q | Answer |
|---|---|
| 1 | `PX4DMENC` |
| 2 | `AES-256-GCM` |
| 3 | `0x170af0` |
| 4 | `384` |
| 5 | `PBKDF2-HMAC-SHA256` |
| 6 | `a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce` |

## Key techniques worth remembering

1. **Finding hidden custom crypto in a giant statically-linked OpenSSL binary**: don't
   search for algorithm names (thousands of false positives from linked-in OpenSSL). Search
   for *unique, application-specific error strings* (`"invalid encrypted image header"`,
   `"key derivation ... failed"`, `"mission-vault"`) and cross-reference (`axt` in radare2)
   to find the actual application code, ignoring all library internals.
2. **TEA/XTEA fingerprint**: the constants `0x9e3779b9` (⌊2³²/φ⌋, the "golden ratio" delta)
   and `0x61c88647` (its negation mod 2³²) are a very strong signal of a Feistel/ARX cipher
   in the TEA family, even when heavily obfuscated or custom-modified.
3. **Off-by-one loop counting**: always check whether the compare-and-branch happens on the
   pre- or post-increment value, and whether the loop body executes before or after the
   check — this determines whether the true iteration count is N, N+1, or N-1 relative to
   the naive "the compare says X" reading.
4. **When static reconstruction of an obfuscated buffer gets impractical, go dynamic**:
   setting a single breakpoint at the exact library call site and reading the CPU
   registers/stack directly at that point is far more reliable than manually replaying
   obfuscation logic by hand.
5. **Verify crypto answers cryptographically, not just "plausibly"**: an AEAD scheme's tag
   verification is a built-in correctness check — if decryption with your derived key
   succeeds, the key is provably correct, not just probably correct.

   
