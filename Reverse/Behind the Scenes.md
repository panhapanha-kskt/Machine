# HackTheBox — Reverse Engineering — "Behind the Scenes"

**Category:** Reverse Engineering
**Difficulty:** Very Easy
**Binary:** `behindthescenes`
**Tools used:** Ghidra, GDB, `strings`, `objdump`

---

## 1. Challenge Overview

Running the binary with no arguments shows a usage hint:

```bash
$ ./behindthescenes
./challenge <password>
```

The binary expects a password as `argv[1]`. On success it prints a flag in the format:

```
> HTB{%s}
```

confirmed from static strings:

```bash
$ strings behindthescenes | grep -iE "pass|flag|correct|wrong"
./challenge <password>
```

and separately from the `.rodata` section:

```
> HTB{%s}
```

So the flag is `HTB{<password>}` once the correct password is supplied.

---

## 2. Initial Static Analysis (Ghidra)

Loading the binary into Ghidra's CodeBrowser and decompiling `main` gives incomplete / broken output:

```c
void main(void)

{
  code *pcVar1;
  long in_FS_OFFSET;
  sigaction local_a8;
  undefined8 local_10;

  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  memset(&local_a8,0,0x98);
  sigemptyset(&local_a8.sa_mask);
  local_a8.__sigaction_handler.sa_handler = segill_sigaction;
  local_a8.sa_flags = 4;
  sigaction(4,&local_a8,(sigaction *)0x0);
                    // WARNING: Does not return
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}
```

Ghidra decompiles `sigaction()` being set up to handle **signal 4 (`SIGILL`)** with a custom handler `segill_sigaction`, then appears to call an unresolved function `invalidInstructionException()` which "does not return."

This is misleading — Ghidra's static analyzer hits a byte sequence it can't disassemble (an intentionally placed `UD2` instruction) and gives up on the rest of the function, assuming the program terminates there.

### The `segill_sigaction` handler

```c
void segill_sigaction(undefined8 param_1,undefined8 param_2,long param_3)
{
  *(long *)(param_3 + 0xa8) = *(long *)(param_3 + 0xa8) + 2;
  return;
}
```

`param_3` is the `ucontext_t*` passed to a `SA_SIGINFO`-style signal handler (`sa_flags = 4` = `SA_SIGINFO`). Offset `+0xa8` in `ucontext_t` on x86-64 Linux corresponds to `uc_mcontext.gregs[REG_RIP]` — the saved instruction pointer at the time of the fault.

The handler simply **adds 2 to the saved RIP**, meaning: *when a SIGILL fires, skip 2 bytes and resume execution right after the illegal instruction.*

---

## 3. The Anti-Disassembly Trick: `UD2`

`UD2` (`0F 0B`) is a 2-byte x86 instruction whose sole purpose is to raise an **Invalid Opcode Exception (SIGILL)**. It's often used intentionally by compilers/sanitizers to mark unreachable code — but here it's abused as an obfuscation primitive:

1. The program installs a `SIGILL` handler at startup.
2. `UD2` instructions are sprinkled throughout `main`, breaking the illusion of a single continuous, linear function for static disassemblers.
3. When executed, each `UD2` raises `SIGILL` → the handler fires → RIP is incremented by 2 (past the `UD2`) → execution resumes normally at the next real instruction.
4. Static tools like Ghidra see `UD2` and assume the function terminates there ("noreturn"), hiding everything that follows from the decompiler view.

This does not affect a debugger stepping through the actual instruction stream, or a disassembler that ignores control-flow assumptions and just walks bytes linearly (e.g. `objdump -d`, or manually forcing GDB to disassemble past the `UD2`).

---

## 4. Real Disassembly (GDB)

Using `gdb ./behindthescenes` and `disas main` gives the full, real assembly — GDB doesn't stop at the `UD2` markers:

```asm
Dump of assembler code for function main:
   0x0000000000001261 <+0>:     endbr64
   0x0000000000001265 <+4>:     push   %rbp
   0x0000000000001266 <+5>:     mov    %rsp,%rbp
   0x0000000000001269 <+8>:     sub    $0xb0,%rsp
   0x0000000000001270 <+15>:    mov    %edi,-0xa4(%rbp)
   0x0000000000001276 <+21>:    mov    %rsi,-0xb0(%rbp)
   0x000000000000127d <+28>:    mov    %fs:0x28,%rax
   0x0000000000001286 <+37>:    mov    %rax,-0x8(%rbp)
   0x000000000000128a <+41>:    xor    %eax,%eax
   0x000000000000128c <+43>:    lea    -0xa0(%rbp),%rax
   0x0000000000001293 <+50>:    mov    $0x98,%edx
   0x0000000000001298 <+55>:    mov    $0x0,%esi
   0x000000000000129d <+60>:    mov    %rax,%rdi
   0x00000000000012a0 <+63>:    call   0x1120 <memset@plt>
   0x00000000000012a5 <+68>:    lea    -0xa0(%rbp),%rax
   0x00000000000012ac <+75>:    add    $0x8,%rax
   0x00000000000012b0 <+79>:    mov    %rax,%rdi
   0x00000000000012b3 <+82>:    call   0x1130 <sigemptyset@plt>
   0x00000000000012b8 <+87>:    lea    -0x96(%rip),%rax        # 0x1229 <segill_sigaction>
   0x00000000000012bf <+94>:    mov    %rax,-0xa0(%rbp)
   0x00000000000012c6 <+101>:   movl   $0x4,-0x18(%rbp)
   0x00000000000012cd <+108>:   lea    -0xa0(%rbp),%rax
   0x00000000000012d4 <+115>:   mov    $0x0,%edx
   0x00000000000012d9 <+120>:   mov    %rax,%rsi
   0x00000000000012dc <+123>:   mov    $0x4,%edi
   0x00000000000012e1 <+128>:   call   0x10e0 <sigaction@plt>
   0x00000000000012e6 <+133>:   ud2
   0x00000000000012e8 <+135>:   cmpl   $0x2,-0xa4(%rbp)
   0x00000000000012ef <+142>:   je     0x130b <main+170>
   0x00000000000012f1 <+144>:   ud2
   0x00000000000012f3 <+146>:   lea    0xd0a(%rip),%rdi        # 0x2004
   0x00000000000012fa <+153>:   call   0x10d0 <puts@plt>
   0x00000000000012ff <+158>:   ud2
   0x0000000000001301 <+160>:   mov    $0x1,%eax
   0x0000000000001306 <+165>:   jmp    0x1439 <main+472>
   0x000000000000130b <+170>:   ud2
   0x000000000000130d <+172>:   mov    -0xb0(%rbp),%rax
   0x0000000000001314 <+179>:   add    $0x8,%rax
   0x0000000000001318 <+183>:   mov    (%rax),%rax
   0x000000000000131b <+186>:   mov    %rax,%rdi
   0x000000000000131e <+189>:   call   0x10f0 <strlen@plt>
   0x0000000000001323 <+194>:   cmp    $0xc,%rax
   0x0000000000001327 <+198>:   jne    0x1432 <main+465>
   0x000000000000132d <+204>:   ud2
   0x000000000000132f <+206>:   mov    -0xb0(%rbp),%rax
   0x0000000000001336 <+213>:   add    $0x8,%rax
   0x000000000000133a <+217>:   mov    (%rax),%rax
   0x000000000000133d <+220>:   mov    $0x3,%edx
   0x0000000000001342 <+225>:   lea    0xcd2(%rip),%rsi        # 0x201b
   0x0000000000001349 <+232>:   mov    %rax,%rdi
   0x000000000000134c <+235>:   call   0x10c0 <strncmp@plt>
   0x0000000000001351 <+240>:   test   %eax,%eax
   0x0000000000001353 <+242>:   jne    0x1429 <main+456>
   0x0000000000001359 <+248>:   ud2
   0x000000000000135b <+250>:   mov    -0xb0(%rbp),%rax
   0x0000000000001362 <+257>:   add    $0x8,%rax
   0x0000000000001366 <+261>:   mov    (%rax),%rax
   0x0000000000001369 <+264>:   add    $0x3,%rax
   0x000000000000136d <+268>:   mov    $0x3,%edx
   0x0000000000001372 <+273>:   lea    0xca6(%rip),%rsi        # 0x201f
   0x0000000000001379 <+280>:   mov    %rax,%rdi
   0x000000000000137c <+283>:   call   0x10c0 <strncmp@plt>
   0x0000000000001381 <+288>:   test   %eax,%eax
   0x0000000000001383 <+290>:   jne    0x1420 <main+447>
   0x0000000000001389 <+296>:   ud2
   0x000000000000138b <+298>:   mov    -0xb0(%rbp),%rax
   0x0000000000001392 <+305>:   add    $0x8,%rax
   0x0000000000001396 <+309>:   mov    (%rax),%rax
   0x0000000000001399 <+312>:   add    $0x6,%rax
   0x000000000000139d <+316>:   mov    $0x3,%edx
   0x00000000000013a2 <+321>:   lea    0xc7a(%rip),%rsi        # 0x2023
   0x00000000000013a9 <+328>:   mov    %rax,%rdi
   0x00000000000013ac <+331>:   call   0x10c0 <strncmp@plt>
   0x00000000000013b1 <+336>:   test   %eax,%eax
   0x00000000000013b3 <+338>:   jne    0x1417 <main+438>
   0x00000000000013b5 <+340>:   ud2
   0x00000000000013b7 <+342>:   mov    -0xb0(%rbp),%rax
   0x00000000000013be <+349>:   add    $0x8,%rax
   0x00000000000013c2 <+353>:   mov    (%rax),%rax
   0x00000000000013c5 <+356>:   add    $0x9,%rax
   0x00000000000013c9 <+360>:   mov    $0x3,%edx
   0x00000000000013ce <+365>:   lea    0xc52(%rip),%rsi        # 0x2027
   0x00000000000013d5 <+372>:   mov    %rax,%rdi
   0x00000000000013d8 <+375>:   call   0x10c0 <strncmp@plt>
   0x00000000000013dd <+380>:   test   %eax,%eax
   0x00000000000013df <+382>:   jne    0x140e <main+429>
   0x00000000000013e1 <+384>:   ud2
   0x00000000000013e3 <+386>:   mov    -0xb0(%rbp),%rax
   0x00000000000013ea <+393>:   add    $0x8,%rax
   0x00000000000013ee <+397>:   mov    (%rax),%rax
   0x00000000000013f1 <+400>:   mov    %rax,%rsi
   0x00000000000013f4 <+403>:   lea    0xc30(%rip),%rdi        # 0x202b
   0x00000000000013fb <+410>:   mov    $0x0,%eax
   0x0000000000001400 <+415>:   call   0x1110 <printf@plt>
   0x0000000000001405 <+420>:   ud2
   0x0000000000001407 <+422>:   mov    $0x0,%eax
   0x000000000000140c <+427>:   jmp    0x1439 <main+472>
   0x000000000000140e <+429>:   ud2
   0x0000000000001410 <+431>:   mov    $0x0,%eax
   0x0000000000001415 <+436>:   jmp    0x1439 <main+472>
   0x0000000000001417 <+438>:   ud2
   0x0000000000001419 <+440>:   mov    $0x0,%eax
   0x000000000000141e <+445>:   jmp    0x1439 <main+472>
   0x0000000000001420 <+447>:   ud2
   0x0000000000001422 <+449>:   mov    $0x0,%eax
   0x0000000000001427 <+454>:   jmp    0x1439 <main+472>
   0x0000000000001429 <+456>:   ud2
   0x000000000000142b <+458>:   mov    $0x0,%eax
   0x0000000000001430 <+463>:   jmp    0x1439 <main+472>
   0x0000000000001432 <+465>:   ud2
   0x0000000000001434 <+467>:   mov    $0x0,%eax
   0x0000000000001439 <+472>:   mov    -0x8(%rbp),%rcx
   0x000000000000143d <+476>:   xor    %fs:0x28,%rcx
   0x0000000000001446 <+485>:   je     0x144d <main+492>
   0x0000000000001448 <+487>:   call   0x1100 <__stack_chk_fail@plt>
   0x000000000000144d <+492>:   leave
   0x000000000000144e <+493>:   ret
End of assembler dump.
```

### Logic breakdown

| Step | Address | Action |
|------|---------|--------|
| 1 | `+135` | Checks `argc == 2` (i.e. exactly one CLI argument given) |
| 2 | `+189` | `strlen(argv[1])`, compares against `0xc` (12) — password must be **exactly 12 characters** |
| 3 | `+206`–`+235` | `strncmp(argv[1] + 0, <static string @ 0x201b>, 3)` — checks **bytes 0–2** |
| 4 | `+250`–`+283` | `strncmp(argv[1] + 3, <static string @ 0x201f>, 3)` — checks **bytes 3–5** |
| 5 | `+298`–`+331` | `strncmp(argv[1] + 6, <static string @ 0x2023>, 3)` — checks **bytes 6–8** |
| 6 | `+342`–`+375` | `strncmp(argv[1] + 9, <static string @ 0x2027>, 3)` — checks **bytes 9–11** |
| 7 | `+386`–`+415` | If all 4 chunks match: `printf("> HTB{%s}\n", argv[1])` |

So the 12-character password is split into **4 chunks of 3 bytes each**, each checked against a separate hardcoded string in `.rodata`. This confirms the "four `strncmp` calls" observation — each call corresponds to one 3-byte segment of the full password.

---

## 5. Extracting the Password Chunks

### Static offsets (from the `lea X(%rip),%rsi` comments in GDB)

These are the binary's *file-relative* `.rodata` addresses (unaffected by ASLR):

```
Chunk 1 → 0x201b
Chunk 2 → 0x201f
Chunk 3 → 0x2023
Chunk 4 → 0x2027
```

### Getting the runtime address

Since the binary is PIE (Position Independent Executable), ASLR randomizes the load base each run. To resolve real, in-memory addresses:

```gdb
(gdb) b main
(gdb) run
(gdb) info proc mappings
```

Find the binary's load base (the first mapped region for `behindthescenes`), then:

```
runtime_address = load_base + static_offset
```

Example from this session: breakpoint at `main+15` landed at `0x555555555270`, so:

```
load_base = 0x555555555270 - 0x1270 = 0x555555554000
```

Runtime addresses:
```
0x555555554000 + 0x201b = 0x55555555601b
0x555555554000 + 0x201f = 0x55555555601f
0x555555554000 + 0x2023 = 0x555555556023
0x555555554000 + 0x2027 = 0x555555556027
```

### Dumping the strings

```gdb
(gdb) x/s 0x55555555601b
(gdb) x/s 0x55555555601f
(gdb) x/s 0x555555556023
(gdb) x/s 0x555555556027
```

Each prints a 3-character ASCII chunk. Concatenated in order, they form the full 12-character password.

> **Note:** since ASLR randomizes the base on every process launch, re-run `b main` / `run` / `info proc mappings` each new GDB session to recompute the load base before dumping.

---

## 6. Solving

Once all 4 chunks are recovered and concatenated:

```bash
$ ./behindthescenes <recovered_password>
> HTB{<recovered_password>}
```

The printed output is the flag.

---

## 7. Key Takeaways

- **`UD2` as anti-disassembly**: inserting deliberate invalid opcodes paired with a `SIGILL` handler that skips past them breaks static analysis tools (Ghidra) that assume linear, non-returning control flow at an illegal instruction — while leaving runtime execution completely unaffected.
- **Static vs. dynamic analysis**: When a decompiler gives you broken/incomplete output around a suspicious "does not return" warning, that's a strong signal to switch to a debugger (GDB) or a raw linear disassembler (`objdump -d`) that won't stop at the fault instruction.
- **Chunked string comparison**: splitting a secret into multiple `strncmp` calls doesn't add real cryptographic security — it's purely an obfuscation layer. Once you find all the call sites and their target buffers, reconstruction is trivial.
- **PIE binaries**: static `.rodata` offsets from `objdump`/Ghidra need the process's actual load base added at runtime to be dereferenced correctly in GDB, since ASLR relocates the whole image on each execution.

---

## 8. Tools Reference

| Tool | Purpose |
|------|---------|
| `strings <bin>` | Fast static scan for readable text (formats, hints, usage strings) |
| `objdump -d -M intel <bin>` | Linear disassembly, ignores control-flow assumptions, disassembles through unreachable/illegal bytes |
| `gdb <bin>` | Dynamic analysis; can disassemble/step past `UD2` traps, dump live memory with `x/s` |
| Ghidra | Good for overall structure & cross-references, but fooled by intentional anti-disassembly tricks like `UD2` + signal handlers |
