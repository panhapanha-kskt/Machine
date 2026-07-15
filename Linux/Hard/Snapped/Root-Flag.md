# HTB — Snapped (Hard) — Root Flag Writeup

**Machine:** Snapped
**Difficulty:** Hard
**Flag obtained:** `root.txt`
**Vulnerability exploited:** CVE-2026-3888 — `snap-confine` / `systemd-tmpfiles` TOCTOU Race Condition (SUID variant)
**CVSS:** 7.8 (High)
**Patched in:** snapd 2.74.2

> Prerequisite: a foothold as `jonathan` via SSH. See the user flag writeup for the CVE-2026-27944 Nginx-UI exploitation chain that gets you here.

---

## 1. Identifying the Vulnerability

### Checking the snapd version

```bash
jonathan@snapped:~$ snap --version
snap    2.63.1+24.04
snapd   2.63.1+24.04
series  16
ubuntu  24.04
kernel  6.8.0-41-generic
```

This version predates the 2.74.2 patch, so the box is vulnerable to **CVE-2026-3888**.

On Ubuntu 24.04, `/usr/lib/snapd/snap-confine` is a **SUID-root** binary responsible for building each snap's sandbox before it runs. Part of that setup involves creating "mimics" — writable stand-ins for read-only system directories such as `/usr/lib/x86_64-linux-gnu`. The mimic sequence is:

1. bind-mount the real directory into staging under `/tmp/.snap/...`
2. mount a fresh tmpfs over the real path
3. bind-mount each staged file back into place, **as root**
4. clean up the staging directory

Because steps 1–3 aren't atomic, whoever controls the contents of the staging directory at step 3 gets their files mounted into the sandbox with root privileges. This is the classic TOCTOU (time-of-check-to-time-of-use) window.

### Confirming exploitable conditions

```bash
jonathan@snapped:~$ systemctl cat systemd-tmpfiles-clean.timer
# /etc/systemd/system/systemd-tmpfiles-clean.timer.d/override.conf
[Timer]
OnBootSec=1m
OnUnitActiveSec=1m

jonathan@snapped:~$ cat /usr/lib/tmpfiles.d/tmp.conf
D /tmp 1777 root root 4m
```

The cleanup timer has been overridden to run every minute, and files in `/tmp` older than 4 minutes are purged. This means the `.snap` staging directory goes stale quickly and can be recreated — attacker-owned — in a short window, rather than the default 30-day age-out on stock Ubuntu 24.04.

---

## 2. Building the Exploit

Two components are needed, both compiled **locally on the attacking machine** (statically, so they run on the target with no library dependency issues):

| File | Purpose |
|------|---------|
| `exploit_suid.c` | Orchestrates the full attack: enter sandbox, wait for `.snap` cleanup, win the race, inject the payload, trigger root, escape the sandbox |
| `librootshell_suid.c` | Minimal payload ELF using raw x86_64 syscalls — no libc — that replaces the dynamic linker |

```bash
gcc -O2 -static -o exploit exploit_suid.c
gcc -nostdlib -static -Wl,--entry=_start -o librootshell.so librootshell_suid.c
```

Transfer both files to the target:

```bash
scp exploit librootshell.so jonathan@snapped.htb:~/
```

On the target:

```bash
jonathan@snapped:~$ chmod +x exploit
```

---

## 3. How the Race Is Won Reliably

A pure timing race against `snap-confine` would be unreliable, so the exploit uses an I/O backpressure trick instead:

- `snap-confine`'s `stderr` is redirected to a Unix domain socket configured with `SO_RCVBUF=1` and `SO_SNDBUF=1`.
- With a 1-byte buffer, `snap-confine` **blocks on every single `write()`** to stderr until the exploit reads exactly one byte back.
- This effectively lets the exploit single-step `snap-confine`'s execution, byte by byte, through its debug output.
- When the trigger line `dir:"/tmp/.snap/usr/lib/x86_64-linux-gnu"` appears — logged right after step 1 of the mimic sequence — `snap-confine` is paused mid-write.
- At that exact moment, the exploit atomically swaps the staging directory with `renameat2(RENAME_EXCHANGE)`, replacing it with a directory of attacker-controlled libraries.
- `snap-confine` resumes and bind-mounts the attacker's files into the sandbox **as root**.

A separate access trick is needed to reach the sandbox's private `/tmp` in the first place: `/tmp/snap-private-tmp/` is `700 root:root` and not directly traversable, but `/proc/<PID>/cwd` follows the sandboxed process's own view of its mount namespace, bypassing that host-level permission check entirely.

---

## 4. Running the Exploit

```bash
jonathan@snapped:~$ ./exploit ./librootshell.so
```

The exploit runs through seven phases automatically:

1. **Enter the Firefox snap sandbox** — spawns an inner shell and records its PID.
2. **Wait for `.snap` deletion** — polls until `systemd-tmpfiles` cleans the stale mimic directory (fast here, thanks to the 1-minute timer override).
3. **Destroy the cached mount namespace** — forces a (deliberately failing) re-invocation of `snap-confine` to tear down the cached namespace while preserving `/tmp`.
4. **Set up and win the race** — recreates `.snap` as attacker-owned, populates an `.exchange` directory with ~285 real libraries copied from `core22`, then single-steps `snap-confine` via the socket-backpressure technique and swaps the directories at the trigger point via `renameat2`.
5. **Inject the payload** — confirms the swapped library directory is attacker-owned, plants a static `busybox` at `/tmp/sh`, and overwrites `ld-linux-x86-64.so.2` inside the poisoned namespace with the `librootshell.so` shellcode.
6. **Trigger root** — re-invokes SUID-root `snap-confine` inside the poisoned namespace. Because `snap-confine` is dynamically linked, the kernel loads whatever `PT_INTERP` points to — now the attacker's shellcode — **before** the program itself runs, with the SUID binary's root privileges. The shellcode calls `setreuid(0,0)` and `setregid(0,0)`, then `execve("/tmp/sh")`.
7. **Verify and escape** — from the resulting root shell inside busybox, a copy of `bash` is placed in `/var/snap/firefox/common/` and made SUID (`chmod 4755`). The Firefox snap's AppArmor profile happens to permit writes to that directory, so the SUID bash persists there with **no AppArmor confinement** once the sandbox is exited.

Expected output on success:

```
[Phase 6] Triggering root via SUID snap-confine...
[*]   snap-confine → snap-confine (SUID trigger)
[*]   Exit status: 0

[Phase 7] Verifying...
[+] SUID root bash: /var/snap/firefox/common/bash (mode 4755)

================================================================
  ROOT SHELL: /var/snap/firefox/common/bash -p
================================================================
```

---

## 5. Escaping to a Persistent Root Shell

```bash
jonathan@snapped:~$ /var/snap/firefox/common/bash -p
bash-5.1# id
uid=1000(jonathan) gid=1000(jonathan) euid=0(root) groups=1000(jonathan)
```

The `-p` flag preserves the SUID effective UID/GID rather than dropping them, giving a genuine root shell **outside** the sandbox.

```bash
bash-5.1# cat /root/root.txt
```

**Root flag obtained.** 🚩

---

## Summary of the Attack Chain

1. Confirm `snapd` version < 2.74.2 and that `snap-confine` is SUID-root → vulnerable to CVE-2026-3888.
2. Confirm the aggressive `/tmp` cleanup timer, which makes the `.snap` staging directory race-able quickly.
3. Compile the exploit and payload locally (static binaries) and transfer them to the target.
4. Enter the Firefox snap sandbox and wait for `.snap` to be cleaned up.
5. Recreate `.snap` as attacker-owned and win the TOCTOU race using AF_UNIX socket backpressure to single-step `snap-confine`.
6. Swap in attacker-controlled libraries via `renameat2(RENAME_EXCHANGE)` at the exact moment of the bind-mount.
7. Overwrite the dynamic linker (`ld-linux-x86-64.so.2`) with shellcode that escalates to root.
8. Trigger the poisoned linker by re-invoking SUID `snap-confine`.
9. Drop a SUID root `bash` into an AppArmor-permitted snap data directory to escape the sandbox with full, unconfined root.

---

## Tools / Techniques Used

- `gcc` — static compilation of the exploit and raw-syscall payload
- `scp` — binary transfer to the target
- AF_UNIX `socketpair()` with 1-byte `SO_RCVBUF`/`SO_SNDBUF` — I/O backpressure single-stepping
- `renameat2(RENAME_EXCHANGE)` — atomic directory swap at the race window
- `/proc/<PID>/cwd` — mount-namespace-aware traversal bypassing host permission checks
- `PT_INTERP` / dynamic linker hijacking — SUID privilege escalation
- AppArmor profile misconfiguration — sandbox escape via a writable snap common directory

---

## Lessons Learned

- Non-atomic multi-step privileged filesystem operations (check → act) are inherently race-prone; an attacker with write access to intermediate staging paths can win these races reliably using I/O backpressure rather than brute-force timing.
- Aggressive tuning of cleanup timers (`systemd-tmpfiles`) for other operational reasons can inadvertently shrink the window attackers need to exploit TOCTOU conditions, rather than eliminating it.
- SUID binaries that are dynamically linked are only as trustworthy as the library directories they load from — if any part of that path becomes attacker-writable, even briefly, full compromise follows.
- Sandbox/confinement mechanisms (AppArmor, mount namespaces) are only as strong as their permitted write paths; a single writable directory intended for legitimate snap data can become a durable escape hatch.
