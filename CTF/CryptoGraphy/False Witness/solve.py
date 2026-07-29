#!/usr/bin/env python3
from pwn import remote, context
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# context.log_level = 'debug'  # uncomment if you need to see raw traffic

HOST, PORT = "154.57.164.82", 30437
P = 0xCD4A96D3B7FA7251A1BB765933FB676FCAE8C9026682E34F779122DFD66915BB
G = P - 1  # order-2 element: G^msg mod P is 1 (msg even) or P-1 (msg odd)

io = remote(HOST, PORT, timeout=10)

io.recvuntil(b"you:")
io.recvline()  # eat rest of that line
ct_hex = io.recvline().strip().decode()
ct = bytes.fromhex(ct_hex)
print("Ciphertext:", ct_hex)

io.recvuntil(b"give me the hashing generator: ")
io.sendline(str(G).encode())

bits = []
for i in range(256):
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"Enter offset: ")
    io.sendline(str(i).encode())
    line = io.recvline().decode()
    val = int(line.split(":")[1].strip())
    bit = '1' if (val == 1 or val == P - 1) else '0'
    bits.append(bit)
    if i % 32 == 0:
        print(f"[{i}/256] val={val} bit={bit}")

io.recvuntil(b"> ")
io.sendline(b"2")
io.close()

key_int = int(''.join(bits), 2)
KEY = key_int.to_bytes(32, 'big')
print("Recovered KEY:", KEY.hex())

flag = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(ct), 16)
print("FLAG:", flag.decode())
