# Run: gdb -q -x solve.py ./re03-lin-x86.bin
import gdb, struct, re

gdb.execute("set pagination off")
gdb.execute("break memmem")
gdb.execute("run > /dev/null")          # hide the banner, stop at memmem

inf = gdb.selected_inferior()
esp = int(gdb.parse_and_eval("$esp")) & 0xffffffff
words = struct.unpack("<32I", inf.read_memory(esp, 0x80).tobytes())

for i in range(len(words) - 3):
    if words[i] == 0x100 and words[i + 1] == 7:
        out, needle = words[i + 2], words[i + 3]
        break
else:
    raise SystemExit("[-] memmem args not found on stack")

print("[+] out    = %#x" % out)
print("[+] needle = %r" % inf.read_memory(needle, 7).tobytes())   # expect b'badf00d'

# Stack layout from Ghidra: key = out-0x201, ct = out-0x101, out = XOR result
blob = inf.read_memory(out - 0x201, 0x301).tobytes()
key, ct, pt = blob[:0x100], blob[0x100:0x200], blob[0x201:0x301]

def x(a, b): return bytes(p ^ q for p, q in zip(a, b))
print("[+] ct^key == out (layout sanity check):", x(ct, key) == pt)

open("key.bin", "wb").write(key)
open("ct.bin", "wb").write(ct)
open("pt.bin", "wb").write(pt)
print("\nkey:", key.hex())
print("ct :", ct.hex())
print("pt :", pt.hex())
print("\nprintable runs in pt:", re.findall(rb"[ -~]{4,}", pt))

# "TIME is REVERSIBLE" -> try reversed / endian-swapped / rotated variants
def swap32(b): return b"".join(b[i:i+4][::-1] for i in range(0, len(b), 4))
tf = {"id": lambda b: b,
      "rev": lambda b: b[::-1],
      "swap32": swap32,
      "rev+swap32": lambda b: swap32(b[::-1])}

found = False
for kn, kf in tf.items():
    for cn, cf in tf.items():
        k, c = kf(key), cf(ct)
        for r in range(256):
            p = x(c, k[r:] + k[:r])
            if b"badf00d" in p.lower():
                found = True
                print("\n[HIT] key=%s ct=%s rot=%d" % (kn, cn, r))
                print(re.findall(rb"[ -~]{4,}", p))
if not found:
    print("\n[-] no variant produced 'badf00d'; paste the key/ct/pt hex above to me")
