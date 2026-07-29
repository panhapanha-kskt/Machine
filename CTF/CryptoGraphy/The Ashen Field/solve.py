#!/usr/bin/env python3
"""
USAGE:
    python3 solve_nullspace.py output.txt
"""
import sys, re, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
N = 137
def parse_equations(text):
    text = text.strip()
    if text.startswith("("):
        text = text[1:]
    if text.endswith(")"):
        text = text[:-1]
    polys = [p.strip() for p in text.split(",")]
    assert len(polys) == N, f"expected {N} equations, got {len(polys)}"
    return polys
def poly_to_linear_row(poly_str):
    row = [0] * N
    for m in re.finditer(r"x(\d+)\^(\d+)", poly_str):
        idx = int(m.group(1)) - 1
        row[idx] ^= 1  # toggle: x^4 and x^2 each contribute 1, so x^4+x^2 -> 0
    stripped = re.sub(r"x\d+\^\d+", "", poly_str)
    const = 1 if re.search(r"(?<![\w])1(?![\w])", stripped) else 0
    return row, const
def gf2_solve_with_nullspace(A_in, b):
    n = len(A_in)
    # Augmented matrix [A | b]
    M = [row[:] + [b[i]] for i, row in enumerate(A_in)]
    ncols = n + 1
    pivot_row = 0
    pivot_cols = []
    col_to_pivot_row = {}

    for col in range(n):
        # Find pivot
        sel = None
        for r in range(pivot_row, n):
            if M[r][col] == 1:
                sel = r
                break
        if sel is None:
            continue
        M[pivot_row], M[sel] = M[sel], M[pivot_row]
        # Eliminate column
        for r in range(n):
            if r != pivot_row and M[r][col] == 1:
                for c in range(col, ncols):
                    M[r][c] ^= M[pivot_row][c]
        col_to_pivot_row[col] = pivot_row
        pivot_cols.append(col)
        pivot_row += 1
        if pivot_row == n:
            break

    free_cols = [c for c in range(n) if c not in col_to_pivot_row]
    rank = len(pivot_cols)

    # Particular solution (free vars = 0)
    x_part = [0] * n
    for i, col in enumerate(pivot_cols):
        x_part[col] = M[i][ncols - 1]

    # Null space basis vectors: one per free variable
    # For free var f: set x_f=1, read pivot vars from reduced matrix
    null_basis = []
    for f in free_cols:
        v = [0] * n
        v[f] = 1
        for i, col in enumerate(pivot_cols):
            v[col] = M[i][f]
        null_basis.append(v)

    return x_part, null_basis, free_cols, pivot_cols
def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "output.txt"
    with open(path) as f:
        lines = f.read().splitlines()
    eq_text = lines[0]
    y_text = lines[1]
    hex_text = lines[2].strip()
    polys = parse_equations(eq_text)
    A, b_const = [], []
    for p in polys:
        row, const = poly_to_linear_row(p)
        A.append(row)
        b_const.append(const)
    y = [int(v.strip()) for v in y_text.strip("[]").split(",")]
    rhs = [y[i] ^ b_const[i] for i in range(N)]
    ct = bytes.fromhex(hex_text)

    x_part, null_basis, free_cols, pivot_cols = gf2_solve_with_nullspace(A, rhs)
    rank = len(pivot_cols)
    k = len(null_basis)
    print(f"Rank: {rank}/{N}")
    print(f"Free variables ({k}): {[c+1 for c in free_cols]}")
    print(f"Enumerating {2**k} candidate keys...")

    def try_key(key_int, label=""):
        aes_key = hashlib.sha256(str(key_int).encode()).digest()
        try:
            pt = AES.new(aes_key, AES.MODE_ECB).decrypt(ct)
            flag = unpad(pt, 16)
            print(f"\n*** FLAG [{label}]: {flag.decode(errors='replace')} ***")
            return True
        except Exception:
            return False

    found = False
    for mask in range(2 ** k):
        x = x_part[:]
        for bit in range(k):
            if (mask >> bit) & 1:
                for j in range(N):
                    x[j] ^= null_basis[bit][j]
        # KEY = sum(x[j] * 2^j): x[0]=x1=LSB, x[136]=x137=MSB
        key = sum(x[j] << j for j in range(N))
        label = f"mask={mask:0{k}b}" if k > 0 else "unique"
        if try_key(key, label):
            found = True
            break
    if not found:
        print("No solution found. Check parsing or bit ordering.")
if __name__ == "__main__":
    main()
