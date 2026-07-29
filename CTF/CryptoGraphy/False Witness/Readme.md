# False Witness

**Category:** Crypto
**Target:** `154.57.164.82:30437`

## Scenario

> Caldrin Vowmark knows that not every seal deserves belief. Some marks still
> carry the weight of a living vow; others only imitate one well enough to
> pass a glance. She can question the realm's witnesses as many times as she
> likes, but certainty, it turns out, is much harder to earn than a
> convincing lie.

## Overview

The server implements a Lamport-style one-time-signature scheme built on a
discrete-log based "hash" function:

```python
def H(msg):
    return pow(G, msg, P)
```

Each bit of a random 256-bit AES key has a corresponding pair of secret
values `sk[i] = (s0, s1)` and public values `pk[i] = (H(s0), H(s1))`. An
oracle lets you query index `i` and get back:

- a **uniformly random 256-bit integer** if `KEY_BITS[i] == 0`
- **one of the two public values** `pk[i][0]` or `pk[i][1]` if `KEY_BITS[i] == 1`

Each index is cached after first use, so you only get one look at it — but
that's enough, because of a critical design flaw: **the client supplies the
generator `G`** before keygen happens.

```python
while True:
    G = int(input("Before we start, give me the hashing generator: "))
    if 1 < G < P:
        break
```

## The vulnerability

`P` is confirmed prime (256-bit), so there's no way to pick a `G` that makes
`H` collapse to a single constant value (that would require an idempotent
element mod `P`, which only exist — trivially — for `G = 0` or `G = 1`, both
excluded by the `1 < G < P` check).

Instead, pick **`G = P - 1`**, i.e. `G ≡ -1 (mod P)`. This element has
multiplicative order 2, so:

```
H(msg) = G^msg mod P = 1        if msg is even
                       P - 1    if msg is odd
```

Every public value `pk[i][j]` therefore lands in the tiny set `{1, P-1}`,
**regardless of the actual secret**. This turns the oracle into a clean
binary distinguisher:

| Oracle response                | Bit value |
|---------------------------------|-----------|
| `1` or `P-1`                    | `KEY_BITS[i] = 1` |
| any other 256-bit integer        | `KEY_BITS[i] = 0` |

A truly random 256-bit integer landing on `1` or `P-1` by chance has
probability `~2^-255` — negligible. So querying all 256 offsets once fully
recovers the AES key used to encrypt the flag (printed at connection time).

## Exploit steps

1. Connect, capture the AES-ECB-encrypted flag printed on connect.
2. Send `G = P - 1` as the generator.
3. Query the oracle for every offset `0..255` once.
4. Classify each result: `1`/`P-1` → bit `1`, else → bit `0`.
5. Reassemble the 256 bits into the AES key.
6. AES-ECB decrypt the captured ciphertext and unpad to get the flag.

## Usage

```bash
python3 exploit.py
```

Outputs the recovered AES key and the flag.

## Files

- `exploit.py` — full solve script (pwntools).

## Key takeaway

Never let an untrusted party choose parameters for a cryptographic primitive
after the fact (generator, modulus, curve, etc.) if those parameters affect
the primitive's security properties. Here, letting the client pick `G`
completely destroyed the one-wayness of `H`, since a low-order element makes
the "hash" function only take a handful of possible outputs.
