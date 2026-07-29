# Three Tankards and a Lie

A solution for tracking item positions through a sequence of swaps — framed as Rin Kagetsura tailing a courier's tankard shuffle at the Drowned Bell.

## Problem

`N` tankards start out holding item `i` in position `i`. A sequence of `M` swaps is applied, in order, each exchanging the contents of two positions. Given `Q` starting positions, report where the item that started at each one ends up after all swaps.

**Input format**
```
N M Q
a b        (M lines — swap positions a and b)
p          (Q lines — starting position to query)
```

**Output format**
```
Q lines — final position of the item that started at p
```

**Constraints**
- 1 ≤ N ≤ 2000
- 0 ≤ M ≤ 5000
- 1 ≤ Q ≤ 2000

## Approach

Maintain two arrays instead of replaying history per query:

- `cur[position]` — the item currently sitting at that position
- `itemPos[item]` — the current position of that item

Each swap `a b` swaps `cur[a]` and `cur[b]`, and updates `itemPos` for the two items that moved. After all `M` swaps are applied once, `itemPos[p]` is a direct lookup — no need to re-simulate per query.

This runs in **O(N + M + Q)**, well under any reasonable limit for the given constraints (worst case ~9,000 operations).

## Solution

```python
import sys

def main():
    data = sys.stdin.read().split()
    idx = 0
    N = int(data[idx]); idx += 1
    M = int(data[idx]); idx += 1
    Q = int(data[idx]); idx += 1

    cur = list(range(N + 1))      # cur[position] = item at that position
    itemPos = list(range(N + 1))  # itemPos[item] = position of that item

    for _ in range(M):
        a = int(data[idx]); idx += 1
        b = int(data[idx]); idx += 1
        ia, ib = cur[a], cur[b]
        cur[a], cur[b] = ib, ia
        itemPos[ia], itemPos[ib] = b, a

    out = []
    for _ in range(Q):
        p = int(data[idx]); idx += 1
        out.append(str(itemPos[p]))

    print('\n'.join(out))

main()
```

## Example

**Input**
```
5 4 2
1 3
2 4
3 5
4 1
3
5
```

**Output**
```
4
3
```

**Trace**
- Item that started at 3: swap `(1,3)` moves it to 1. `(2,4)` and `(3,5)` don't touch position 1. Swap `(4,1)` moves it to 4. → **4**
- Item that started at 5: `(1,3)` and `(2,4)` don't touch it. Swap `(3,5)` moves it to 3. `(4,1)` doesn't touch position 3. → **3**

## Usage

```bash
python3 solution.py < input.txt
```
