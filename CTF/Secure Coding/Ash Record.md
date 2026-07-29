# Ash Record

A solution for confirming the longest prefix of a suspected extraction sequence from timestamped residues — framed as Elowen Ashglass reconstructing a staged, not raided, evacuation.

## Problem

`N` recovered residues each carry a timestamp and a material type, given in arbitrary order. A suspected extraction sequence of `P` material types is given. Find the length of the longest prefix of that sequence that can be confirmed by a subsequence of residues matching it in order, where consecutively matched residues are at least `min_gap` apart in time.

**Input format**
```
N P min_gap
<P material types — the suspected sequence>
<timestamp> <material type>   (N lines)
```

**Output format**
```
A single integer — the length of the longest confirmable prefix
```

**Constraints**
- 1 ≤ N ≤ 5000
- 1 ≤ P ≤ 12
- 1 ≤ min_gap ≤ 10
- 1 ≤ timestamp ≤ 10000
- Material type strings: lowercase letters, length ≤ 10

## Approach

Sort residues by timestamp. Run a DP where `dp[k]` tracks the *earliest possible* timestamp that completes a valid match of the first `k` steps of the sequence — earliest is always best, since it leaves the most room for the gap constraint on the remaining steps.

Process residues in timestamp order. For each one, scan prefix lengths `k` from `P` down to `1` (high-to-low so a single residue can't be reused twice within the same pass). If the residue's material matches `seq[k-1]` and the gap from `dp[k-1]` is at least `min_gap` (no gap check needed for `k == 1`), it can potentially extend that prefix — update `dp[k]` with the smaller of its current value and this residue's timestamp.

The answer is the largest `k` for which `dp[k]` is finite.

**Complexity:** O(N·P) — at most 5000 × 12 = 60,000 operations, trivial for the given limits.

## Solution

```python
import sys

def main():
    data = sys.stdin.read().split()
    idx = 0

    N = int(data[idx]); idx += 1
    P = int(data[idx]); idx += 1
    min_gap = int(data[idx]); idx += 1

    seq = data[idx:idx+P]; idx += P

    residues = []
    for _ in range(N):
        ts = int(data[idx]); idx += 1
        mat = data[idx]; idx += 1
        residues.append((ts, mat))

    residues.sort(key=lambda x: x[0])

    INF = float('inf')
    NEG_INF = float('-inf')

    # dp[k] = minimum timestamp at which the first k steps of seq
    # can be confirmed (satisfying the min_gap constraint), or INF if impossible.
    dp = [INF] * (P + 1)
    dp[0] = NEG_INF

    for ts, mat in residues:
        # iterate k from high to low so each residue is used at most once per pass
        for k in range(P, 0, -1):
            if seq[k-1] != mat:
                continue
            prev = dp[k-1]
            if prev == INF:
                continue
            if k == 1 or ts - prev >= min_gap:
                if ts < dp[k]:
                    dp[k] = ts

    ans = 0
    for k in range(P, 0, -1):
        if dp[k] != INF:
            ans = k
            break

    print(ans)

main()
```

## Example

**Input**
```
5 4 3
ash rope oil ash
1 ash
4 rope
7 oil
10 ash
11 rope
```

**Output**
```
4
```

**Trace**

Sorted residues: `(1,ash) (4,rope) (7,oil) (10,ash) (11,rope)`

| Step | Sequence type | Matched residue | Gap from previous |
|---|---|---|---|
| 1 | ash | timestamp 1 | — |
| 2 | rope | timestamp 4 | 3 ≥ 3 |
| 3 | oil | timestamp 7 | 3 ≥ 3 |
| 4 | ash | timestamp 10 | 3 ≥ 3 |

All four steps confirmed → **4**. The residue at timestamp 11 (rope) isn't needed for this match.

## Usage

```bash
python3 solution.py < input.txt
```
