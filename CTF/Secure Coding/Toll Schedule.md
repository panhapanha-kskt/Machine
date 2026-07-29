# Toll Schedule

A solution for computing the minimum total wait when assigning convoys to checkpoint clearances — framed as Elric Ashspar establishing the clean baseline a rigged schedule will be measured against.

## Problem

`N` convoys each arrive at a known time. `G` checkpoint clearances (G ≥ N) each open at a known time and can seat exactly one convoy, no earlier than its arrival. Every convoy must be assigned to a distinct clearance that opens at or after its arrival. Find the minimum possible total waiting time (clearance opening time − convoy arrival time), summed over all convoys.

**Input format**
```
N G
<N arrival times>
<G clearance opening times>
```

**Output format**
```
A single integer — the minimum total waiting time
```

**Constraints**
- 1 ≤ N ≤ 1200
- N ≤ G ≤ 1500
- 1 ≤ arrival time ≤ 200
- 1 ≤ clearance opening time ≤ 220
- A valid assignment is guaranteed to exist

## Approach

Total wait = (sum of clearances used) − (sum of arrivals). The arrival sum is fixed, so minimizing total wait reduces to picking the cheapest N clearances that admit a valid matching.

Sort both arrivals and clearances ascending. Walk convoys in increasing arrival order, and for each one advance a pointer through the sorted clearances until reaching the first clearance that's still available and legal (opens at or after that arrival) — that's the cheapest option left for it. Because both lists are sorted, the pointer only ever moves forward, so this greedy pass is linear after the sort.

**Complexity:** O(N log N + G log G) for sorting, O(N + G) for the single pass — comfortably fast for the given constraints.

## Solution

```python
import sys

def main():
    data = sys.stdin.read().split()
    idx = 0

    N = int(data[idx]); idx += 1
    G = int(data[idx]); idx += 1

    arrivals = list(map(int, data[idx:idx+N])); idx += N
    clearances = list(map(int, data[idx:idx+G])); idx += G

    arrivals.sort()
    clearances.sort()

    total_wait = 0
    j = 0
    for a in arrivals:
        while clearances[j] < a:
            j += 1
        total_wait += clearances[j] - a
        j += 1

    print(total_wait)

main()
```

## Example

**Input**
```
4 4
2 4 6 9
3 5 8 11
```

**Output**
```
6
```

**Trace**

| Convoy arrival | Clearance | Wait |
|---|---|---|
| 2 | 3 | 1 |
| 4 | 5 | 1 |
| 6 | 8 | 2 |
| 9 | 11 | 2 |

Total waiting time: 1 + 1 + 2 + 2 = **6**

## Usage

```bash
python3 solution.py < input.txt
```
