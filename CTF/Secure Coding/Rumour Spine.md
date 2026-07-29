# Rumour Spine

A solution for finding the minimum vertex cut between a coordinator and a target district — framed as Miren Vale severing every path the Quiet March's priming signal could travel, without touching the coordinator or target directly.

## Problem

A directed graph of `N` quiet hands (nodes) and `E` links (edges) represents every path a priming signal could take from coordinator `S` to target district `T`. Find the minimum number of nodes, other than `S` and `T`, that must be removed to disconnect all paths from `S` to `T`.

**Input format**
```
N E S T
u v   (E lines — directed edge from u to v)
```

**Output format**
```
A single integer — the minimum number of nodes to remove to disconnect S from T
```

**Constraints**
- 6 ≤ N ≤ 120
- 1 ≤ E ≤ 360
- S = 0, T = N-1
- The graph may contain cycles
- At least one path from S to T is guaranteed
- No direct edge from S to T

## Approach

This is a minimum vertex cut problem — S and T themselves are off-limits for removal. It reduces cleanly to max-flow via **node splitting**:

- Each node `i` is split into an in-node and an out-node, connected by an edge of capacity 1 (the cost of "exposing" that hand) — except S and T, whose internal edge gets infinite capacity since they can never be removed.
- Each original directed edge `u -> v` becomes an edge from `out_u` to `in_v` with infinite capacity, since edges are never the bottleneck — only nodes are.

By Menger's theorem, the max flow from `out_S` to `in_T` in this transformed network equals the minimum number of nodes needed to disconnect S from T.

Max flow is computed with **Dinic's algorithm**. The transformed network has at most 2×120 = 240 nodes and roughly 120 + 2×360 = 840 edges, well within reach for Dinic's O(V²E) worst case at this scale.

## Solution

```python
import sys
from collections import deque

class Dinic:
    def __init__(self, n):
        self.n = n
        self.graph = [[] for _ in range(n)]  # each entry: [to, cap, rev_index]

    def add_edge(self, u, v, cap):
        self.graph[u].append([v, cap, len(self.graph[v])])
        self.graph[v].append([u, 0, len(self.graph[u]) - 1])

    def bfs(self, s, t):
        self.level = [-1] * self.n
        self.level[s] = 0
        q = deque([s])
        while q:
            u = q.popleft()
            for edge in self.graph[u]:
                v, cap, _ = edge
                if cap > 0 and self.level[v] < 0:
                    self.level[v] = self.level[u] + 1
                    q.append(v)
        return self.level[t] >= 0

    def dfs(self, u, t, f):
        if u == t:
            return f
        while self.it[u] < len(self.graph[u]):
            edge = self.graph[u][self.it[u]]
            v, cap, rev = edge
            if cap > 0 and self.level[v] == self.level[u] + 1:
                d = self.dfs(v, t, min(f, cap))
                if d > 0:
                    edge[1] -= d
                    self.graph[v][rev][1] += d
                    return d
            self.it[u] += 1
        return 0

    def max_flow(self, s, t):
        flow = 0
        while self.bfs(s, t):
            self.it = [0] * self.n
            while True:
                f = self.dfs(s, t, float('inf'))
                if f == 0:
                    break
                flow += f
        return flow


def main():
    data = sys.stdin.read().split()
    idx = 0

    N = int(data[idx]); idx += 1
    E = int(data[idx]); idx += 1
    S = int(data[idx]); idx += 1
    T = int(data[idx]); idx += 1

    # Node splitting: in-node i -> id i, out-node i -> id i + N
    INF = float('inf')
    dinic = Dinic(2 * N)

    for i in range(N):
        cap = INF if (i == S or i == T) else 1
        dinic.add_edge(i, i + N, cap)

    for _ in range(E):
        u = int(data[idx]); idx += 1
        v = int(data[idx]); idx += 1
        dinic.add_edge(u + N, v, INF)

    result = dinic.max_flow(S + N, T)
    print(result)

main()
```

## Example

**Input**
```
7 8 0 6
0 1
0 2
1 3
2 4
3 6
4 6
2 3
1 4
```

**Output**
```
2
```

**Trace**

The paths from 0 to 6 are:
```
0 -> 1 -> 3 -> 6
0 -> 1 -> 4 -> 6
0 -> 2 -> 3 -> 6
0 -> 2 -> 4 -> 6
```

No single node lies on all four paths, so one exposure can't cut S off from T. Exposing nodes **1** and **2** removes every surviving path — max flow = **2**.

## Usage

```bash
python3 solution.py < input.txt
```
