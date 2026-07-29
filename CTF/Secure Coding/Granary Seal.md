# Granary Seal

A solution for validating ration orders against three independent custody rolls — framed as Lysa Harrowmere checking clerk, countersigner, and courier against the hands the gatehouse has actually watched work.

## Problem

Three custody rolls are given — one each for clerks, countersigners, and couriers. A batch of `N` orders follows, each listing a clerk, countersigner, and courier. An order survives only if all three names appear on their respective role's roll. Count how many orders survive.

**Input format**
```
C
<clerk name> x C
CS
<countersigner name> x CS
R
<courier name> x R
N
<clerk> <countersigner> <courier>   (N lines)
```

**Output format**
```
A single integer — the number of orders where all three hands are on their role's roll
```

**Constraints**
- 1 ≤ C, CS, R ≤ 20
- 1 ≤ N ≤ 5000
- Names consist of lowercase letters and dots, length ≤ 30

## Approach

Load each custody roll into its own set. For each order, check membership of the clerk, countersigner, and courier against their respective set — an order survives only if all three checks pass.

Set membership is O(1) on average, so the whole batch is checked in **O(C + CS + R + N)** — comfortably fast for the given constraints.

## Solution

```python
import sys

def main():
    data = sys.stdin.read().split()
    idx = 0

    C = int(data[idx]); idx += 1
    clerks = set(data[idx:idx+C]); idx += C

    CS = int(data[idx]); idx += 1
    countersigners = set(data[idx:idx+CS]); idx += CS

    R = int(data[idx]); idx += 1
    couriers = set(data[idx:idx+R]); idx += R

    N = int(data[idx]); idx += 1

    count = 0
    for _ in range(N):
        clerk = data[idx]; idx += 1
        countersigner = data[idx]; idx += 1
        courier = data[idx]; idx += 1
        if clerk in clerks and countersigner in countersigners and courier in couriers:
            count += 1

    print(count)

main()
```

## Example

**Input**
```
3
aldric.vowmark
bren.irongate
seyna.saltholm
3
voss.ashglass
tal.greywater
mira.crownwall
3
garren.cinders
lysa.stonepass
elric.brinemark
7
aldric.vowmark voss.ashglass garren.cinders
bren.irongate tal.greywater lysa.stonepass
cassian.embervane voss.ashglass garren.cinders
aldric.vowmark forger.oathstone garren.cinders
seyna.saltholm mira.crownwall ghost.saltwind
bren.irongate voss.ashglass elric.brinemark
seyna.saltholm tal.greywater garren.cinders
```

**Output**
```
4
```

**Trace**
- Orders **1, 2, 6, 7** — all three names are on their role's roll. Survive.
- Order 3 — `cassian.embervane` not on the clerk roll. Fails.
- Order 4 — `forger.oathstone` not on the countersigner roll. Fails.
- Order 5 — `ghost.saltwind` not on the courier roll. Fails.

## Usage

```bash
python3 solution.py < input.txt
```
