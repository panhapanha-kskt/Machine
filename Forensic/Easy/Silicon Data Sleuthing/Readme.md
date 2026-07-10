# Silicon Data Sleuthing — HTB Forensics Writeup

> **Difficulty:** Easy  
> **Category:** Forensics  
> **Challenge:** OpenWRT firmware image analysis  
> **Author:** c4n0pus

---

## Table of Contents

1. [Overview](#overview)
2. [Tools Required](#tools-required)
3. [File Structure After Extraction](#file-structure-after-extraction)
4. [OpenWRT Partition Layout](#openwrt-partition-layout)
5. [Step-by-Step Solution](#step-by-step-solution)
   - [Q1: OpenWRT Version](#q1-openwrt-version)
   - [Q2: Linux Kernel Version](#q2-linux-kernel-version)
   - [Q3: Root Password Hash](#q3-root-password-hash)
   - [Q4: PPPoE Username](#q4-pppoe-username)
   - [Q5: PPPoE Password](#q5-pppoe-password)
   - [Q6: WiFi SSID](#q6-wifi-ssid)
   - [Q7: WiFi Password](#q7-wifi-password)
   - [Q8: WAN Redirect Ports](#q8-wan-redirect-ports)
6. [Key Takeaways](#key-takeaways)

---

## Overview

We are given a raw firmware dump (`chal_router_dump.bin`) from a **Xiaomi 4A 100M** router running **OpenWRT**. The goal is to extract and analyze the firmware to recover configuration data including credentials, network settings, and firewall rules.

---

## Tools Required

| Tool | Purpose | Install |
|------|---------|---------|
| `binwalk` | Firmware analysis & extraction | `apt install binwalk` |
| `jefferson` | JFFS2 filesystem extractor | `pip install jefferson --break-system-packages` |
| `sasquatch` | SquashFS extractor (extended) | `apt install sasquatch` |
| `strings` | Raw string extraction | Built-in |
| `tar` | Archive extraction | Built-in |

---

## File Structure After Extraction

```
_chal_router_dump.bin.extracted/
├── 18168C              ← LZMA compressed kernel data (raw)
├── 18168C.7z           ← Same, archived
├── 42C2C8.squashfs     ← SquashFS root filesystem (read-only base OS)
├── 70000               ← gzip compressed data
├── 7C0000.jffs2        ← JFFS2 overlay filesystem (user config) ← KEY FILE
└── squashfs-root/      ← Extracted SquashFS (base OS, read-only)
    ├── bin/
    ├── etc/
    │   ├── openwrt_release     ← Q1: OpenWRT version
    │   ├── shadow              ← Wrong hash (read-only default)
    │   └── ...
    ├── lib/
    │   └── modules/
    │       └── 5.15.134/       ← Q2: Kernel version
    └── ...

jffs2-root/             ← Extracted JFFS2 (after running jefferson)
├── upper/
│   └── sysupgrade.tgz          ← Full config backup (easiest path)
│       └── etc/
│           ├── shadow          ← Q3: Real root password hash
│           ├── config/
│           │   ├── network     ← Q4, Q5: PPPoE credentials
│           │   ├── wireless    ← Q6, Q7: WiFi SSID & password
│           │   └── firewall    ← Q8: WAN redirect ports
└── work/
    └── work/
        ├── #3/                 ← Corresponds to /etc/ssl certs + board.json
        │   ├── uhttpd.crt
        │   ├── uhttpd.key
        │   ├── board.json
        │   └── urandom.seed
        └── #4/                 ← Corresponds to /etc/config/
            ├── network         ← Q4, Q5: PPPoE credentials
            ├── wireless        ← Q6, Q7: WiFi SSID & password
            └── system
```

---

## OpenWRT Partition Layout

The firmware ROM is a single continuous data block split into address spaces:

| Partition | Address | Filesystem | Mount | Purpose |
|-----------|---------|------------|-------|---------|
| bootloader | `0x00000` | raw | — | U-Boot |
| kernel | `0x180000` | uImage | — | Linux kernel (MIPS) |
| rootfs | `0x42C2C8` | SquashFS | `/` | Base OS, **read-only** |
| overlay | `0x7C0000` | JFFS2 | `/overlay` | User config, **writable** |

> **Key insight:** SquashFS is read-only and compressed. The JFFS2 overlay is mounted on top via OverlayFS, giving the user a transparent writable filesystem. This means **any user-modified file** (passwords, network config, etc.) lives in JFFS2, not SquashFS.

---

## Step-by-Step Solution

### Initial Extraction

```bash
# Step 1: Run binwalk to identify and extract all partitions
binwalk -Me chal_router_dump.bin
# Creates: _chal_router_dump.bin.extracted/

cd _chal_router_dump.bin.extracted/

# Step 2: Extract the JFFS2 overlay with jefferson
jefferson 7C0000.jffs2 -d jffs2-root
# Creates: jffs2-root/ with upper/ and work/work/ directories
```

---

### Q1: OpenWRT Version

**Answer:** `23.05.0`

**File path:**
```
squashfs-root/etc/openwrt_release
```

**Command:**
```bash
cat squashfs-root/etc/openwrt_release
```

**Output:**
```
DISTRIB_ID='OpenWrt'
DISTRIB_RELEASE='23.05.0'
DISTRIB_REVISION='r23497-6637af95aa'
DISTRIB_TARGET='ramips/mt7621'
DISTRIB_ARCH='mipsel_24kc'
DISTRIB_DESCRIPTION='OpenWrt 23.05.0 r23497-6637af95aa'
```

> Also visible directly in `binwalk` output: `image name: "MIPS OpenWrt Linux-5.15.134"`

---

### Q2: Linux Kernel Version

**Answer:** `5.15.134`

**File path:**
```
squashfs-root/lib/modules/5.15.134/
```

**Command:**
```bash
ls squashfs-root/lib/modules/
```

> `/proc/version` is empty in squashfs-root (it's a static dump, not a live system). The kernel modules directory is named after the kernel version, making it a reliable source.

> Also readable directly from `binwalk` output: `uImage ... image name: "MIPS OpenWrt Linux-5.15.134"`

---

### Q3: Root Password Hash

**Answer:** `root:$1$YfuRJudo$cXCiIJXn9fWLIt8WY2Okp1:19804:0:99999:7:::`

**Why not squashfs?**  
`squashfs-root/etc/shadow` contains the factory-default hash, which is **wrong** because SquashFS is read-only. The actual modified hash is in the JFFS2 overlay.

**File path (easiest method via sysupgrade backup):**
```
jffs2-root/upper/sysupgrade.tgz → etc/shadow
```

**Commands:**
```bash
cd jffs2-root/upper/
tar -xzf sysupgrade.tgz
cat etc/shadow | grep "root:"
```

**Alternative (raw search across numbered overlay files):**
```bash
strings -a jffs2-root/work/work/#* | grep "root:"
```

---

### Q4: PPPoE Username

**Answer:** `yohZ5ah`

**File path:**
```
jffs2-root/work/work/#4/network
```

**Command:**
```bash
cat jffs2-root/work/work/#4/network | grep "username"
```

**Relevant config block:**
```
config interface 'wan'
    option device 'wan'
    option proto 'pppoe'
    option username 'yohZ5ah'
    option password 'ae-h+i$i^Ngohroorie!bieng6kee7oh'
    option ipv6 'auto'
```

---

### Q5: PPPoE Password

**Answer:** `ae-h+i$i^Ngohroorie!bieng6kee7oh`

**File path:** Same as Q4
```
jffs2-root/work/work/#4/network
```

**Command:**
```bash
cat jffs2-root/work/work/#4/network | grep "password"
```

---

### Q6: WiFi SSID

**Answer:** `VLT-AP01`

**File path:**
```
jffs2-root/work/work/#4/wireless
```

**Command:**
```bash
cat jffs2-root/work/work/#4/wireless | grep "ssid"
```

**Relevant config block:**
```
config wifi-iface 'default_radio0'
    option device 'radio0'
    option network 'lan'
    option mode 'ap'
    option ssid 'VLT-AP01'
    option encryption 'sae-mixed'
    option key 'french-halves-vehicular-favorable'
```

> The same SSID and password are used for both `radio0` (2.4GHz) and `radio1` (5GHz).

---

### Q7: WiFi Password

**Answer:** `french-halves-vehicular-favorable`

**File path:** Same as Q6
```
jffs2-root/work/work/#4/wireless
```

**Command:**
```bash
cat jffs2-root/work/work/#4/wireless | grep "key"
```

---

### Q8: WAN Redirect Ports

**Answer:** `1778,2289,8088`

**File path:**
```
jffs2-root/upper/sysupgrade.tgz → etc/config/firewall
```

> There is **no `firewall` file under `#4`**. The firewall config is stored in a different numbered file. The easiest method is extracting `sysupgrade.tgz`.

**Commands:**
```bash
cd jffs2-root/upper/
tar -xzf sysupgrade.tgz
cat etc/config/firewall | grep -A5 "redirect"
```

**Firewall redirect rules found:**
```
config redirect
    option dest 'lan'
    option target 'DNAT'
    option name 'DB'
    option src 'wan'
    option src_dport '1778'        ← Port 1 → 192.168.1.184:5881
    option dest_ip '192.168.1.184'
    option dest_port '5881'

config redirect
    option dest 'lan'
    option target 'DNAT'
    option name 'WEB'
    option src 'wan'
    option src_dport '2289'        ← Port 2 → 192.168.1.119:9889
    option dest_ip '192.168.1.119'
    option dest_port '9889'

config redirect
    option dest 'lan'
    option target 'DNAT'
    option name 'NAS'
    option src 'wan'
    option src_dport '8088'        ← Port 3 → 192.168.1.166:4431
    option dest_ip '192.168.1.166'
    option dest_port '4431'
```

---

## Key Takeaways

| Concept | Detail |
|---------|--------|
| **SquashFS = read-only** | Factory defaults only; password changes never live here |
| **JFFS2 = writable overlay** | All user config, credentials, and customizations |
| **`sysupgrade.tgz`** | Auto-created backup on firmware upgrade; contains full named config tree — the easiest way to read the overlay |
| **`work/work/#N/`** | JFFS2 overlay directories mapped to `/etc` paths; `#4` = `/etc/config/`, `#3` = `/etc/ssl/` etc. |
| **Backdoor vector** | Modifying the JFFS2 hash + enabling SSH/telnet in firewall rules = router backdoor without JTAG |
| **binwalk tip** | The uImage header directly reveals kernel version and OS in the `image name` field |
