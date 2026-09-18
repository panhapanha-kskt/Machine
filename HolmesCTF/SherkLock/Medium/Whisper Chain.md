# Whisper Chain — Sherlock Answers

## Question 1: TLS Certificate SANs

List all Subject Alternative Names present in the server's TLS certificate.
Primary hostname first, remaining SANs in alphabetical order.

**Source:** `nmap -sV -sC` scan output, `ssl-cert` script result on port 5281.

```
Subject Alternative Name: DNS:murknet.htb, DNS:groups.murknet.htb, DNS:command.murknet.htb, DNS:upload.murknet.htb
```

**Answer:**
```
murknet.htb,command.murknet.htb,groups.murknet.htb,upload.murknet.htb
```

---

## Question 2: Public XMPP Channels

List the names of all public channels available on the XMPP server, sorted
alphabetically.

**Source:** `murknet_recon.py` — disco#items query against `groups.murknet.htb`.

```
('random@groups.murknet.htb', None, 'Random')
('rules@groups.murknet.htb', None, 'Rules')
('infra@groups.murknet.htb', None, 'Infrastructure')
('resources@groups.murknet.htb', None, 'Resources')
```

**Answer:**
```
Infrastructure,Random,Resources,Rules
```
