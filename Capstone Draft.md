# SOC Automation: Splunk + n8n + DeepSeek + Telegram

An automated SOC workflow that collects logs from Windows, Linux, and network sources, detects suspicious activity in Splunk, enriches and analyzes each alert with AI, and delivers analyst-ready notifications to Telegram. A human-approved response step (IP block) closes the loop.

---

## Technologies Used

| Technology | Role in the project |
|---|---|
| **Splunk Enterprise** | SIEM: log ingestion, indexing, detection rules (SPL), and alerting |
| **Splunk Universal Forwarder** | Lightweight agent that ships logs from endpoints and sensors to Splunk (TCP 9997) |
| **Splunk Add-on for Microsoft Windows** | Parses and normalizes Windows Security Event Logs (e.g. Event ID 4625) |
| **n8n** (self-hosted) | Orchestration engine: receives the Splunk webhook, runs enrichment, calls the AI, and sends notifications |
| **Windows 10** | Monitored endpoint and source of Windows Security Events |
| **Linux** | Monitored host; auth logs and syslog (e.g. failed SSH logins) |
| **Python** | Custom logic: log/field normalization and the enforcement API that validates and applies blocks |
| **DeepSeek** | LLM acting as a Tier 1 SOC analyst: summary, MITRE ATT&CK mapping, severity, recommended actions |
| **Docker** | Container runtime for n8n (Docker Compose) and the Python enforcement API |
| **Telegram** | Notification channel and approve/reject interface for response actions |
| **VirusTotal** | Enriches hashes/IPs for malicious scoring |
| **OPNsense** | Has a REST API that n8n can call with the HTTP Request node |

---

## Architecture / Data Flow

```
Windows 10, Linux, Network Traffic → Universal Forwarder → Splunk → webhook → n8n → Deepseek (Build Skill in Model) → Create case for deep investigation (Why/How) → Telegram Group (History attack / Lesson Learned) #Noted: all in one using AI.
                                                                                      |                                                                            └─> Determine via DeepSeek Model → Calls Python Block API → ufw/OPNsense block → Send status to Telegram with description
                                                                                      └─> VirusTotal (Checking the IP on the DB) → If matching IP in the DB or range of IPs → Calls Python Block API → ufw/OPNsense block (auto-expires) → Send status to Telegram with description
                                                                                                                              └─> If not matching IP → Human In the Loop in the Telegram (Approve Block / Manual Investigate) → If block → Calls Python Block API → ufw/OPNsense block
                                                                                                                                                                                                                            └─> If not → Telegram Description
```

1. **Collect:** Universal Forwarders send Windows, Linux, and network-sensor logs to Splunk.
2. **Detect:** Splunk searches and scheduled alerts flag suspicious activity (e.g. brute force).
3. **Trigger:** The alert fires a webhook (HTTP POST) to n8n.
4. **Enrich:** n8n queries AbuseIPDB and can run follow-up Splunk searches for context.
5. **Analyze:** DeepSeek summarizes the alert, maps it to MITRE ATT&CK, rates severity, and recommends actions.
6. **Notify:** The result is sent to Telegram for the analyst.

---

## Project Scope

### Objective

Reduce manual log review and speed up incident response by automating detection, enrichment, analysis, and notification, using self-hosted and open-source tooling wherever possible.

### In Scope

- **Log collection** from Windows 10, Linux, and network traffic (via sensor logs) using the Universal Forwarder
- **Detection** in Splunk, starting with brute force (Windows Event ID 4625, Linux failed SSH logins), with thresholds and an IP allowlist
- **Webhook integration** between Splunk and a self-hosted n8n instance (Docker)
- **Alert enrichment** with AbuseIPDB and optional Splunk pivot searches
- **AI-assisted triage** with DeepSeek: summary, severity, MITRE ATT&CK mapping, recommended actions
- **Telegram notifications** with concise, structured alerts
- **Response (block) workflow**, following these principles:
  - AI recommends, code enforces, a human approves
  - Strict JSON output from the AI, validated before any action
  - Allowlist for gateways, admin IPs, and infrastructure
  - Every block has a TTL and auto-expires
  - Dry-run mode before enabling real blocking
  - Every action is logged back to Splunk for audit

### Out of Scope

- Fully autonomous blocking without human approval
- Commercial SOAR or paid Splunk Enterprise Security features
- Production-scale deployment, high availability, and multi-tenant use
- Advanced malware analysis and full digital forensics
- Detection use cases beyond the initial set (e.g. lateral movement, data exfiltration) in the first phase

### Deliverables

- Working end-to-end pipeline from log source to Telegram alert
- Splunk detection searches and alert configuration
- n8n workflow (webhook, enrichment, AI analysis, Telegram)
- Python enforcement API with validation, allowlist, and TTL
- Documentation and demo of a simulated attack (e.g. Hydra from a Kali machine) through detection, alert, approval, and block

### Success Criteria

- A simulated brute force attack triggers an alert in Splunk within minutes
- n8n delivers an AI-analyzed alert to Telegram with no manual steps
- An approved block is applied, logged to Splunk, and expires automatically
- Allowlisted IPs are never blocked

---

## Security Considerations

- Keep the n8n webhook on private network addresses and require a shared secret header
- Use least-privilege service accounts for Splunk REST/HEC and for the enforcement API
- Treat log content as untrusted input to the LLM (prompt injection risk) and validate all AI output in code
- Consider masking sensitive fields, or using a local model, before sending logs to a third-party API
- Watch Splunk license limits and filter noisy events at the forwarder
