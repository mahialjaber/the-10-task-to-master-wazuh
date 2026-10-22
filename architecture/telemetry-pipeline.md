# 🔄 End-to-End Telemetry Ingestion & Analysis Pipeline

Understanding Wazuh at a senior SOC level requires understanding how data moves from a raw kernel system call or network packet to a searchable OpenSearch JSON document.

---

## 1. The Wazuh Core Daemon Architecture

The Wazuh Manager is not a monolithic application; it is an orchestrated pipeline of high-performance C daemons:

```
[Endpoint Event: Sysmon / Auditd / Suricata]
                     │
                     ▼ (Encrypted AES/Blowfish TCP Port 1514)
              [wazuh-remoted]
                     │
                     ▼ (UNIX Domain Socket: /var/ossec/queue/sockets/queue)
             [wazuh-analysisd]
               ├── Phase 1: Pre-decoding (timestamp, hostname, program)
               ├── Phase 2: Decoding (regex field extraction -> JSON)
               ├── Phase 3: Rule Matching & MITRE Mapping
               │        └── local_rules.xml / ruleset/*.xml
               ▼
   ┌─────────────────┴─────────────────┐
   ▼                                   ▼
[Alert Triggered (Level >= 3)]    [Alert Level >= 12 (VT Group)]
   │                                   │
   ▼                                   ▼
[File: alerts.json]             [wazuh-integratord]
   │                                   │ (HTTPS REST API)
   ▼                                   ▼
[Filebeat / Indexer API]        [VirusTotal Threat Cloud]
   │                                   │
   ▼                                   ▼ (Enriched Alert Generated)
[OpenSearch Index: wazuh-alerts-*] ───┘
```

---

## 2. Granular Daemon Responsibilities

| Daemon | Binary Path | Primary Function in this Lab |
| :--- | :--- | :--- |
| **`wazuh-remoted`** | `/var/ossec/bin/wazuh-remoted` | Listens on port `1514/TCP`, decrypts agent traffic from Windows 11 (`001`) and Rocky Linux (`002`), and pushes raw strings into the internal queue. |
| **`wazuh-analysisd`** | `/var/ossec/bin/wazuh-analysisd` | The brain of the SIEM. Executes the 3-phase analysis engine: pre-decoding, dynamic regex decoding, and hierarchical rule evaluation (`local_rules.xml`). |
| **`wazuh-execd`** | `/var/ossec/bin/wazuh-execd` | Executes Active Response scripts (e.g. `firewall-drop`) when `wazuh-analysisd` triggers an alert matching configured rule IDs. |
| **`wazuh-integratord`** | `/var/ossec/bin/wazuh-integratord` | Asynchronously monitors `alerts.json` for FIM events. Extracts file hashes (MD5/SHA1/SHA256) and submits them via HTTPS to VirusTotal. |
| **`wazuh-modulesd`** | `/var/ossec/bin/wazuh-modulesd` | Manages external polling modules, specifically the `aws-s3` wodle pulling CloudTrail JSON bundles from bucket `for-wazuh1`. |

---

## 3. The 3-Phase Log Processing Engine (`wazuh-logtest`)

Whenever a log enters `wazuh-analysisd`, it passes through three sequential phases. In **Task 3**, this was verified live using `wazuh-logtest`:

### Phase 1: Pre-Decoding
Extracts the static header fields present in standard RFC syslog or Windows Event headers:
- `timestamp`: Event creation time.
- `hostname`: Originating endpoint name (`windows-vm-01` or `rhel-endpoint-01`).
- `program_name`: Executable or service logging the event (e.g., `powershell.exe`, `sshd-session`).

### Phase 2: Decoding
Parses the variable payload using XML regex decoders:
- Dynamic key-value pairs are extracted into normalized fields (e.g., `src_ip`, `dst_port`, `parentProcessName`, `newProcessName`).
- If no custom decoder matches, the raw event is passed through to full-text regex filtering.

### Phase 3: Filtering & Rule Matching
Evaluates the hierarchical rule tree:
1. Root rules check baseline criteria (`<if_group>syslog</if_group>` or `<if_sid>86601</if_sid>`).
2. Child rules evaluate precision regex (`<regex type="pcre2">`), strings, and thresholds (`frequency="10"`).
3. If criteria match:
   - Rule ID and Severity Level are assigned.
   - MITRE ATT&CK tactic and technique IDs are mapped.
   - If `level="0"` (as authored in **Task 10**), the alert is suppressed, eliminating alert fatigue.

---

## 4. Active Response Dynamic Flow

```
[Kali Linux NetExec SSH Brute Force]
                 │
                 ▼
[Rocky Linux /var/log/secure -> wazuh-agent]
                 │
                 ▼ (TCP 1514)
[Wazuh Manager: wazuh-analysisd]
   ├── Matches Rule 5712 / 100011 (Brute-force detected)
   └── Matches <active-response> in ossec.conf:
                 │
                 ▼
[wazuh-remoted sends AR command to Agent 002]
                 │
                 ▼
[Rocky Linux wazuh-execd executes: active-response/bin/firewall-drop]
   ├── Invokes /usr/sbin/iptables-nft or firewalld
   └── Dynamic Rule Injected: -s 192.168.198.128 -j DROP (1200s timeout)
                 │
                 ▼
[Kali connection immediately severed with banner read timeout!]
```
