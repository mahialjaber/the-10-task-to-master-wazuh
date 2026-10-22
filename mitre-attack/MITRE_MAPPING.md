# 🗺️ MITRE ATT&CK Enterprise Matrix Mapping

This matrix maps every challenge in the **10-Task Wazuh Gauntlet** to its corresponding **MITRE ATT&CK Enterprise (v15)** tactic, technique, and detection signature.

---

## 📊 Comprehensive Coverage Matrix

| Task # | Challenge Domain | MITRE Tactic | Technique Name | MITRE ID | Detection Mechanism / Wazuh Rule |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **01** | Cloud SIEM Audit | Persistence / PrivEsc | Create Account: Cloud Account | **T1136.003** | CloudTrail S3 Wodle $\rightarrow$ Rule `80202` (CreateUser) |
| **01** | Cloud SIEM Audit | Defense Evasion | Valid Accounts: Cloud Accounts | **T1078.004** | CloudTrail S3 Wodle $\rightarrow$ Rule `80202` (Root ARN) |
| **02** | Real-Time FIM | Impact | Stored Data Manipulation | **T1565.001** | Inotify Differential FIM $\rightarrow$ Rule `550` (`/usr/bin/tty`) |
| **03** | Detection Engineering | Discovery | System Owner/User Discovery | **T1033** | Custom Rule `100025` (PCRE2 `whoami /priv`) |
| **03** | Detection Engineering | Credential Access | OS Credential Dumping: /etc/passwd and /etc/shadow | **T1003.008** | Custom Rule `100025` (PCRE2 `cat /etc/shadow`) |
| **04** | Threat Intelligence | Execution | Exploitation for Client Execution | **T1203** | `wazuh-integratord` VirusTotal API $\rightarrow$ Rule `87105` |
| **05** | Active Defense | Credential Access | Brute Force: Password Guessing | **T1110.001** | Syslog `/var/log/secure` $\rightarrow$ Rules `5712`, `100011` |
| **05** | Active Defense | Containment / Defense | Dynamic Firewall Dropping | — | Active Response `firewall-drop` script execution |
| **06** | SOC Threat Hunting | Credential Access | Brute Force: Credential Spraying | **T1110.003** | DQL Query Filtering PAM Failures & SSH Brute Force |
| **07** | Windows Lineage | Execution | Command and Scripting Interpreter: Windows Command Shell | **T1059.003** | Event ID 4688 $\rightarrow$ Rule `67027` (Command lines) |
| **07** | Windows Lineage | Defense Evasion | Masquerading: Match Legitimate Name or Location | **T1036.005** | Baseline Lineage Modeling (`services.exe` $\rightarrow$ `svchost.exe`) & Hunter Criteria |
| **08** | NIDS Correlation | Discovery | Network Service Discovery | **T1046** | Suricata `eve.json` Nmap Signature $\rightarrow$ Rule `86601` |
| **09** | Vulnerability Hunting | Initial Access | Exploit Public-Facing Application | **T1190** | OpenSearch Dev Tools REST API (`CVE-2026-72130` & `CVE-2025-41244`) |
| **10** | False Positive Tuning | Defense Evasion | Indicator Removal: Rule Noise Suppression | — | Custom Rule `100060` (Child `level="0"` silencing) |

---

## 🛡️ Custom Ruleset MITRE Mapping (`detections/local_rules.xml`)

| Custom Rule ID | Level | Tactic | Technique Name | MITRE ID |
| :---: | :---: | :--- | :--- | :---: |
| **`100001`** | **14** | Execution | Command and Scripting Interpreter: Unix Shell | **T1059.004** |
| **`100010`** | **14** | Credential Access / Initial Access | Brute Force / Valid Accounts | **T1110** / **T1078** |
| **`100011`** | **14** | Credential Access / Initial Access | Brute Force / Valid Accounts | **T1110** / **T1078** |
| **`100012`** | **13** | Privilege Escalation / Lateral Movement | Sysinternals PsExec Service Installation | **T1543.003** / **T1021.002** |
| **`100013`** | **14** | Privilege Escalation / Lateral Movement | Impacket Randomized Service Installation | **T1543.003** / **T1021.002** |
| **`100025`** | **10** | Discovery / Credential Access | System Owner/User Discovery & /etc/shadow | **T1033** / **T1003.008** |
| **`100060`** | **0** | Discovery (Benign Tuning) | Network Service Discovery (Suppressed) | **T1046** |
