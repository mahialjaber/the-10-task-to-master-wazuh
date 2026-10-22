# 🛡️ Detection Engineering Suite (`detections/`)

This directory houses the custom detection rules, suppression logic, and MITRE ATT&CK mappings authored during the 10-Task Gauntlet.

---

## 📋 Rule Catalog Summary

| Rule ID | Level | Classification | Trigger / Logic Summary | MITRE ATT&CK |
| :---: | :---: | :--- | :--- | :--- |
| **`100025`** | **10** | High Reconnaissance | PCRE2 regex matching `whoami /priv` or `cat /etc/shadow` across Windows and Linux. | **T1033**, **T1003.008** |
| **`100060`** | **0** | False Positive Tuning | Silences Suricata ping signature `9000001` exclusively when originating from authorized Kali IPv6. | **T1046** |
| **`100010`** | **14** | Critical Breach | Correlates Windows logon success following multiple auth failures from same IP (`if_sid: 60106` + `if_matched_sid: 18153`). | **T1110**, **T1078** |
| **`100011`** | **14** | Critical Breach | Correlates SSH authentication success following brute-force failures from same IP (`if_sid: 5715` + `if_matched_sid: 5720`). | **T1110**, **T1078** |
| **`100012`** | **13** | Lateral Movement | Detects Sysinternals PsExec service installation (`Event ID 7045` + `serviceName: PSEXESVC`). | **T1543.003**, **T1021.002** |
| **`100013`** | **14** | Lateral Movement | Detects Impacket PsExec randomized service installation (`Event ID 7045` + `%SystemRoot%\*.exe`). | **T1543.003**, **T1021.002** |
| **`100001`** | **14** | Critical C2 | Regex matching interactive bash / netcat reverse shell syntax over network sockets. | **T1059.004** |
| **`5720`** | **10** | Overwrite Tuning | Lowers SSH brute-force threshold to exactly 10 failed attempts within 120s from the same IP. | **T1110** |
| **`5712`** | **10** | Overwrite Tuning | Lowers invalid user SSH brute-force threshold to exactly 10 attempts within 120s from the same IP. | **T1110** |

---

## ⚙️ Testing Custom Rules with `wazuh-logtest`

To validate custom detection rules without restarting the production manager daemon, execute `/var/ossec/bin/wazuh-logtest`:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

### Test Case 1: Testing Windows Privilege Reconnaissance
* **Input String:** `powershell.exe: whoami /priv`
* **Expected Output:**
  ```text
  **Phase 1: Completed pre-decoding.
  **Phase 2: Completed decoding.
  **Phase 3: Completed filtering (rules).
      id: '100025'
      level: '10'
      description: 'Suspicious command execution: whoami /priv (Windows) or cat /etc/shadow (Linux)'
  **Alert to be generated.
  ```

### Test Case 2: Testing Linux Credential Access
* **Input String:** `bash: cat /etc/shadow`
* **Expected Output:** Triggers Rule `100025` with MITRE `T1003.008`.

---

## 🚀 Deployment Instructions

1. Append or replace the rules into `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager.
2. Validate syntax:
   ```bash
   sudo /var/ossec/bin/wazuh-analysisd -t
   ```
3. Restart the Wazuh Manager service:
   ```bash
   sudo systemctl restart wazuh-manager
   ```
