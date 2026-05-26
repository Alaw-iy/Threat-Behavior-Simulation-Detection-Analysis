```markdown
# Incident Timeline Ledger

This document tracking table maps out the chronological sequence of events generated during the defensive laboratory simulation exercise. Timestamps are aligned with the Sysmon telemetry logs collected during triage.

| Timestamp (UTC) | Telemetry Event Action | Source Log Channel / ID | Forensic Significance & Investigative Notes | Risk Severity |
| :--- | :--- | :--- | :--- | :--- |
| **11:35:10** | `simulated_payload.exe` execution | Sysmon Event ID 1 | Initial execution phase. Process spawned from administrative context (`powershell.exe`). Hashes extracted. | **Medium** |
| **11:35:22** | File Drop: `simulated_config.txt` | Sysmon Event ID 11 | Data staging marker. The process successfully dropped a configuration file into a custom directory path. | **Medium** |
| **11:35:44** | Registry Value Created | Sysmon Event ID 13 | Mock persistence hook executed. Target key `SimulationTestCompany` created to model automated startup behavior. | **High** |
| **11:59:56** | Network Socket Instantiated | Sysmon Event ID 3 | Active connection established over Loopback (`127.0.0.1`) targeting RPC administration port `135`. | **High** |
| **12:05:00** | Analyst Containment Triage | Incident Playbook Action | Mitigation tasks started. Rogue processes killed, persistence registry keys deleted, and files scrubbed from disk. | **Info** |
