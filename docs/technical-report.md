# Comprehensive Technical Analysis Report

## 1. Incident Context & Investigation Scope
This technical report details the behavioral auditing of a controlled security simulation executed within an isolated Windows 11 Enterprise sandbox environment. The primary objective of this investigation is to validate endpoint telemetry coverage (Microsoft Sysmon) against common post-exploitation tactics and map the resulting footprints to enterprise detection engineering standards.

The scope of this analysis covers the lifecycle of the execution, from initial process creation to persistence staging and outbound loopback network traffic analysis.

---

## 2. In-Depth Behavioral Breakdown

### Stage 1: Process Ingestion & Execution
* **Behavior:** The operator executed a replica binary named `simulated_payload.exe` (staged inside the `C:\Lab-Defensivo\` directory) via an active PowerShell administrative session.
* **Telemetry Correlation:** Sysmon successfully caught this activity via **Event ID 1 (Process Creation)**.
* **Threat Hunter Notes:** Executing binaries from non-standard administrative paths or shared/public directories (such as `\Public\`, `\Temp\`, or custom folders directly under `C:\`) is a high-confidence indicator of human-operated ransomware staging or automated script delivery. Standard corporate software rarely deploys or executes from these paths.

### Stage 2: Staging / Artifact Drops
* **Behavior:** The primary process instantiated a file-write drop operation, creating a text-based asset called `simulated_config.txt`.
* **Telemetry Correlation:** Checked and validated inside Sysmon via **Event ID 11 (FileCreate)**.
* **Threat Hunter Notes:** Rogue applications frequently utilize configuration dumps or download secondary stages into localized folders to bypass default application control mechanisms. Tracking the creating process lineage (`Image` file context) is key to identifying the entry vector.

### Stage 3: Registry Modification & Persistence Modeling
* **Behavior:** The session updated the Windows registry infrastructure, writing a string value pointer inside a simulation hive space.
* **Telemetry Correlation:** Captured with high fidelity by Sysmon **Event ID 13 (RegistryEvent - Value Set)**.
* **Threat Hunter Notes:** Attackers leverage automated registry entry points (such as the traditional `CurrentVersion\Run` or `RunOnce` keys) to maintain access over host reboots. Monitoring modifications to these hives allows detection engineers to stop a threat before it gains structural persistence.

### Stage 4: Outbound Traffic & Network Beaconing
* **Behavior:** The script generated a loopback network socket request targeting port `135` over `127.0.0.1`.
* **Telemetry Correlation:** Intercepted and recorded by Sysmon **Event ID 3 (Network Connection)**.
* **Threat Hunter Notes:** Legitimate business tools like browsers or communication apps frequently talk to the internet, but native utilities (like the Bloco de Notas copy used here) starting outbound network calls is highly unusual. This behavior strongly suggests Command and Control (C2) beaconing or data exfiltration.

---

## 3. Playbook Action Plan: Incident Response Workflow

When an alert fires matching this exact behavioral signature in production, SOC analysts must follow this structured response playbook:

| Phase | Action Item | Telemetry Evidence Required | Expected Defensive Outcome |
| :--- | :--- | :--- | :--- |
| **1. Triage** | Verify alert legitimacy inside the SIEM console. Filter out expected administrative maintenance jobs. | Check parent-child hierarchy in Sysmon Event ID 1. | Confirm event validity and eliminate false positives. |
| **2. Isolation** | Isolate the compromised endpoint from the wider network segment via EDR or firewall rules. | Hostname, MAC address, and active DHCP IP block. | Lateral movement vectors are immediately severed. |
| **3. Investigation**| Map out the full process tree and look for indicators of data staging or credential dumping. | Correlate Event IDs 11, 13, and 3 under the same `ProcessGuid`. | The complete scope of the intrusion is uncovered. |
| **4. Eradication** | Terminate all malicious PIDs and purge dropped artifacts from the system. | Process paths, hashes, and specific registry strings. | Threat factors are fully removed from the host. |

### Containment PowerShell Commands for Administrators:
```powershell
# 1. Kill the rogue active process instance
Stop-Process -Name "simulated_payload" -Force

# 2. Remediate disk modifications
Remove-Item -Path "C:\Lab-Defensivo\simulated_config.txt" -Force

# 3. Purge the persistence hook from the Registry hive
Remove-ItemProperty -Path "HKLM:\SOFTWARE\SimulationTestCompany" -Name "SimulatedRunKey" -Force
