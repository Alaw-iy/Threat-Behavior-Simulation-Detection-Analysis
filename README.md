# Threat Behavior Simulation & Detection Analysis

## 1. Project Overview
This project documents a controlled, non-malicious behavior simulation conducted within an isolated Windows 11 enterprise laboratory. The primary objective is to demonstrate a Blue Team investigative mindset by capturing endpoint telemetry, mapping actions to the MITRE ATT&CK framework, and engineering actionable detection logic (Sigma, YARA, Splunk, KQL).

> **⚠️ Operational Security Note:** This repository does not contain malicious payloads, anti-virus bypasses, or destructive code. All simulation steps utilize benign system utilities and mock administrative configurations to safely generate realistic system activity for educational and defensive triage analysis.

---

## 2. Executive Summary

This project documents a controlled Windows threat behavior simulation built to validate endpoint detection and analysis workflows.

The lab generated telemetry through PowerShell execution, file creation, registry modification, and local network activity.

Sysmon was used to collect Windows event data, which was then reviewed through Sigma detection logic, IOC documentation, and incident reporting.

The objective was to demonstrate practical Blue Team skills in telemetry analysis, detection engineering, and incident documentation.

### Telemetry & Framework Mapping Matrix
| Observed Behavior | MITRE ATT&CK Mapping | Log Source | Severity | Target Object / Context |
| :--- | :--- | :--- | :--- | :--- |
| Binary execution from untrusted path | **T1059** - Command & Scripting Interpreter | Sysmon Event ID 1 | **Medium** | `simulated_payload.exe` |
| Dropping configuration files to disk | **T1105** - Ingress Tool Transfer | Sysmon Event ID 11 | **Medium** | `simulated_config.txt` |
| Registry manipulation for persistence | **T1547.001** - Registry Run Keys | Sysmon Event ID 13 | **Medium** | `SimulationTestCompany` |
| Outbound local socket beaconing | **T1071** - Application Layer Protocol | Sysmon Event ID 3 | **Medium** | Port `135` over `127.0.0.1` |

## Architecture Overview

The lab follows a simple endpoint detection workflow:

1. A controlled behavior simulation runs on a Windows 11 lab machine.
2. Sysmon captures process, network, file and registry events.
3. The collected telemetry is reviewed through detection artifacts.
4. Sigma, KQL, Splunk and YARA logic support the analysis.
5. Findings are documented through an incident timeline, IOC list and technical report.

Architecture diagram:

[View architecture diagram](docs/architecture/architecture-diagram.md)

---

## 3. Lab Environment & Architecture
To ensure complete isolation from production infrastructure, the detection engineering workflow was built using the following stack:

| Component | Purpose / Tooling Details |
| :--- | :--- |
| **Operating System** | Windows 11 Enterprise (Isolated VM Sandbox Instance) |
| **Telemetry Agent** | Microsoft Sysmon (System Monitor) with Modular Configuration |
| **Log Management** | Windows Event Viewer (Auditing Subsystem) |
| **Execution Engine** | PowerShell Core (Administrative Console Context) |

![Lab Environment](screenshots/01-lab-environment.png)
*Figure 1: Isolated Windows 11 security monitoring workspace setup with exclusions configured.*

---

## 4. Behavioral Simulation Breakdown

### 4.1 Process Execution (Event ID 1)
A replica payload binary (`simulated_payload.exe`) was staged and executed via an interactive command-line environment to baseline process creation auditing.
* **Monitored Fields:** `Image`, `CommandLine`, `ParentImage`, `Hashes` (SHA256).

![Process Creation Telemetry](screenshots/02-sysmon-event-id-1-process-creation.png)
*Figure 2: Sysmon capturing process creation details and cryptographic hashes for the executing binary.*

### 4.2 File Creation (Event ID 11)
The process triggered the generation of a static configuration observed system behavior (`simulated_config.txt`) inside the dedicated laboratory working directory.
* **Monitored Fields:** `TargetFilename`, `CreationUtcTime`, `Image`.

![File Creation Telemetry](screenshots/03-sysmon-event-id-11-file-created.png)
*Figure 3: Telemetry log confirming local disk modification and file staging patterns.*

### 4.3 Registry Modification (Event ID 13)
To simulate host persistence without making intrusive system changes, an administrative key value was written to a dedicated non-destructive registry path.
* **Monitored Fields:** `TargetObject`, `Details`, `EventType` (CreateKey / SetValue).

![Registry Modification Telemetry](screenshots/04-sysmon-event-id-13-registry-change.png)
*Figure 4: Event ID 13 logging administrative registry modification matching persistence tactics.*

### 4.4 Network Connection (Event ID 3)
An active loopback socket request was initiated to simulate egress command-and-control beaconing traffic over common administration ports.
* **Monitored Fields:** `SourceIp`, `DestinationIp`, `DestinationPort`, `Protocol`.

![Network Connection Telemetry](screenshots/05-sysmon-event-id-3-network-connection.png)
*Figure 5: Network socket telemetry confirming outbound traffic monitoring capability.*

---

## 5. Indicators of Compromise (IoCs)
The following verified attributes were extracted during telemetry collection to assist in defensive signature matching:

### Host Indicators
* **File Name:** `simulated_payload.exe`
* **Staging Path:** `C:\Lab-Defensivo\simulated_payload.exe`
* **SHA256 Hash:** `SHA256: intentionally omitted for controlled simulation artifact consistency`
* **Registry Key:** `HKLM\SOFTWARE\SimulationTestCompany\SimulatedRunKey`

### Network Indicators
* **Destination IP:** `127.0.0.1` (Localhost Loopback validation)
* **Destination Port:** `135 / TCP`

![IoC Hash Verification](screenshots/06-sigma-rule-detection.png)
*Figure 6: Cryptographic SHA256 validation of the laboratory executable file.*

---

## 6. Detection Engineering Artifacts

### 🟢 Sigma Detection Rules
This project includes two Sigma rules. The first rule detects the main lab behavior across Sysmon Event IDs 1, 3, 11 and 13. The second rule focuses on PowerShell-based TCP client activity observed during the network simulation step.
Located at: `detection/sigma/windows-threat-behavior-detection.yml &
detection/sigma/powershell-tcpclient-connection.yml`
```yaml
title: Suspicious Simulation Registry and Process Behavioral Pattern
id: c4e28a90-1234-abcd-ef01-987654321abc
status: experimental
description: Detects registry creation/modification parameters linked to the controlled threat behavior simulation.
author: Alan Nunes Moreira
date: 2026/05/26
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains: 'SimulationTestCompany'
        Details|endswith: 'simulated_payload.exe'
    condition: selection
falsepositives:
    - Controlled sandbox engineering exercises.
level: medium
