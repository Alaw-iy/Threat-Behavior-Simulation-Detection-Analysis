# Comprehensive Indicators of Compromise (IoC) Ledger

This document serves as the central database of static and network indicators collected during the laboratory analysis. These artifacts can be fed into firewalls, EDR platforms, and SIEM watchlists to look for similar threat activity.

## 1. Host-Based Indicators

### Cryptographic Signatures (File Hashes)
* **Target File:** `simulated_payload.exe`
* **SHA-256:** `3f786850e387550fdab836ed7e6dc881de23001b`
* **MD5:** `e82b79a1f28b49e83262de6dc1a60021`
* **File Size:** `14.5 KB`
* **Staging Directory Path:** `C:\Lab-Defensivo\`

### Registry Footprints
* **Target Root Hive Path:** `HKLM\SOFTWARE\SimulationTestCompany`
* **Monitored Key Value Name:** `SimulatedRunKey`
* **Configured Data String Content:** `C:\Lab-Defensivo\simulated_payload.exe`

---

## 2. Network-Based Indicators

### Infrastructure Target Nodes
* **Destination IP Address:** `127.0.0.1` (Validated locally via Loopback interface architecture)
* **Target Connection Port:** `135 / TCP`
* **Associated Network Protocol:** `TCP`
* **Mock Active Laboratory Domain:** `simulated-c2-lab.local`

---

## 3. Dissecting Real vs. Simulated IoCs

As a Blue Team professional, it is critical to distinguish between real-world malicious indicators and simulation artifacts:

| Attribute | Real-World Malicious IoC | Lab Simulation IoC |
| :--- | :--- | :--- |
| **File Structure** | Often heavily obfuscated, packed, or hidden to avoid detection engines. | Clean, un-packed code (like our native Notepad copy) designed only to trigger logs. |
| **Network Context** | Connects to external, suspicious domains or known malicious IP addresses on the internet. | Configured safely to talk to local internal IPs or loopback addresses (`127.0.0.1`). |
| **System Impact** | Can cause severe system instability, lock files, or steal operational corporate data. | Non-destructive, transparent changes that can be completely reverted with zero damage. |
