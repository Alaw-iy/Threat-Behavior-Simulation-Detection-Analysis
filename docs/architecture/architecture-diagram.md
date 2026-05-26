# Architecture Diagram

```mermaid
flowchart LR

A[Windows 11 Lab Machine] --> B[Simulated Threat Behavior]

B --> C[Process Execution<br>Sysmon Event ID 1]
B --> D[Network Connection<br>Sysmon Event ID 3]
B --> E[File Creation<br>Sysmon Event ID 11]
B --> F[Registry Modification<br>Sysmon Event ID 13]

C --> G[Windows Event Logs]
D --> G
E --> G
F --> G

G --> H[Sysmon Telemetry Collection]

H --> I[Sigma Detection Rules]
H --> J[KQL Query]
H --> K[Splunk Query]
H --> L[YARA Rule]

I --> M[Detection Engineering Review]
J --> M
K --> M
L --> M

M --> N[Incident Timeline]
M --> O[IOC Documentation]
M --> P[Technical Report]
