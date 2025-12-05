# Hi there, I'm Saichandram Sadhu 👋

### SOC Analyst | Threat Hunter | DFIR (In Progress)

> 🔍 I investigate alerts, hunt adversaries, and perform forensic analysis to secure enterprise environments.

---

## 🛡️ What I Do

*   **Log Analysis**: Deep dive into Windows Event Logs, Linux Syslog, and Sysmon for anomaly detection.
*   **Alert Triage & Investigation**: Analyzing SIEM alerts to distinguish true positives from false positives.
*   **Detection Engineering**: Writing custom detection rules using **Sigma**, **KQL**, and **SPL**.
*   **Threat Hunting**: Proactive hunting based on **MITRE ATT&CK** TTPs.
*   **Malware Triage**: Basic static and dynamic analysis, including memory forensics.
*   **Automation**: Using **Python** to automate repetitive SOC tasks and log parsing.

---

## 🚨 SOC & Threat Detection Projects

### 🏠 A) Home SOC Lab – Elastic + Wazuh + Sysmon
*Built a complete detection lab to simulate real-world attacks and defense.*
*   **Infrastructure**: Deployed **Wazuh** for EDR and **Elastic Stack (ELK)** for log aggregation.
*   **Ingestion**: Configured **Sysmon** with a custom modular configuration to capture granular endpoint telemetry.
*   **Simulations**: Executed attacks using **Atomic Red Team** and **Caldera** to validate log visibility.
*   **Outcome**: Successfully detected and visualized multi-stage attack chains in Kibana dashboards.

### 📦 B) Alert Investigation Pack (5 Cases)
*End-to-end investigation of simulated security incidents.*
1.  **Encoded PowerShell**: Decoded Base64 payloads to identify C2 beaconing attempts.
2.  **RDP Brute Force**: Analyzed Event ID 4625 clusters to identify attacker IP and targeted accounts.
3.  **Malicious Service Creation**: Detected persistence via `sc.exe` and registry run keys.
4.  **Persistence Mechanisms**: Investigated scheduled tasks used for maintaining access.
5.  **Data Exfiltration**: Identified anomalous outbound traffic patterns correlated with file access events.

### ⚙️ C) Detection Engineering (20+ Rules)
*Developed and tuned detection logic to reduce noise and catch threats.*
*   **Sigma Rules**: Created platform-agnostic rules for process injection and credential dumping (e.g., LSASS access).
*   **Behavioral Detections**: Wrote KQL queries to detect "Living off the Land" (LotL) binaries abuse (e.g., `certutil`, `bitsadmin`).
*   **Tuning**: Optimized existing rules to reduce false positive rates by 40% through whitelisting legitimate business operations.

---

## 🏹 Threat Hunting Projects

*   **MITRE ATT&CK Hunts**: Conducted hypothesis-driven hunts mapping to T1059 (Command and Scripting Interpreter) and T1003 (OS Credential Dumping).
*   **Process**:
    1.  **Hypothesis**: "Attackers are using named pipes for lateral movement."
    2.  **Query**: Developed SPL queries to look for anomalous SMB pipe connections.
    3.  **Findings**: Identified a misconfigured service mimicking lateral movement behavior; documented findings for remediation.
*   **Detection Improvement**: Translated successful hunt queries into permanent SIEM alerts.

---

## 🔍 DFIR Projects

### 🧠 A) Memory Forensics
*   **Tools**: Utilized **Volatility 3** to analyze captured RAM images.
*   **Artifacts**: Extracted process lists (`pslist`), network connections (`netscan`), and injected code segments (`malfind`) to identify rootkits and hidden malware.

### 🦠 B) Malware Analysis
*   **Static Analysis**: Examined PE headers, strings, and imports using **PEStudio** and **CFF Explorer**.
*   **Dynamic Analysis**: Ran samples in a sandbox environment, monitoring API calls and file system changes with **ProcMon**.
*   **YARA**: Wrote custom YARA rules to classify malware families based on identified unique strings and byte sequences.

### ⏱️ C) Forensic Timelines
*   **Timeline Generation**: Created super-timelines using **Plaso** (log2timeline) to reconstruct the sequence of events during an incident.
*   **Analysis**: Correlated file system changes ($MFT) with execution artifacts (Prefetch, Shimcache) to pinpoint patient zero.

---

## 🤖 AI & Network Projects

### 🧠 A) AI-Powered Intrusion Detection System
*   Developed a Python-based IDS using **Machine Learning** (Isolation Forest) to detect network anomalies.
*   Integrated with a web dashboard to visualize threat scores and alert details in real-time.

### 🕸️ B) Botnet Detection
*   Analyzed PCAP files using **Wireshark** and **Python** (Scapy/Pandas).
*   Identified C2 communication patterns and beaconing intervals characteristic of IoT botnets.

---

## 🛠️ Tools & Technologies

| Category | Tools |
| :--- | :--- |
| **SIEM & Log Management** | Splunk, Elastic Stack (ELK), Wazuh, Microsoft Sentinel |
| **Forensics** | Volatility 3, Autopsy, KAPE, Eric Zimmerman's Tools, Plaso |
| **Threat Hunting** | MITRE ATT&CK, Sigma, YARA, Snort |
| **Malware Analysis** | PEStudio, ProcMon, Wireshark, Any.Run, Ghidra |
| **Languages** | Python, PowerShell, Bash, SQL (KQL/SPL) |
| **Operating Systems** | Windows Server, Linux (Ubuntu/Kali/Remnux) |

---

## 🚀 Current Focus

I am actively deepening my expertise in **Digital Forensics & Incident Response (DFIR)**:
*   📈 **Advanced Sysmon Configs**: Tuning configuration for maximum visibility with minimal noise.
*   ✍️ **Signature Writing**: Mastering advanced Sigma and YARA rule development.
*   🕵️‍♂️ **Deep Forensics**: Advanced file system forensics (NTFS internals) and registry analysis.
*   🤖 **Automation**: Building SOAR playbooks to automate the initial triage phase.

---

## 📬 Contact

*   📧 **Email**: [saichandram.sadhu.it@gmail.com](saichandram.sadhu.it@gmail.com)
*   🐙 **GitHub**: [https://github.com/saichandram-sadhu](https://github.com/saichandram-sadhu)
*   💼 **LinkedIn**: [www.linkedin.com/in/saichandram-sadhu-9980a2357](www.linkedin.com/in/saichandram-sadhu-9980a2357)

---
