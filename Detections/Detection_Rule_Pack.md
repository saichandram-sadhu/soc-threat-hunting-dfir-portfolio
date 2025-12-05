# Detection Rule Pack

This document contains a collection of high-fidelity detection rules for common adversarial techniques. Each rule is provided in **Sigma**, **Elastic KQL**, and **Splunk SPL** formats.

---

## 1. Base64 Encoded PowerShell Execution
**Technique:** T1059.001 (Command and Scripting Interpreter: PowerShell)  
**Description:** Detects the use of Base64 encoded commands in PowerShell, often used to obfuscate malicious payloads.

### Sigma Rule
```yaml
title: Base64 Encoded PowerShell Command
id: 5f1f759e-d9d3-4d6a-b7c9-1234567890ab
status: stable
description: Detects PowerShell execution with encoded command flags.
author: Saichandram Sadhu
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc'
            - '-e '
    condition: selection
level: medium
```

### Elastic KQL
```kql
process.name: "powershell.exe" and process.command_line: (*-EncodedCommand* or *-enc* or *-e *)
```

### Splunk SPL
```splunk
index=windows EventCode=4688 NewProcessName="*\\powershell.exe" (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*" OR CommandLine="*-e *")
```

---

## 2. RDP Brute Force Detection
**Technique:** T1110 (Brute Force)  
**Description:** Detects a high volume of failed RDP login attempts from a single source IP within a short timeframe.

### Sigma Rule
```yaml
title: Potential RDP Brute Force
id: 9a8b7c6d-5e4f-3a2b-1c0d-9876543210ef
status: stable
description: Detects 10 or more failed RDP login attempts in 5 minutes.
author: Saichandram Sadhu
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        LogonType: 10
    timeframe: 5m
    condition: selection | count() > 10 by IpAddress
level: high
```

### Elastic KQL
```kql
event.code: "4625" and winlog.event_data.LogonType: "10" 
| summarize Count=count() by source.ip 
| where Count > 10
```

### Splunk SPL
```splunk
index=windows EventCode=4625 LogonType=10 
| stats count by IpAddress 
| where count > 10
```

---

## 3. New Scheduled Task Creation (Persistence)
**Technique:** T1053.005 (Scheduled Task/Job: Scheduled Task)  
**Description:** Detects the creation of a new scheduled task, a common persistence mechanism.

### Sigma Rule
```yaml
title: New Scheduled Task Created
id: 11223344-5566-7788-9900-aabbccddeeff
status: experimental
description: Detects the creation of a new scheduled task via event 4698.
author: Saichandram Sadhu
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
    condition: selection
level: medium
```

### Elastic KQL
```kql
event.code: "4698"
```

### Splunk SPL
```splunk
index=windows EventCode=4698
```

---

## 4. Suspicious Parent-Child Relationship (cmd → powershell)
**Technique:** T1059 (Command and Scripting Interpreter)  
**Description:** Detects `cmd.exe` spawning `powershell.exe`, which may indicate a macro or script launching further payloads.

### Sigma Rule
```yaml
title: CMD Spawning PowerShell
id: aa11bb22-cc33-dd44-ee55-ff6677889900
status: stable
description: Detects cmd.exe launching powershell.exe.
author: Saichandram Sadhu
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\cmd.exe'
        Image|endswith: '\powershell.exe'
    condition: selection
level: medium
```

### Elastic KQL
```kql
process.parent.name: "cmd.exe" and process.name: "powershell.exe"
```

### Splunk SPL
```splunk
index=windows EventCode=4688 ParentProcessName="*\\cmd.exe" NewProcessName="*\\powershell.exe"
```

---

## 5. Credential Dumping Indicators (LSASS Access)
**Technique:** T1003.001 (OS Credential Dumping: LSASS Memory)  
**Description:** Detects non-system processes attempting to read the memory of the Local Security Authority Subsystem Service (LSASS).

### Sigma Rule
```yaml
title: LSASS Memory Access
id: 99887766-5544-3322-1100-aabbccddeeff
status: critical
description: Detects process access to LSASS with suspicious access rights.
author: Saichandram Sadhu
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess: '0x1410'
    filter:
        SourceImage|endswith:
            - '\svchost.exe'
            - '\MsMpEng.exe'
    condition: selection and not filter
level: critical
```

### Elastic KQL
```kql
event.code: "10" and winlog.event_data.TargetImage: "*\\lsass.exe" and winlog.event_data.GrantedAccess: "0x1410" and not winlog.event_data.SourceImage: ("*\\svchost.exe" or "*\\MsMpEng.exe")
```

### Splunk SPL
```splunk
index=windows EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess="0x1410" NOT (SourceImage="*\\svchost.exe" OR SourceImage="*\\MsMpEng.exe")
```
