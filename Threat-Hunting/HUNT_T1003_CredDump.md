# Threat Hunt: T1003 - OS Credential Dumping (LSASS)

**Date:** 2023-11-05
**Technique:** T1003.001 - LSASS Memory
**Status:** Complete

## 1. Hypothesis
Attackers may attempt to dump the memory of the `lsass.exe` process to retrieve plaintext credentials or NTLM hashes using tools like Mimikatz or ProcDump.

## 2. Data Sources
*   Sysmon Event ID 10 (Process Access)

## 3. Query (KQL)
```kql
// Look for non-system processes accessing LSASS with specific access rights
DeviceProcessEvents
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in ("svchost.exe", "MsMpEng.exe", "csrss.exe")
// Access Mask 0x1410 or 0x1010 often indicates reading memory
| where GrantedAccess in ("0x1410", "0x1010")
```

## 4. Findings
*   **Anomalies:** Found `taskmgr.exe` accessing LSASS (Legitimate admin activity).
*   **Confirmed Threats:** None in this hunt window.

## 5. Outcome
*   Created a whitelist for `taskmgr.exe` when run by Domain Admins.
*   Implemented a high-fidelity alert for any unknown binary accessing LSASS.
