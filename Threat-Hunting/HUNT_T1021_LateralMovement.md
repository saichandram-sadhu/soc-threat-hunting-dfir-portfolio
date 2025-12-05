# Threat Hunt: T1021 - Lateral Movement (SMB/Windows Admin Shares)

**Date:** 2023-11-12
**Technique:** T1021.002 - SMB/Windows Admin Shares
**Status:** Complete

## 1. Hypothesis
Attackers may use valid accounts to move laterally to other systems via SMB (Port 445), specifically targeting administrative shares like C$ or ADMIN$.

## 2. Data Sources
*   Windows Security Event 5140 (Network Share Object Accessed)
*   Sysmon Event ID 3 (Network Connection)

## 3. Query (SPL)
```spl
index=windows EventCode=5140 ShareName="*C$" OR ShareName="*ADMIN$"
| stats count by SubjectUserName, SourceAddress, ComputerName
| where SubjectUserName != "SYSTEM" AND SubjectUserName != "*$"
```

## 4. Findings
*   **Anomalies:** Detected a service account `svc_backup` accessing C$ on multiple workstations.
*   **Investigation:** Validated as legitimate backup activity, but the account had excessive privileges.

## 5. Outcome
*   Recommended applying "Logon as a Service" restrictions to the backup account.
*   Refined detection to exclude the backup server IP.
