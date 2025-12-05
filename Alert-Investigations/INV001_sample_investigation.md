# Investigation Report: INV001 - Credential Theft via Mimikatz

**Date:** 2023-10-15
**Analyst:** Saichandram Sadhu
**Severity:** Critical
**Status:** Closed

## 1. Alert Trigger
*   **Rule Name:** `Mimikatz Usage Detected (Sysmon)`
*   **Trigger Time:** 14:32 UTC
*   **Affected Host:** `FIN-WRKSTN-02`
*   **User Account:** `finance_admin`

## 2. Triage & Initial Analysis
*   **True Positive**: Yes.
*   **Evidence**:
    *   Process `lsass.exe` was accessed by `rundll32.exe` with `GrantedAccess` 0x1410 (Read/Write).
    *   Command line: `rundll32.exe C:\Windows\Temp\mimi.dll,Coffee`

## 3. Investigation Steps
1.  **Process Analysis**: Traced parent process of `rundll32.exe` to `powershell.exe`.
2.  **Network Analysis**: Observed outbound connection to `192.168.1.50` (Internal IP, possible lateral movement) on port 445 immediately after.
3.  **File Analysis**: `mimi.dll` hash matched known Mimikatz variant.

## 4. Findings
*   Attacker gained initial access via Phishing (correlated with email logs).
*   Executed Mimikatz to dump credentials.
*   Attempted lateral movement to File Server.

## 5. Remediation & Lessons Learned
*   **Action Taken**: Isolated `FIN-WRKSTN-02`. Reset `finance_admin` credentials. Re-imaged host.
*   **Improvement**: Tuned LSASS access rule to alert on non-system processes accessing LSASS memory.
