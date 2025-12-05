# SOC Alert Investigation Report
## Incident Report: INV-2023-1025-01
**Status:** Closed  
**Severity:** Critical  
**Date:** October 25, 2023  
**Analyst:** Saichandram Sadhu  

---

## 1. Executive Summary
On October 25, 2023, at 14:15 UTC, the SOC received a critical alert indicating the execution of a suspicious PowerShell command with high entropy (Base64 encoded) on workstation `HR-WKSTN-04`. Investigation revealed a successful credential dumping attempt targeting the `lsass.exe` process. The host was immediately isolated, and the malicious artifacts were removed. No lateral movement was observed.

## 2. Triggering Alert
*   **Alert Name:** `Suspicious PowerShell Encoded Command`
*   **SIEM Rule ID:** `PS-ENC-001`
*   **Severity:** High
*   **Trigger Time:** 2023-10-25 14:15:32 UTC
*   **Affected Host:** `HR-WKSTN-04` (10.10.50.23)
*   **User Account:** `jdoe` (Domain User)

## 3. Timeline of Events

| Timestamp (UTC) | Event Type | Description |
| :--- | :--- | :--- |
| 14:10:05 | Phishing Delivery | User `jdoe` received an email with subject "Invoice_UPDATED.docm". |
| 14:12:15 | Execution | User opened the attachment. Word spawned `cmd.exe`. |
| 14:15:32 | Alert Trigger | `cmd.exe` spawned `powershell.exe` with a Base64 encoded payload. |
| 14:15:45 | C2 Connection | `powershell.exe` initiated a connection to `192.168.45.10` (External). |
| 14:16:10 | Credential Dump | `powershell.exe` injected code into a new thread in `rundll32.exe`, which then accessed `lsass.exe`. |
| 14:20:00 | Containment | Host `HR-WKSTN-04` isolated via EDR. |

## 4. Evidence Collected

### A. Windows Event Logs
**Event ID 4688 (Process Creation):**
```text
Parent Process Name: C:\Program Files\Microsoft Office\Office16\WINWORD.EXE
Process Name: C:\Windows\System32\cmd.exe
Command Line: cmd.exe /c powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQAoAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAIg...
```

### B. Sysmon Logs
**Event ID 1 (Process Create):**
Shows the full command line arguments and the parent-child relationship confirming the macro execution.

**Event ID 3 (Network Connection):**
```text
Image: C:\Windows\System32\powershell.exe
Protocol: tcp
SourceIp: 10.10.50.23
SourcePort: 49678
DestinationIp: 192.168.45.10
DestinationPort: 443
```

**Event ID 10 (Process Access):**
```text
SourceImage: C:\Windows\System32\rundll32.exe
TargetImage: C:\Windows\System32\lsass.exe
GrantedAccess: 0x1410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
CallTrace: C:\Windows\SYSTEM32\ntdll.dll+0xa0b40|C:\Windows\System32\KERNELBASE.dll+0x257d0|...
```

## 5. Attack Analysis

### Decoding the Payload
The Base64 string from the PowerShell command was decoded:
```powershell
$s = New-Object IO.MemoryStream([Convert]::FromBase64String("H4sIAAAAAAAEAO..."));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s, [IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```
**Analysis:** The script decodes a Gzip-compressed byte array and executes it in memory (`IEX`). This is a common technique used by **Cobalt Strike** and **Empire** stagers.

### MITRE ATT&CK Mapping
*   **T1566.001 (Phishing: Spearphishing Attachment)**: Malicious Word doc.
*   **T1059.001 (Command and Scripting Interpreter: PowerShell)**: Execution of the payload.
*   **T1027 (Obfuscated Files or Information)**: Base64 encoding.
*   **T1003.001 (OS Credential Dumping: LSASS Memory)**: Accessing LSASS to steal credentials.

## 6. Indicators of Compromise (IOCs)

| Type | Indicator | Description |
| :--- | :--- | :--- |
| IP Address | `192.168.45.10` | C2 Server (Malicious) |
| File Hash (SHA256) | `a1b2c3d4e5f6...` | Invoice_UPDATED.docm |
| Domain | `update-office-secure.com` | Phishing Link Domain |

## 7. Root Cause Analysis
The user enabled macros on an untrusted document delivered via email. The email filter failed to catch the weaponized `.docm` file due to it being a zero-day variant.

## 8. Containment & Eradication
1.  **Isolation**: `HR-WKSTN-04` was isolated from the network using Wazuh active response.
2.  **Password Reset**: User `jdoe`'s domain password was reset.
3.  **Cleanup**: The malicious file `Invoice_UPDATED.docm` was deleted.
4.  **Re-imaging**: The workstation was queued for re-imaging to ensure no persistence mechanisms remained.

## 9. Prevention Recommendations
1.  **Policy**: Enforce "Block macros from files downloaded from the Internet" via Group Policy.
2.  **Detection**: Tune Sysmon rules to alert on `rundll32.exe` accessing `lsass.exe` with `GrantedAccess` 0x1410.
3.  **Training**: Conduct targeted phishing awareness training for the HR department.

---

## 10. Screenshots
*(Placeholders for evidence screenshots)*

![Process Tree](screenshots/process_tree_placeholder.png)
*Figure 1: Process tree showing WINWORD.EXE spawning cmd.exe*

![Network Connection](screenshots/network_conn_placeholder.png)
*Figure 2: Sysmon Event ID 3 showing connection to C2 IP*
