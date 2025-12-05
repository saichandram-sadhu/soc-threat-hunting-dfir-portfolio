# Memory Forensics Case 1: Malicious Process Injection

**Case ID:** MF-001
**Evidence:** `memdump_infected.raw`
**Tool:** Volatility 3

## 1. Process Analysis
Ran `windows.pslist` and `windows.pstree`.
*   **Observation:** Found `svchost.exe` running with a parent process of `explorer.exe`.
*   **Analysis:** Legitimate `svchost.exe` should be spawned by `services.exe`. This is highly suspicious.

## 2. Network Analysis
Ran `windows.netscan`.
*   **Observation:** The suspicious `svchost.exe` (PID 4520) had an established connection to `192.168.1.100` on port 4444.
*   **Analysis:** Port 4444 is commonly used by Metasploit/Meterpreter.

## 3. Code Injection
Ran `windows.malfind`.
*   **Observation:** Detected PAGE_EXECUTE_READWRITE (RWX) memory protection in PID 4520.
*   **Analysis:** Confirmed code injection. Extracted the memory segment and identified it as a Meterpreter payload.

## Conclusion
The system was compromised via a malicious payload injected into a fake `svchost.exe` process.
