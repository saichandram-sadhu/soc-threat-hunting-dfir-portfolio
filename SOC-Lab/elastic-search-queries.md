# Elastic Search Queries (KQL)

## Process Execution
Find all PowerShell executions with encoded commands.
```kql
process.name: "powershell.exe" and process.command_line: *EncodedCommand*
```

## Network Activity
Find outbound connections to non-standard ports.
```kql
event.category: "network" and not destination.port: (80 or 443 or 53)
```

## User Authentication
Identify failed login attempts (Brute Force indicators).
```kql
event.code: "4625" and winlog.event_data.LogonType: "3"
```
