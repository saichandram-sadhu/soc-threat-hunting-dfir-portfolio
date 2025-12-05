# Wazuh Configuration

## Agent Configuration (ossec.conf)

### File Integrity Monitoring (FIM)
Enabled real-time monitoring for critical system directories.

```xml
<syscheck>
  <directories check_all="yes" realtime="yes">C:\Windows\System32\drivers\etc</directories>
  <directories check_all="yes" realtime="yes">C:\Users\Administrator\Desktop</directories>
</syscheck>
```

### Log Collection
Ingesting Sysmon operational logs.

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
