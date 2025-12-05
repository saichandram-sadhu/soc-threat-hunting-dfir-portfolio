# Plaso Timeline Analysis

**Case:** [Case Name]
**Evidence:** [Disk Image Name]

## 1. Timeline Generation
Command used:
`log2timeline.py timeline.plaso image.dd`

## 2. Filtering
Command used to filter for specific date range:
`psort.py -o l2tcsv -w timeline.csv timeline.plaso "date > '2023-01-01 00:00:00'"`

## 3. Key Events
| Timestamp | Source | Description |
| :--- | :--- | :--- |
| 2023-01-01 10:00:00 | WEVT | User Logon (Event 4624) |
| 2023-01-01 10:05:00 | FILE | File Created: C:\Temp\malware.exe |
| 2023-01-01 10:05:05 | REG | Run Key Added: HKCU\...\Run\Malware |
