# Threat Hunting

## Overview
Proactive threat hunting missions based on the **MITRE ATT&CK** framework. I use a hypothesis-driven approach to find threats that evade automated detection.

## Hunting Process
1.  **Hypothesis Generation**: "If an attacker is doing X, I should see Y in the logs."
2.  **Data Mining**: Querying SIEM/EDR data.
3.  **Analysis**: Filtering out known good behavior (baselining).
4.  **Validation**: Confirming malicious intent.
5.  **Operationalization**: Converting successful hunts into detection rules.
