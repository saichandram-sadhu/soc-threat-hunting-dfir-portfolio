# SOC Lab Setup

## Overview
This folder contains the configuration and documentation for my Home SOC Lab. The lab is designed to simulate a real-world enterprise environment for detection engineering and threat analysis.

## Architecture
- **SIEM**: Elastic Stack (Elasticsearch, Logstash, Kibana)
- **EDR**: Wazuh Manager & Agents
- **Telemetry**: Sysmon (System Monitor)
- **Attack Simulation**: Atomic Red Team, Caldera

## Contents
- `sysmon-config.xml`: Optimized Sysmon configuration for capturing relevant security events.
- `wazuh-config.md`: Configuration details for Wazuh manager and agents.
- `elastic-search-queries.md`: Useful KQL queries for hunting in Kibana.
