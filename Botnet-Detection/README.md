# Botnet Detection

## Overview
Network traffic analysis project aimed at identifying Command & Control (C2) communication patterns characteristic of IoT botnets (e.g., Mirai).

## Methodology
*   **PCAP Analysis**: Extracting flow features from raw packet captures.
*   **Behavioral Profiling**: Looking for periodic beaconing and high-frequency connection attempts.

## Tools
*   **Wireshark**: Manual inspection.
*   **Python (Scapy)**: Automated feature extraction.
