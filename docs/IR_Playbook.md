# Incident Response Playbook: Malware Outbreak

## 1. Preparation
*   Ensure EDR is active.
*   Update AV signatures.

## 2. Identification
*   **Triggers**: Multiple EDR alerts, user reports of slow systems.
*   **Verification**: Check hash reputation, analyze sample.

## 3. Containment
*   **Short-term**: Isolate infected hosts from network.
*   **Long-term**: Block C2 domains at firewall.

## 4. Eradication
*   Re-image infected machines.
*   Remove malicious artifacts (scheduled tasks, registry keys).

## 5. Recovery
*   Restore data from backups.
*   Monitor for re-infection.

## 6. Lessons Learned
*   Conduct Post-Incident Review.
