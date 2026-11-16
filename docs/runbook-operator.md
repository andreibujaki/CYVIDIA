# Operator runbook

1. **Hunt (read-only)**  
   `cyvidia hunt --output-json /tmp/cyvidia.json --report-md /tmp/cyvidia.md`

2. **Review** Critical/High findings and correlation labels in the JSON/MD report.

3. **Plan (required)**  
   `cyvidia harden --plan --findings /tmp/cyvidia.json`  
   Or: `cyvidia harden --plan` (runs hunt first).

4. **Consent**  
   `cyvidia consent grant "$USER" 24`

5. **Execute remediation**  
   `cyvidia harden --execute --plan-file /path/from/plan`

6. **Verify**  
   `cyvidia hunt --output-json /tmp/cyvidia-after.json`

7. **Reboot manually** if rootkit/initramfs notes say so. CYVIDIA never auto-reboots.

Air-gapped hosts: omit `--network`. Refresh IOC packs offline per `docs/ioc-update.md`.
