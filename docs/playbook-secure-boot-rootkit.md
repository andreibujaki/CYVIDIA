# Secure Boot / rootkit removal playbook

When `acpi_thermal_mgr` evidence exists and Secure Boot is enabled:

1. Do **not** force-unload unsigned modules.
2. Quarantine DKMS/source/module files with CYVIDIA harden (consent required).
3. Rebuild initramfs **without** the malicious loader (`update-initramfs -u` or `dracut -f` per distro).
4. Schedule a maintenance reboot with console access.
5. If module signature enforcement blocks changes, use your OS MOK enrollment process only for **vendor-signed** replacements — never enroll attacker modules.
6. If live views look clean but disk/initramfs still show toolkit paths, treat runtime listings as untrustworthy and prefer offline disk inspection from a clean boot/rescue environment.
