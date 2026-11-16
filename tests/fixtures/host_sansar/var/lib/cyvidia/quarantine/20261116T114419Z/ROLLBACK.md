# CYVIDIA rollback notes

Quarantine: /d/CYBERSEC/CYVIDIA/tests/fixtures/host_sansar/var/lib/cyvidia/quarantine/20261116T114419Z

Restore files from `tree/` preserving relative paths. Review metadata.json and rollback.json before restore.
- stop_processes: done

## NVML restore
# Debian/Ubuntu — review before running
sudo apt-get update
sudo apt-get install --reinstall -y nvidia-driver-libs nvidia-utils 2>/dev/null || \
  sudo apt-get install --reinstall -y libnvidia-ml1 nvidia-utils 2>/dev/null || \
  echo "Adjust package names for your NVIDIA apt repository / CUDA install"
After restore, re-hash libnvidia-ml.so.1 and re-run: cyvidia hunt

## Rootkit / initramfs
1. Ensure acpi_thermal_mgr sources/modules quarantined.
3. Rebuild initramfs WITHOUT malicious loader: update-initramfs -u
4. Reboot manually when ready. CYVIDIA never auto-reboots.
See docs/playbook-secure-boot-rootkit.md
- ssh_key_cleanup: backups under quarantine (manual key edit recommended)

## Ray harden
- Bind dashboard/Jobs API to 127.0.0.1 only or place behind auth/firewall.
- Block public TCP/8265 and Ray worker ports at host firewall.
- Example (nftables/iptables): deny WAN to 8265; allow management VLAN only.
- Restart Ray only after config change; verify with: ss -lntp | grep 8265

## NVIDIA CVE update
# Debian/Ubuntu — review before running
sudo apt-get update
sudo apt-get install --reinstall -y nvidia-driver-libs nvidia-utils 2>/dev/null || \
  sudo apt-get install --reinstall -y libnvidia-ml1 nvidia-utils 2>/dev/null || \
  echo "Adjust package names for your NVIDIA apt repository / CUDA install"
Prefer vendor/security-updated driver packages; then re-run cyvidia hunt.
