#!/usr/bin/env bash
# acpi_thermal_mgr rootkit / DKMS / initramfs / Secure Boot hunt

cyvidia_mod_rootkit() {
  local src
  src="$(cyvidia_host_path /usr/src/acpi_thermal_mgr-1.0)"
  if [[ -d "${src}" ]]; then
    cyvidia_finding_add Critical rootkit "acpi_thermal_mgr source tree present" "DKMS/rootkit source staging" "${src}" "rootkit_remove" "sansar.json" high "disk_ioc,disk_ioc_or_rootkit"
  fi

  local ko
  ko="$(cyvidia_host_path /lib/modules)"
  if [[ -d "${ko}" ]]; then
    local hit
    hit="$(find "${ko}" -name 'acpi_thermal_mgr.ko' 2>/dev/null | head -n1 || true)"
    if [[ -n "${hit}" ]]; then
      cyvidia_finding_add Critical rootkit "acpi_thermal_mgr.ko present" "Rootkit module on disk" "${hit}" "rootkit_remove" "sansar.json" high "disk_ioc,disk_ioc_or_rootkit"
    fi
  fi

  # Initramfs name search (fixture: file listing)
  local init_list
  init_list="$(cyvidia_host_path /var/log/cyvidia-fixture/initramfs-list.txt)"
  if [[ -f "${init_list}" ]] && grep -qi 'acpi_thermal_mgr' "${init_list}"; then
    cyvidia_finding_add Critical rootkit "acpi_thermal_mgr referenced in initramfs listing" "Persistence via early boot loader" "${init_list}" "rootkit_remove" "sansar.json" high "disk_ioc_or_rootkit"
  elif ! cyvidia_is_fixture_mode; then
    if command -v lsinitramfs >/dev/null 2>&1; then
      local img
      img="$(ls /boot/initrd.img-* 2>/dev/null | tail -n1 || true)"
      if [[ -n "${img}" ]] && lsinitramfs "${img}" 2>/dev/null | grep -qi 'acpi_thermal_mgr'; then
        cyvidia_finding_add Critical rootkit "acpi_thermal_mgr in initramfs" "${img}" "${img}" "rootkit_remove" "sansar.json" high "disk_ioc_or_rootkit"
      fi
    elif command -v lsinitrd >/dev/null 2>&1; then
      if lsinitrd 2>/dev/null | grep -qi 'acpi_thermal_mgr'; then
        cyvidia_finding_add Critical rootkit "acpi_thermal_mgr in initramfs (lsinitrd)" "" "lsinitrd" "rootkit_remove" "sansar.json" high "disk_ioc_or_rootkit"
      fi
    fi
  fi

  # Secure Boot detect — never force unload
  local sb
  sb="$(cyvidia_host_path /var/log/cyvidia-fixture/secureboot.txt)"
  local state=""
  if [[ -f "${sb}" ]]; then
    state="$(tr -d '\r' <"${sb}" | head -n1)"
  elif command -v mokutil >/dev/null 2>&1; then
    state="$(mokutil --sb-state 2>/dev/null | head -n1 || true)"
  fi
  if echo "${state}" | grep -qi 'enabled'; then
    cyvidia_finding_add Medium rootkit "Secure Boot enabled" "Rootkit unload/module rebuild may require MOK/reboot guidance; see docs/playbook-secure-boot-rootkit.md" "${state}" "rootkit_remove" "" medium
  fi
}
