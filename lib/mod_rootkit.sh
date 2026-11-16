#!/usr/bin/env bash
# acpi_thermal_mgr rootkit / DKMS / initramfs / Secure Boot hunt

cyvidia_mod_rootkit() {
  local src
  src="$(cyvidia_host_path /usr/src/acpi_thermal_mgr-1.0)"
  if [[ -d "${src}" ]]; then
    cyvidia_finding_add Critical rootkit "acpi_thermal_mgr source tree present" "DKMS/rootkit source staging" "${src}" "rootkit_remove" "sansar.json" high "disk_ioc,disk_ioc_or_rootkit"
  fi

  # Any acpi_thermal_mgr-* under /usr/src
  local src_root
  src_root="$(cyvidia_host_path /usr/src)"
  if [[ -d "${src_root}" ]]; then
    local d
    for d in "${src_root}"/acpi_thermal_mgr*; do
      [[ -e "${d}" ]] || continue
      cyvidia_finding_add Critical rootkit "acpi_thermal_mgr tree: $(basename "${d}")" "DKMS/rootkit source staging" "${d}" "rootkit_remove" "sansar.json" high "disk_ioc,disk_ioc_or_rootkit"
    done
  fi

  local ko_root
  ko_root="$(cyvidia_host_path /lib/modules)"
  if [[ -d "${ko_root}" ]]; then
    local hit
    hit="$(find "${ko_root}" -name 'acpi_thermal_mgr.ko' 2>/dev/null | head -n1 || true)"
    if [[ -n "${hit}" ]]; then
      local h
      h="$(cyvidia_sha256_file "${hit}" 2>/dev/null || echo unknown)"
      cyvidia_finding_add Critical rootkit "acpi_thermal_mgr.ko present" "sha256=${h}" "${hit}" "rootkit_remove" "sansar.json" high "disk_ioc,disk_ioc_or_rootkit"
    fi
  fi

  # DKMS status (live)
  if ! cyvidia_is_fixture_mode && command -v dkms >/dev/null 2>&1; then
    if dkms status 2>/dev/null | grep -qi 'acpi_thermal_mgr'; then
      cyvidia_finding_add Critical rootkit "DKMS lists acpi_thermal_mgr" "$(dkms status 2>/dev/null | grep -i acpi_thermal_mgr)" "dkms status" "rootkit_remove" "sansar.json" high "disk_ioc_or_rootkit"
    fi
  fi

  # Initramfs inspection
  local init_list
  init_list="$(cyvidia_host_path /var/log/cyvidia-fixture/initramfs-list.txt)"
  if [[ -f "${init_list}" ]] && grep -qi 'acpi_thermal_mgr' "${init_list}"; then
    cyvidia_finding_add Critical rootkit "acpi_thermal_mgr referenced in initramfs listing" "Persistence via early boot loader" "${init_list}" "rootkit_remove" "sansar.json" high "disk_ioc_or_rootkit"
  elif ! cyvidia_is_fixture_mode; then
    local found_init=0
    if command -v lsinitramfs >/dev/null 2>&1; then
      local img
      for img in /boot/initrd.img-* /boot/initramfs-*.img; do
        [[ -f "${img}" ]] || continue
        if lsinitramfs "${img}" 2>/dev/null | grep -qi 'acpi_thermal_mgr'; then
          cyvidia_finding_add Critical rootkit "acpi_thermal_mgr in initramfs" "${img}" "${img}" "rootkit_remove" "sansar.json" high "disk_ioc_or_rootkit"
          found_init=1
        fi
      done
    fi
    if [[ "${found_init}" -eq 0 ]] && command -v lsinitrd >/dev/null 2>&1; then
      if lsinitrd 2>/dev/null | grep -qi 'acpi_thermal_mgr'; then
        cyvidia_finding_add Critical rootkit "acpi_thermal_mgr in initramfs (lsinitrd)" "" "lsinitrd" "rootkit_remove" "sansar.json" high "disk_ioc_or_rootkit"
        found_init=1
      fi
    fi
    # Fallback: strings on newest initrd if tools missing
    if [[ "${found_init}" -eq 0 ]]; then
      local img
      img="$(ls -1t /boot/initrd.img-* /boot/initramfs-*.img 2>/dev/null | head -n1 || true)"
      if [[ -n "${img}" ]] && command -v strings >/dev/null 2>&1; then
        if strings "${img}" 2>/dev/null | grep -qi 'acpi_thermal_mgr'; then
          cyvidia_finding_add High rootkit "acpi_thermal_mgr string in initramfs image" "Confirm with lsinitramfs/lsinitrd when available" "${img}" "rootkit_remove" "sansar.json" medium "disk_ioc_or_rootkit"
        fi
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
  elif [[ -d /sys/firmware/efi ]]; then
    if [[ -f /sys/firmware/efi/efivars/SecureBoot-* ]]; then
      state="EFI present (check mokutil for SecureBoot state)"
    fi
  fi
  if echo "${state}" | grep -qi 'enabled'; then
    cyvidia_finding_add Medium rootkit "Secure Boot enabled" "Rootkit unload/module rebuild may require MOK/reboot guidance; see docs/playbook-secure-boot-rootkit.md" "${state}" "rootkit_remove" "" medium
  elif [[ -n "${state}" ]]; then
    cyvidia_finding_add Info rootkit "Secure Boot state" "${state}" "" "" "" low
  fi
}
