#!/usr/bin/env bash
# Consent-gated remediation (full map; never auto-reboot)

cyvidia_remediate_execute() {
  local plan_file="$1"
  [[ -f "${plan_file}" ]] || cyvidia_die "plan file missing: ${plan_file}"

  local status
  status="$(cyvidia_consent_validate | head -n1)" || true
  if [[ "${status}" != "ok" ]]; then
    cyvidia_die "consent required/refused (${status})"
  fi

  cyvidia_lock_acquire
  trap cyvidia_lock_release EXIT

  local plan_id
  plan_id="$(cyvidia_py -c "import json,sys; print(json.load(open(sys.argv[1],encoding='utf-8'))['plan_id'])" "${plan_file}")"
  local qdir
  qdir="$(cyvidia_quarantine_begin "${plan_id}")"
  cyvidia_info "Quarantine: ${qdir}"

  # Stop processes (best-effort names)
  local n
  for n in sansar kurt tilki lyrebird netns xmrig; do
    if ! cyvidia_is_fixture_mode; then
      pkill -x "${n}" 2>/dev/null || true
    fi
  done

  # Quarantine known paths if present
  local p
  for p in /opt/vadi_ /usr/src/acpi_thermal_mgr-1.0 /usr/lib/.libnvidia-ml.so.1.backup; do
    local hp
    hp="$(cyvidia_host_path "${p}")"
    if [[ -e "${hp}" ]]; then
      cyvidia_quarantine_file "${qdir}" "${hp}"
      if ! cyvidia_is_fixture_mode; then
        rm -rf "${hp}"
      else
        # In fixture mode, leave originals for repeatable tests unless CYVIDIA_FIXTURE_MUTATE=1
        if [[ "${CYVIDIA_FIXTURE_MUTATE:-0}" == "1" ]]; then
          rm -rf "${hp}"
        fi
      fi
    fi
  done

  # NVML restore guidance
  {
    echo "## NVML restore"
    cyvidia_distro_load
    cyvidia_nvidia_reinstall_cmds
  } >>"${qdir}/ROLLBACK.md"

  # Rootkit / initramfs — never reboot
  {
    echo
    echo "## Rootkit / initramfs"
    echo "Rebuild initramfs without acpi_thermal_mgr, then reboot manually when ready."
    echo "Command: $(cyvidia_initramfs_rebuild_cmd)"
    echo "See docs/playbook-secure-boot-rootkit.md"
  } >>"${qdir}/ROLLBACK.md"

  logger -t cyvidia "remediate completed plan_id=${plan_id} quarantine=${qdir}" 2>/dev/null || true
  echo "Remediation steps applied (quarantine + notes). Manual reboot may be required."
  echo "${qdir}"
}
