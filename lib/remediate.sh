#!/usr/bin/env bash
# Consent-gated remediation (full map; never auto-reboot)

cyvidia_remediate_execute() {
  local plan_file="$1"
  [[ -f "${plan_file}" ]] || cyvidia_die "plan file missing: ${plan_file}"

  local plan_n
  plan_n="$(cyvidia_native_path "${plan_file}")"

  local status
  status="$(cyvidia_consent_validate | head -n1)" || true
  if [[ "${status}" != "ok" ]]; then
    echo "CONSENT_STATUS=${status}" >&2
    exit 3
  fi

  local allowed
  allowed="$(cyvidia_consent_validate | tail -n1)"

  cyvidia_lock_acquire
  trap cyvidia_lock_release EXIT

  local plan_id
  plan_id="$(cyvidia_py -c "import json,sys; print(json.load(open(sys.argv[1],encoding='utf-8'))['plan_id'])" "${plan_n}")"
  local qdir
  qdir="$(cyvidia_quarantine_begin "${plan_id}")"
  cyvidia_info "Quarantine: ${qdir}"
  logger -t cyvidia "remediate start plan_id=${plan_id} quarantine=${qdir}" 2>/dev/null || true

  cyvidia_distro_load

  _allow() {
    [[ ",${allowed}," == *",$1,"* ]]
  }

  # 1) Stop processes
  if _allow stop_processes; then
    local n
    for n in sansar kurt tilki lyrebird netns xmrig SRBMiner-MULTI; do
      if ! cyvidia_is_fixture_mode; then
        pkill -x "${n}" 2>/dev/null || true
      fi
    done
    echo "- stop_processes: done" >>"${qdir}/ROLLBACK.md"
  fi

  # 2) Disable units
  if _allow disable_units && ! cyvidia_is_fixture_mode && command -v systemctl >/dev/null 2>&1; then
    local u
    for u in netns.service sansar.service lyrebird.service; do
      systemctl disable --now "${u}" 2>/dev/null || true
      systemctl mask "${u}" 2>/dev/null || true
    done
    echo "- disable_units: attempted netns/sansar/lyrebird" >>"${qdir}/ROLLBACK.md"
  fi

  # 3) Quarantine toolkit paths
  if _allow quarantine; then
    local p
    for p in /opt/vadi_ /usr/src/acpi_thermal_mgr-1.0 /usr/lib/.libnvidia-ml.so.1.backup; do
      local hp
      hp="$(cyvidia_host_path "${p}")"
      if [[ -e "${hp}" ]]; then
        cyvidia_quarantine_file "${qdir}" "${hp}"
        if ! cyvidia_is_fixture_mode || [[ "${CYVIDIA_FIXTURE_MUTATE:-0}" == "1" ]]; then
          rm -rf "${hp}"
        fi
      fi
    done
    # Also quarantine DKMS-like trees
    local src_root
    src_root="$(cyvidia_host_path /usr/src)"
    if [[ -d "${src_root}" ]]; then
      local d
      for d in "${src_root}"/acpi_thermal_mgr*; do
        [[ -e "${d}" ]] || continue
        cyvidia_quarantine_file "${qdir}" "${d}"
        if ! cyvidia_is_fixture_mode || [[ "${CYVIDIA_FIXTURE_MUTATE:-0}" == "1" ]]; then
          rm -rf "${d}"
        fi
      done
    fi
  fi

  # 4) NVML restore notes / commands
  if _allow nvml_restore; then
    {
      echo
      echo "## NVML restore"
      cyvidia_nvidia_reinstall_cmds
      echo "After restore, re-hash libnvidia-ml.so.1 and re-run: cyvidia hunt"
    } >>"${qdir}/ROLLBACK.md"
  fi

  # 5) Rootkit / initramfs — never reboot
  if _allow rootkit_remove; then
    {
      echo
      echo "## Rootkit / initramfs"
      echo "1. Ensure acpi_thermal_mgr sources/modules quarantined."
      if ! cyvidia_is_fixture_mode && command -v dkms >/dev/null 2>&1; then
        echo "2. dkms remove acpi_thermal_mgr/1.0 --all  # if registered"
      fi
      echo "3. Rebuild initramfs WITHOUT malicious loader: $(cyvidia_initramfs_rebuild_cmd)"
      echo "4. Reboot manually when ready. CYVIDIA never auto-reboots."
      echo "See docs/playbook-secure-boot-rootkit.md"
    } >>"${qdir}/ROLLBACK.md"
  fi

  # 6) SSH key cleanup from plan evidence (backup first)
  if _allow ssh_key_cleanup; then
    cyvidia_py - "${plan_n}" "${qdir}" <<'PY'
import json, pathlib, shutil, sys
plan = json.load(open(sys.argv[1], encoding="utf-8"))
qdir = pathlib.Path(sys.argv[2])
notes = []
for a in plan.get("actions", []):
    if a.get("action") != "ssh_key_cleanup":
        continue
    ev = a.get("evidence") or ""
    p = pathlib.Path(ev)
    if not p.is_file():
        continue
    bak = qdir / "tree" / "ssh_backup" / p.name
    bak.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(p, bak)
    notes.append(f"backed up {p} -> {bak}")
(qdir / "ssh_cleanup_notes.txt").write_text("\n".join(notes) + "\n", encoding="utf-8")
print(f"ssh_backups={len(notes)}")
PY
    echo "- ssh_key_cleanup: backups under quarantine (manual key edit recommended)" >>"${qdir}/ROLLBACK.md"
  fi

  # 7) Ray harden guidance
  if _allow ray_harden; then
    {
      echo
      echo "## Ray harden"
      echo "- Bind dashboard/Jobs API to 127.0.0.1 only or place behind auth/firewall."
      echo "- Block public TCP/8265 and Ray worker ports at host firewall."
      echo "- Example (nftables/iptables): deny WAN to 8265; allow management VLAN only."
      echo "- Restart Ray only after config change; verify with: ss -lntp | grep 8265"
    } >>"${qdir}/ROLLBACK.md"
  fi

  # 8) CVE update guidance
  if _allow cve_update; then
    {
      echo
      echo "## NVIDIA CVE update"
      cyvidia_nvidia_reinstall_cmds
      echo "Prefer vendor/security-updated driver packages; then re-run cyvidia hunt."
    } >>"${qdir}/ROLLBACK.md"
  fi

  # Append machine-readable completion
  cyvidia_py - "$(cyvidia_native_path "${qdir}/rollback.json")" "${plan_id}" <<'PY'
import json,sys
rb, plan_id = sys.argv[1:]
doc=json.load(open(rb,encoding="utf-8"))
doc.setdefault("steps", []).append({"action":"remediate_complete","plan_id":plan_id,"reboot_required_manual":True})
json.dump(doc, open(rb,"w",encoding="utf-8"), indent=2)
PY

  logger -t cyvidia "remediate completed plan_id=${plan_id} quarantine=${qdir}" 2>/dev/null || true
  echo "Remediation steps applied (quarantine + notes). Manual reboot may be required."
  echo "QUARANTINE=${qdir}"
  echo "${qdir}"
}
