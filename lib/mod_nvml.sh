#!/usr/bin/env bash
# NVML library integrity hunt + package verification

cyvidia_mod_nvml() {
  local backup
  backup="$(cyvidia_host_path /usr/lib/.libnvidia-ml.so.1.backup)"
  if [[ -e "${backup}" ]]; then
    cyvidia_finding_add Critical nvml "NVML backup file present" "SANSAR installs /usr/lib/.libnvidia-ml.so.1.backup when replacing the library" "${backup}" "nvml_restore" "sansar.json" high "nvml_spoof_or_mismatch,disk_ioc_or_rootkit"
  fi

  local hook
  hook="$(cyvidia_host_path /opt/vadi_/nvml-hook)"
  if [[ -d "${hook}" ]]; then
    cyvidia_finding_add Critical nvml "nvml-hook directory present" "Malicious NVML wrapper source/staging" "${hook}" "quarantine" "sansar.json" high "nvml_spoof_or_mismatch,disk_ioc,disk_ioc_or_rootkit"
  fi

  local lib=""
  if cyvidia_is_fixture_mode; then
    lib="$(cyvidia_host_path /usr/lib/libnvidia-ml.so.1)"
  else
    if command -v ldconfig >/dev/null 2>&1; then
      lib="$(ldconfig -p 2>/dev/null | awk '/libnvidia-ml\.so\.1/ {print $NF; exit}')"
    fi
    for candidate in /usr/lib/libnvidia-ml.so.1 /usr/lib64/libnvidia-ml.so.1 /usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1; do
      [[ -z "${lib}" && -e "${candidate}" ]] && lib="${candidate}"
    done
  fi

  if [[ -n "${lib}" && -e "${lib}" ]]; then
    local h
    h="$(cyvidia_sha256_file "${lib}")"
    local known
    known="$(cyvidia_py -c "import json,pathlib; p=json.loads(pathlib.Path(r'${CYVIDIA_ROOT_NATIVE}/iocs/sansar.json').read_text(encoding='utf-8'));
print('\n'.join(x['hash'].lower() for x in p.get('sha256',[]) if x.get('name')=='libnvidia-ml.so.1'))")"
    if echo "${known}" | grep -qi "^${h}$"; then
      cyvidia_finding_add Critical nvml "libnvidia-ml.so.1 matches known malicious hash" "${h}" "${lib}" "nvml_restore" "sansar.json" high "nvml_spoof_or_mismatch,disk_ioc,disk_ioc_or_rootkit"
    fi

    # Live package ownership / verify
    if ! cyvidia_is_fixture_mode; then
      cyvidia_distro_load
      local verify_out
      verify_out="$(cyvidia_pkg_verify_file "${lib}" 2>&1 || true)"
      if echo "${verify_out}" | grep -Eiq 'FAILED|modified|missing|NOT OK|deletes|replaces'; then
        cyvidia_finding_add High nvml "Package verify reports NVML library anomaly" "${verify_out}" "${lib}" "nvml_restore" "" high "nvml_spoof_or_mismatch"
      elif [[ -n "${verify_out}" ]]; then
        cyvidia_finding_add Info nvml "NVML package ownership" "${verify_out}" "${lib}" "" "" low
      fi
    fi
  elif ! cyvidia_is_fixture_mode; then
    cyvidia_finding_add Info nvml "libnvidia-ml.so.1 not found" "No NVIDIA ML library on host or not in ldconfig" "" "" "" low
  fi
}
