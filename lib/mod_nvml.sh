#!/usr/bin/env bash
# NVML library integrity hunt

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
    [[ -z "${lib}" && -e /usr/lib/libnvidia-ml.so.1 ]] && lib=/usr/lib/libnvidia-ml.so.1
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
  fi
}
