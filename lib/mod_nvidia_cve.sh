#!/usr/bin/env bash
# NVIDIA driver CVE patch-status (v2)

cyvidia_mod_nvidia_cve() {
  local ver=""
  if cyvidia_is_fixture_mode; then
    local vf
    vf="$(cyvidia_host_path /var/log/cyvidia-fixture/nvidia-version.txt)"
    [[ -f "${vf}" ]] && ver="$(tr -d ' \r\n' <"${vf}")"
  elif command -v nvidia-smi >/dev/null 2>&1; then
    ver="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -n1 | tr -d ' ' || true)"
  fi

  if [[ -z "${ver}" ]]; then
    cyvidia_finding_add Info nvidia_cve "NVIDIA driver version unavailable" "CVE compare skipped" "" "cve_update" "nvidia-cves.json" low
    return 0
  fi

  cyvidia_py "${CYVIDIA_ROOT_NATIVE}/python/cyvidia_cve_match.py" --version "${ver}" --pack "$(cyvidia_native_path "${CYVIDIA_ROOT}/iocs/nvidia-cves.json")" \
    | while IFS=$'\t' read -r sev title detail evidence; do
        [[ -z "${sev:-}" ]] && continue
        cyvidia_finding_add "${sev}" nvidia_cve "${title}" "${detail}" "${evidence}" "cve_update" "nvidia-cves.json" medium
      done
}
