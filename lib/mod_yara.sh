#!/usr/bin/env bash
# Optional YARA scan

cyvidia_mod_yara() {
  if ! command -v yara >/dev/null 2>&1; then
    cyvidia_finding_add Info yara "yara binary not present" "Optional scan skipped; see yara/ATTRIBUTION.md" "" "" "" low
    return 0
  fi
  local rules="${CYVIDIA_ROOT}/yara/sansar_netns.yar"
  [[ -f "${rules}" ]] || { cyvidia_finding_add Info yara "rules missing" "${rules}" "" "" "" low; return 0; }

  local roots=()
  if cyvidia_is_fixture_mode; then
    roots+=("$(cyvidia_host_path /opt/vadi_)")
  else
    roots+=(/opt/vadi_ /usr/src /usr/lib)
  fi

  local r
  for r in "${roots[@]}"; do
    [[ -e "${r}" ]] || continue
    local out
    out="$(yara -r "${rules}" "${r}" 2>/dev/null || true)"
    if [[ -n "${out}" ]]; then
      cyvidia_finding_add Critical yara "YARA rule matched" "${out}" "${r}" "quarantine" "yara" high "disk_ioc_or_rootkit"
    fi
  done
}
