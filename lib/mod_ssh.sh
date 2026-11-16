#!/usr/bin/env bash
# SSH authorized_keys anomalies for Ray/service accounts

cyvidia_mod_ssh() {
  local homes=()
  if cyvidia_is_fixture_mode; then
    local fixture_home
    fixture_home="$(cyvidia_host_path /home)"
    if [[ -d "${fixture_home}" ]]; then
      local d
      for d in "${fixture_home}"/*; do
        [[ -d "${d}" ]] && homes+=("${d}")
      done
    fi
    local root_home
    root_home="$(cyvidia_host_path /root)"
    [[ -d "${root_home}" ]] && homes+=("${root_home}")
  else
    homes+=("/root")
    local ent
    while IFS=: read -r user _ uid _ _ home _; do
      if [[ "${uid}" -ge 1000 || "${user}" == ray* || "${user}" == *"ray"* ]]; then
        homes+=("${home}")
      fi
    done < /etc/passwd
  fi

  local home
  for home in "${homes[@]}"; do
    local keys="${home}/.ssh/authorized_keys"
    [[ -f "${keys}" ]] || continue
    local lines
    lines="$(grep -cvE '^\s*(#|$)' "${keys}" 2>/dev/null || echo 0)"
    if [[ "${home}" == *ray* || "${home}" == */ray || "$(basename "${home}")" == ray* ]]; then
      if [[ "${lines}" -gt 0 ]]; then
        cyvidia_finding_add High ssh "authorized_keys present on Ray-related account" "Review unexpected keys" "${keys}" "ssh_key_cleanup" "" medium "ray_job_agent_exposed"
      fi
    fi
    # Flag keys mentioning unusual comments
    if grep -Ei 'sansar|vadi_|miner|crypto' "${keys}" >/dev/null 2>&1; then
      cyvidia_finding_add Critical ssh "Suspicious authorized_keys comment/content" "Matches hunter keyword heuristics" "${keys}" "ssh_key_cleanup" "" high
    fi
  done
}
