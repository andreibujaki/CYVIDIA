#!/usr/bin/env bash
# Expected-vs-observed process hiding awareness

cyvidia_mod_hiding() {
  local names=("sansar" "kurt" "tilki" "lyrebird" "netns" "xmrig")
  local disk_hit=0
  local runtime_missing=0

  local base
  base="$(cyvidia_host_path /opt/vadi_)"
  if [[ -d "${base}" ]]; then
    local n
    for n in "${names[@]}"; do
      if [[ -e "${base}/${n}" ]]; then
        disk_hit=1
        if cyvidia_is_fixture_mode; then
          local procs
          procs="$(cyvidia_host_path /var/log/cyvidia-fixture/ps.txt)"
          if [[ -f "${procs}" ]] && ! grep -qw "${n}" "${procs}"; then
            runtime_missing=1
            cyvidia_finding_add High hiding "Disk binary ${n} not listed in fixture process list" "Possible process hiding" "${base}/${n}" "rootkit_remove" "sansar.json" high "disk_ioc,runtime_missing"
          fi
        else
          if ! pidof -q "${n}" 2>/dev/null && ! pgrep -x "${n}" >/dev/null 2>&1; then
            # Presence on disk without process is normal if not running; only escalate with other rootkit signals later via correlation.
            cyvidia_finding_add Info hiding "Binary on disk not currently running: ${n}" "Informational unless combined with rootkit indicators" "${base}/${n}" "" "sansar.json" low "disk_ioc"
          fi
        fi
      fi
    done
  fi

  if [[ "${disk_hit}" -eq 1 && "${runtime_missing}" -eq 1 ]]; then
    cyvidia_finding_add High hiding "Expected-vs-observed mismatch for miner binaries" "Disk presence without process list visibility" "${base}" "rootkit_remove" "sansar.json" high "disk_ioc,runtime_missing"
  fi
}
