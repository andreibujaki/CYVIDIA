#!/usr/bin/env bash
# systemd unit hunt for netns / miner / tor helpers

cyvidia_mod_systemd() {
  local hints
  hints="$(cyvidia_py -c "import json,pathlib; p=json.loads(pathlib.Path(r'${CYVIDIA_ROOT_NATIVE}/iocs/sansar.json').read_text(encoding='utf-8')); print(' '.join(p.get('systemd_unit_hints',[])))")"

  if cyvidia_is_fixture_mode; then
    local unit_dir
    unit_dir="$(cyvidia_host_path /etc/systemd/system)"
    if [[ -d "${unit_dir}" ]]; then
      local f
      for f in "${unit_dir}"/*; do
        [[ -f "${f}" ]] || continue
        local base
        base="$(basename "${f}")"
        local h
        for h in ${hints}; do
          if [[ "${base}" == *"${h}"* ]]; then
            cyvidia_finding_add High systemd "Suspicious unit: ${base}" "Name matches IOC hint ${h}" "${f}" "disable_units" "sansar.json" high "disk_ioc_or_rootkit"
          fi
        done
      done
    fi
    return 0
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    cyvidia_finding_add Info systemd "systemctl unavailable" "Skipped unit enumeration" "" "" "" low
    return 0
  fi

  local h
  for h in ${hints}; do
    local matches
    matches="$(systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -i "${h}" || true)"
    if [[ -n "${matches}" ]]; then
      while IFS= read -r u; do
        [[ -z "${u}" ]] && continue
        cyvidia_finding_add High systemd "Suspicious unit: ${u}" "Name matches IOC hint ${h}" "${u}" "disable_units" "sansar.json" medium "disk_ioc_or_rootkit"
      done <<<"${matches}"
    fi
  done
}
