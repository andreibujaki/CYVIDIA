#!/usr/bin/env bash
# Quarantine helpers

cyvidia_quarantine_root() {
  if cyvidia_is_fixture_mode; then
    echo "$(cyvidia_host_path /var/lib/cyvidia/quarantine)"
  else
    echo "/var/lib/cyvidia/quarantine"
  fi
}

cyvidia_quarantine_begin() {
  local plan_id="$1"
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local qdir
  qdir="$(cyvidia_quarantine_root)/${ts}"
  mkdir -p "${qdir}/tree"
  cat >"${qdir}/metadata.json" <<EOF
{
  "plan_id": "${plan_id}",
  "timestamp": "${ts}",
  "hostname": "$(cyvidia_hostname)",
  "tool_version": "${CYVIDIA_VERSION}",
  "items": []
}
EOF
  cat >"${qdir}/ROLLBACK.md" <<EOF
# CYVIDIA rollback notes

Quarantine: ${qdir}

Restore files from \`tree/\` preserving relative paths. Review metadata.json and rollback.json before restore.
EOF
  echo '{"steps":[]}' >"${qdir}/rollback.json"
  echo "${qdir}"
}

# Map a concrete path back to logical host path (strip fixture root when present).
cyvidia_logical_host_path() {
  local src="$1"
  if cyvidia_is_fixture_mode && [[ -n "${CYVIDIA_FIXTURE_ROOT}" ]]; then
    local prefix="${CYVIDIA_FIXTURE_ROOT}"
    if [[ "${src}" == "${prefix}"* ]]; then
      local rest="${src#"${prefix}"}"
      [[ "${rest}" == "" ]] && rest="/"
      [[ "${rest}" != /* ]] && rest="/${rest}"
      echo "${rest}"
      return 0
    fi
  fi
  echo "${src}"
}

cyvidia_quarantine_file() {
  local qdir="$1"
  local src="$2"
  [[ -e "${src}" ]] || return 0

  local logical
  logical="$(cyvidia_logical_host_path "${src}")"
  local rel="${logical#/}"
  local dest="${qdir}/tree/${rel}"
  mkdir -p "$(dirname "${dest}")"
  cp -a "${src}" "${dest}" 2>/dev/null || cp -r "${src}" "${dest}"

  local h
  h="$(cyvidia_sha256_file "${src}" 2>/dev/null || echo unknown)"
  local meta_n rb_n
  meta_n="$(cyvidia_native_path "${qdir}/metadata.json")"
  rb_n="$(cyvidia_native_path "${qdir}/rollback.json")"
  local dest_n
  dest_n="$(cyvidia_native_path "${dest}")"

  cyvidia_py - "$meta_n" "$logical" "$h" <<'PY'
import json,sys
meta, src, h = sys.argv[1:]
doc=json.load(open(meta,encoding="utf-8"))
doc.setdefault("items", []).append({"path": src, "sha256_before": h})
json.dump(doc, open(meta,"w",encoding="utf-8"), indent=2)
print("", end="")
PY
  cyvidia_py - "$rb_n" "$logical" "$dest_n" <<'PY'
import json,sys
rb, src, dest = sys.argv[1:]
doc=json.load(open(rb,encoding="utf-8"))
doc.setdefault("steps", []).append({
  "action": "restore_file",
  "from": dest,
  "to": src,
  "commands": [f"cp -a '{dest}' '{src}'"]
})
json.dump(doc, open(rb,"w",encoding="utf-8"), indent=2)
PY
  echo "Quarantined ${logical} -> ${dest}"
}
