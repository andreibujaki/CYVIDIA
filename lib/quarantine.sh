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

cyvidia_quarantine_file() {
  local qdir="$1"
  local src="$2"
  [[ -e "${src}" ]] || return 0
  local rel="${src#/}"
  local dest="${qdir}/tree/${rel}"
  mkdir -p "$(dirname "${dest}")"
  cp -a "${src}" "${dest}" 2>/dev/null || cp -r "${src}" "${dest}"
  local h
  h="$(cyvidia_sha256_file "${src}" 2>/dev/null || echo unknown)"
  cyvidia_py - "$qdir/metadata.json" "$src" "$h" <<'PY'
import json,sys
meta, src, h = sys.argv[1:]
doc=json.load(open(meta,encoding="utf-8"))
doc.setdefault("items", []).append({"path": src, "sha256_before": h})
json.dump(doc, open(meta,"w",encoding="utf-8"), indent=2)
print("", end="")
PY
  cyvidia_py - "$qdir/rollback.json" "$src" "$dest" <<'PY'
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
  echo "Quarantined ${src} -> ${dest}"
}
