#!/usr/bin/env bash
# SANSAR filesystem IOC hunt

cyvidia_mod_sansar_fs() {
  local pack="${CYVIDIA_ROOT}/iocs/sansar.json"
  [[ -f "${pack}" ]] || { cyvidia_finding_add Info sansar_fs "IOC pack missing" "${pack}" "" "" "sansar.json" low; return 0; }
  local pack_n fix_n
  pack_n="$(cyvidia_native_path "${pack}")"
  fix_n=""
  [[ -n "${CYVIDIA_FIXTURE_ROOT:-}" ]] && fix_n="$(cyvidia_native_path "${CYVIDIA_FIXTURE_ROOT}")"

  cyvidia_py - "$pack_n" "$fix_n" <<'PY' | while IFS=$'\t' read -r sev title detail evidence labels; do
import json, os, sys, pathlib
pack = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
root = sys.argv[2] or ""

def hp(p):
    if not root:
        return p
    return str(pathlib.Path(root) / pathlib.Path(p.lstrip("/")))

for path in pack.get("paths", []):
    p = hp(path.rstrip("/") if path.endswith("/") else path)
    # directories in pack end with /
    check = hp(path) if path.endswith("/") else hp(path)
    if path.endswith("/"):
        if pathlib.Path(check).is_dir():
            print("\t".join(["Critical", f"SANSAR path present: {path}", "Toolkit staging/path indicator", check, "disk_ioc,disk_ioc_or_rootkit"]))
    else:
        if pathlib.Path(check).exists():
            print("\t".join(["Critical", f"SANSAR path present: {path}", "Toolkit file indicator", check, "disk_ioc,disk_ioc_or_rootkit"]))

hash_index = {e["hash"].lower(): e for e in pack.get("sha256", [])}
# Hash any existing named binaries under /opt/vadi_/
base = pathlib.Path(hp("/opt/vadi_/"))
if base.is_dir():
    for child in base.rglob("*"):
        if not child.is_file():
            continue
        try:
            import hashlib
            h = hashlib.sha256(child.read_bytes()).hexdigest()
        except OSError:
            continue
        if h in hash_index:
            meta = hash_index[h]
            print("\t".join(["Critical", f"Hash match: {meta.get('name')}", meta.get("role",""), f"{child}:{h}", f"disk_ioc,disk_ioc_or_rootkit,sha256:{h}"]))
PY
    [[ -z "${sev:-}" ]] && continue
    cyvidia_finding_add "${sev}" sansar_fs "${title}" "${detail}" "${evidence}" "quarantine" "sansar.json" high "${labels}"
  done
}
