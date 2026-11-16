#!/usr/bin/env bash
# Pluggable Tor-linked miner behavior hunt

cyvidia_mod_tor_miners() {
  local pack="${CYVIDIA_ROOT}/iocs/tor-miners.json"
  local sansar="${CYVIDIA_ROOT}/iocs/sansar.json"
  local pack_n sansar_n fix_n
  pack_n="$(cyvidia_native_path "${pack}")"
  sansar_n="$(cyvidia_native_path "${sansar}")"
  fix_n=""
  [[ -n "${CYVIDIA_FIXTURE_ROOT:-}" ]] && fix_n="$(cyvidia_native_path "${CYVIDIA_FIXTURE_ROOT}")"

  cyvidia_py - "$pack_n" "$sansar_n" "$fix_n" <<'PY' | while IFS=$'\t' read -r sev title detail evidence labels; do
import json, pathlib, sys
pack = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
sansar = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
root = sys.argv[3] or ""

def hp(p):
    if not root:
        return p
    return str(pathlib.Path(root) / pathlib.Path(p.lstrip("/")))

names = set()
for fam in pack.get("families", []):
    names.update(fam.get("names", []))
names.update(sansar.get("names", []))

search_roots = [hp("/opt/vadi_"), hp("/usr/local/bin"), hp("/tmp")]
hits = []
for sr in search_roots:
    p = pathlib.Path(sr)
    if not p.exists():
        continue
    for child in p.rglob("*"):
        if child.is_file() and child.name in names:
            hits.append(str(child))

signals = pack.get("tor_coupling_signals", [])
coupling = []
base = pathlib.Path(hp("/opt/vadi_/"))
if base.is_dir():
    for child in base.rglob("*"):
        name = child.name.lower()
        text_hit = False
        if any(sig.lower() in name for sig in signals):
            coupling.append(str(child))
            continue
        if child.is_file() and child.stat().st_size < 1_000_000:
            try:
                data = child.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            if any(sig.lower() in data for sig in signals):
                coupling.append(str(child))

for h in hits:
    print("\t".join(["High", f"Miner-named binary: {pathlib.Path(h).name}", "Name matches tor-miners/SANSAR pack", h, "disk_ioc"]))
if hits and coupling:
    print("\t".join(["Critical", "Miner binaries coupled with Tor helper artifacts", f"coupling={len(coupling)}", ";".join(coupling[:10]), "disk_ioc,disk_ioc_or_rootkit"]))
elif coupling and not hits:
    print("\t".join(["Medium", "Tor helper artifacts without miner name hit", "Possible preparatory staging", ";".join(coupling[:10]), ""]))
PY
    [[ -z "${sev:-}" ]] && continue
    cyvidia_finding_add "${sev}" tor_miners "${title}" "${detail}" "${evidence}" "quarantine" "tor-miners.json" medium "${labels}"
  done
}
