#!/usr/bin/env bash
# Build remediation plan from findings JSON

cyvidia_plan_from_findings() {
  local findings_json="$1"
  local out="$2"
  cyvidia_py - "$findings_json" "$out" <<'PY'
import json, sys, uuid
src, out = sys.argv[1:]
doc = json.load(open(src, encoding="utf-8"))
actions = []
for f in doc.get("findings", []):
    hint = f.get("remediation_hint") or ""
    if not hint:
        continue
    actions.append({
        "finding_id": f.get("finding_id"),
        "severity": f.get("severity"),
        "module": f.get("module"),
        "title": f.get("title"),
        "action": hint,
        "evidence": f.get("evidence"),
    })
plan = {
    "plan_id": str(uuid.uuid4()),
    "hostname": doc.get("hostname"),
    "scan_id": doc.get("scan_id"),
    "tool_version": doc.get("tool_version"),
    "actions": actions,
}
open(out, "w", encoding="utf-8").write(json.dumps(plan, indent=2) + "\n")
print(out)
print(f"plan_id={plan['plan_id']}")
print(f"actions={len(actions)}")
for a in actions:
    print(f" - [{a['severity']}] {a['action']}: {a['title']}")
PY
}
