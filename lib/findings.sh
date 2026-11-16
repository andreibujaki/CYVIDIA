#!/usr/bin/env bash
# NDJSON finding emitter for CYVIDIA hunt modules
# shellcheck source=lib/common.sh
# Expected: CYVIDIA_FINDINGS_FILE set to a writable path

cyvidia_json_escape() {
  cyvidia_py -c 'import json,sys; print(json.dumps(sys.stdin.read()[:-1] if False else sys.argv[1]))' "$1"
}

cyvidia_finding_add() {
  local severity="${1//$'\r'/}"
  local module="${2//$'\r'/}"
  local title="${3//$'\r'/}"
  local detail="${4:-}"
  local evidence="${5:-}"
  local remediation_hint="${6:-}"
  local ioc_refs_csv="${7:-}"
  local confidence="${8:-medium}"
  local labels_csv="${9:-}"
  detail="${detail//$'\r'/}"
  evidence="${evidence//$'\r'/}"
  remediation_hint="${remediation_hint//$'\r'/}"
  ioc_refs_csv="${ioc_refs_csv//$'\r'/}"
  confidence="${confidence//$'\r'/}"
  labels_csv="${labels_csv//$'\r'/}"
  labels_csv="${labels_csv//$'\r'/}"

  if [[ -z "${CYVIDIA_FINDINGS_FILE:-}" ]]; then
    cyvidia_warn "CYVIDIA_FINDINGS_FILE unset; finding dropped: ${title}"
    return 0
  fi

  local finding_id
  finding_id="$(cyvidia_py -c "import uuid; print(uuid.uuid4())")"
  local ts
  ts="$(cyvidia_utc_now)"

  cyvidia_py - "$CYVIDIA_FINDINGS_FILE" "$finding_id" "$severity" "$module" "$title" "$detail" "$evidence" "$remediation_hint" "$ioc_refs_csv" "$confidence" "$labels_csv" "$ts" <<'PY'
import json, sys
path, fid, severity, module, title, detail, evidence, hint, iocs, conf, labels, ts = sys.argv[1:]
obj = {
    "schema_version": "0.1.0",
    "finding_id": fid,
    "module": module,
    "severity": severity,
    "confidence": conf,
    "title": title,
    "detail": detail,
    "evidence": evidence,
    "remediation_hint": hint,
    "ioc_refs": [x for x in iocs.split(",") if x],
    "labels": [x for x in labels.split(",") if x],
    "timestamp": ts,
}
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps(obj, ensure_ascii=False) + "\n")
print(f"[{severity}] {module}: {title}", file=sys.stderr)
if detail:
    print(f"        {detail}", file=sys.stderr)
PY
}
