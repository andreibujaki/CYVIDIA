#!/usr/bin/env bash
# Consent file grant/revoke/list

CYVIDIA_CONSENT_FILE="${CYVIDIA_CONSENT_FILE:-/etc/cyvidia/consent.json}"

cyvidia_consent_path() {
  if cyvidia_is_fixture_mode; then
    echo "$(cyvidia_host_path /etc/cyvidia/consent.json)"
  else
    echo "${CYVIDIA_CONSENT_FILE}"
  fi
}

cyvidia_consent_list() {
  local p
  p="$(cyvidia_consent_path)"
  if [[ ! -f "${p}" ]]; then
    echo "No consent file at ${p}"
    return 0
  fi
  cyvidia_py -m json.tool "${p}"
}

cyvidia_consent_revoke() {
  local p
  p="$(cyvidia_consent_path)"
  rm -f "${p}"
  echo "Revoked ${p}"
}

cyvidia_consent_grant() {
  local issuer="${1:-operator}"
  local hours="${2:-24}"
  local actions="${3:-stop_processes,quarantine,nvml_restore,rootkit_remove,ssh_key_cleanup,ray_harden,cve_update,disable_units}"
  local p
  p="$(cyvidia_consent_path)"
  mkdir -p "$(dirname "${p}")"
  cyvidia_py - "$p" "$(cyvidia_hostname)" "${issuer}" "${hours}" "${actions}" <<'PY'
import json, sys, datetime
path, host, issuer, hours, actions = sys.argv[1:]
now = datetime.datetime.now(datetime.timezone.utc)
exp = now + datetime.timedelta(hours=int(hours))
doc = {
  "schema_version": "0.1.0",
  "hostname": host,
  "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
  "expires_at": exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
  "issuer": issuer,
  "allowed_actions": [a for a in actions.split(",") if a],
  "hmac": None,
  "notes": "v1 stores hmac field only; verification not required",
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(path)
PY
  if ! cyvidia_is_fixture_mode; then
    chmod 600 "${p}" 2>/dev/null || true
    chown root:root "${p}" 2>/dev/null || true
  fi
  echo "Granted consent at ${p}"
}

cyvidia_consent_validate() {
  local p
  p="$(cyvidia_consent_path)"
  cyvidia_py - "$p" "$(cyvidia_hostname)" <<'PY'
import json, sys, datetime
path, host = sys.argv[1:]
try:
    doc = json.load(open(path, encoding="utf-8"))
except FileNotFoundError:
    print("missing")
    sys.exit(3)
if doc.get("hostname") != host:
    print("hostname_mismatch")
    sys.exit(3)
exp = datetime.datetime.strptime(doc["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
now = datetime.datetime.now(datetime.timezone.utc)
if now > exp:
    print("expired")
    sys.exit(3)
print("ok")
print(",".join(doc.get("allowed_actions", [])))
PY
}
