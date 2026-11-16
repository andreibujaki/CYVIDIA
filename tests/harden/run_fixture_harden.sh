#!/usr/bin/env bash
# Production checkpoint: hunt → plan → consent → execute(quarantine) → verify
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIX="${ROOT}/tests/fixtures/host_sansar"
WORKDIR="$(mktemp -d)"
export CYVIDIA_FIXTURE_ROOT="${FIX}"
export CYVIDIA_FIXTURE_MUTATE=0
export CYVIDIA_CONSENT_FILE="${WORKDIR}/consent.json"
# consent helper uses fixture path when FIXTURE_ROOT set — override via host path under fixture
mkdir -p "${FIX}/etc/cyvidia" "${FIX}/var/lib/cyvidia/quarantine" "${FIX}/run"
export CYVIDIA_LOCK_FILE="${FIX}/run/cyvidia.lock"

if [[ -z "${CYVIDIA_PYTHON:-}" ]] && command -v cygpath >/dev/null 2>&1; then
  for candidate in "/c/Program Files/Python313/python.exe" "/c/Program Files/Python312/python.exe"; do
    if [[ -x "${candidate}" ]]; then export CYVIDIA_PYTHON="${candidate}"; break; fi
  done
fi

chmod +x "${ROOT}/bin/cyvidia" || true
FINDINGS="${WORKDIR}/findings.json"
PLAN="${WORKDIR}/plan.json"

echo "== 1) hunt =="
set +e
"${ROOT}/bin/cyvidia" hunt --output-json "${FINDINGS}" --report-md "${WORKDIR}/report.md"
hrc=$?
set -e
echo "hunt_rc=${hrc}"
[[ "${hrc}" -eq 2 ]] || { echo "expected hunt exit 2"; exit 1; }

echo "== 2) harden --plan =="
"${ROOT}/bin/cyvidia" harden --plan --findings "${FINDINGS}" | tee "${WORKDIR}/plan.out"
# Extract plan path from output
PLAN_PATH="$(grep -E 'Plan written to |^/' "${WORKDIR}/plan.out" | awk '{print $NF}' | tail -n1)"
# plan_from_findings prints path via cyvidia_plan — also written as mktemp inside harden
# Re-create deterministic plan file for execute
source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/plan.sh"
cyvidia_plan_from_findings "${FINDINGS}" "${PLAN}"
echo "using_plan=${PLAN}"

echo "== 3) consent grant =="
# Grant into fixture /etc/cyvidia/consent.json
source "${ROOT}/lib/consent.sh"
cyvidia_consent_grant "fixture-operator" 24

echo "== 4) harden --execute (quarantine copies; no mutate) =="
set +e
"${ROOT}/bin/cyvidia" harden --execute --plan-file "${PLAN}" | tee "${WORKDIR}/exec.out"
erc=$?
set -e
echo "execute_rc=${erc}"
[[ "${erc}" -eq 0 ]] || { echo "execute failed"; exit 1; }
grep -q 'QUARANTINE=' "${WORKDIR}/exec.out"
QDIR="$(grep '^QUARANTINE=' "${WORKDIR}/exec.out" | tail -n1 | cut -d= -f2-)"
[[ -d "${QDIR}" ]] || QDIR="$(grep -E '/var/lib/cyvidia/quarantine/|/quarantine/' "${WORKDIR}/exec.out" | tail -n1)"
# Resolve from fixture tree listing
if [[ ! -d "${QDIR:-/nonexistent}" ]]; then
  QDIR="$(ls -1d "${FIX}/var/lib/cyvidia/quarantine/"* 2>/dev/null | tail -n1 || true)"
fi
[[ -n "${QDIR}" && -d "${QDIR}" ]] || { echo "quarantine dir missing"; exit 1; }
[[ -f "${QDIR}/metadata.json" ]] || { echo "metadata.json missing"; exit 1; }
[[ -f "${QDIR}/ROLLBACK.md" ]] || { echo "ROLLBACK.md missing"; exit 1; }
[[ -f "${QDIR}/rollback.json" ]] || { echo "rollback.json missing"; exit 1; }
echo "quarantine_ok=${QDIR}"

echo "== 5) originals preserved (mutate=0) =="
[[ -d "${FIX}/opt/vadi_" ]] || { echo "fixture originals should remain when MUTATE=0"; exit 1; }

echo "fixture harden checkpoint OK"
echo "WORK=${WORKDIR}"
echo "FINDINGS=${FINDINGS}"
echo "PLAN=${PLAN}"
echo "QUARANTINE=${QDIR}"
