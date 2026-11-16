#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIX="${ROOT}/tests/fixtures/host_sansar"
OUT="$(mktemp)"
export CYVIDIA_FIXTURE_ROOT="${FIX}"
chmod +x "${ROOT}/bin/cyvidia" || true

# Prefer a real Python if Git Bash's python3 is a Windows Store stub
if [[ -z "${CYVIDIA_PYTHON:-}" ]]; then
  if command -v cygpath >/dev/null 2>&1; then
    for candidate in "/c/Program Files/Python313/python.exe" "/c/Program Files/Python312/python.exe" "/c/Program Files/Python311/python.exe"; do
      if [[ -x "${candidate}" ]]; then
        export CYVIDIA_PYTHON="${candidate}"
        break
      fi
    done
  fi
fi

set +e
"${ROOT}/bin/cyvidia" hunt --output-json "${OUT}"
rc=$?
set -e

echo "hunt_rc=${rc} out=${OUT}"

PYBIN="${CYVIDIA_PYTHON:-}"
if [[ -z "${PYBIN}" ]]; then
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys' >/dev/null 2>&1; then
    PYBIN=python3
  elif command -v python >/dev/null 2>&1 && python -c 'import sys' >/dev/null 2>&1; then
    PYBIN=python
  else
    echo "ERROR: no working Python for assertion" >&2
    exit 1
  fi
fi

OUT_NATIVE="${OUT}"
if command -v cygpath >/dev/null 2>&1; then
  OUT_NATIVE="$(cygpath -w "${OUT}")"
fi

"${PYBIN}" - "${OUT_NATIVE}" "${rc}" <<'PY'
import json, sys
path, rc = sys.argv[1], int(sys.argv[2])
doc = json.load(open(path, encoding="utf-8"))
findings = doc.get("findings", [])
print("count", len(findings))
print("correlation", doc.get("correlation"))
assert findings, "expected findings"
assert any(f.get("severity") in ("Critical", "High") for f in findings), "expected Critical/High"
assert rc == 2, f"infected fixture should exit 2, got {rc}"
print("fixture hunt OK")
PY
