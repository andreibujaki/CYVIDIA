#!/usr/bin/env bash
# CYVIDIA common helpers — sourced by bin/cyvidia and lib modules
set -euo pipefail

CYVIDIA_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CYVIDIA_VERSION="${CYVIDIA_VERSION:-0.1.0}"
CYVIDIA_FINDINGS_FILE="${CYVIDIA_FINDINGS_FILE:-}"
CYVIDIA_SCAN_ID="${CYVIDIA_SCAN_ID:-}"
CYVIDIA_FIXTURE_ROOT="${CYVIDIA_FIXTURE_ROOT:-}"
CYVIDIA_CONFIG="${CYVIDIA_CONFIG:-/etc/cyvidia/config.json}"

# Native OS path for Windows Python launched from Git Bash
cyvidia_native_path() {
  local p="$1"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$p"
  else
    echo "$p"
  fi
}
CYVIDIA_ROOT_NATIVE="$(cyvidia_native_path "${CYVIDIA_ROOT}")"

cyvidia_die() {
  echo "ERROR: $*" >&2
  exit 1
}

cyvidia_warn() {
  echo "WARN: $*" >&2
}

cyvidia_info() {
  echo "INFO: $*" >&2
}

cyvidia_require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    cyvidia_warn "not root — reduced coverage"
    return 1
  fi
  return 0
}

cyvidia_utc_now() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

cyvidia_hostname() {
  hostname -f 2>/dev/null || hostname
}

cyvidia_is_fixture_mode() {
  [[ -n "${CYVIDIA_FIXTURE_ROOT}" ]]
}

# Resolve a host path, optionally under fixture root for tests.
cyvidia_host_path() {
  local rel="$1"
  if cyvidia_is_fixture_mode; then
    echo "${CYVIDIA_FIXTURE_ROOT}${rel}"
  else
    echo "${rel}"
  fi
}

cyvidia_python() {
  if [[ -n "${CYVIDIA_PYTHON:-}" ]]; then
    echo "${CYVIDIA_PYTHON}"
    return 0
  fi
  # Prefer working interpreters (Git Bash on Windows often has a broken python3 stub).
  local c
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c "import sys" >/dev/null 2>&1; then
      echo "$c"
      return 0
    fi
  done
  # Windows py launcher
  if command -v py >/dev/null 2>&1 && py -3 -c "import sys" >/dev/null 2>&1; then
    echo "py -3"
    return 0
  fi
  cyvidia_die "Python 3 not found (tried python3, python, py)"
}

cyvidia_py() {
  local py
  py="$(cyvidia_python)"
  if [[ "${py}" == "py -3" ]]; then
    py -3 "$@"
  else
    "${py}" "$@"
  fi
}

cyvidia_sha256_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
  else
    cyvidia_py -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$f"
  fi
}
