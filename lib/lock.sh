#!/usr/bin/env bash
# Root lockfile for harden/remediate

CYVIDIA_LOCK_FILE="${CYVIDIA_LOCK_FILE:-/run/cyvidia.lock}"

cyvidia_lock_acquire() {
  local lock="${CYVIDIA_LOCK_FILE}"
  if cyvidia_is_fixture_mode; then
    lock="$(cyvidia_host_path /run/cyvidia.lock)"
    mkdir -p "$(dirname "${lock}")"
  fi
  if [[ -f "${lock}" ]]; then
    local oldpid
    oldpid="$(cat "${lock}" 2>/dev/null || true)"
    if [[ -n "${oldpid}" ]] && kill -0 "${oldpid}" 2>/dev/null; then
      cyvidia_die "lock held by PID ${oldpid} (${lock})"
    fi
    cyvidia_warn "stale lock found; replacing"
  fi
  echo "$$" >"${lock}"
  CYVIDIA_LOCK_FILE="${lock}"
  export CYVIDIA_LOCK_FILE
}

cyvidia_lock_release() {
  local lock="${CYVIDIA_LOCK_FILE}"
  if [[ -f "${lock}" ]]; then
    local oldpid
    oldpid="$(cat "${lock}" 2>/dev/null || true)"
    if [[ "${oldpid}" == "$$" ]]; then
      rm -f "${lock}"
    fi
  fi
}
