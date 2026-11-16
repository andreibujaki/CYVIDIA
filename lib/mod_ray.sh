#!/usr/bin/env bash
# Ray dashboard vs job-agent exposure hunt (fixture + live)

cyvidia_mod_ray() {
  local ss_file="" jobs_log=""
  if cyvidia_is_fixture_mode; then
    ss_file="$(cyvidia_host_path /var/log/cyvidia-fixture/ss-listen.txt)"
    jobs_log="$(cyvidia_host_path /var/log/ray/job-agent.log)"
  else
    # Capture live listen table for analysis
    if command -v ss >/dev/null 2>&1; then
      ss_file="$(mktemp)"
      ss -lntp 2>/dev/null >"${ss_file}" || true
    fi
    # Common Ray log locations
    for candidate in \
      /tmp/ray/session_latest/logs/job-agent.log \
      /tmp/ray/session_latest/logs/dashboard.log \
      /var/log/ray/job-agent.log; do
      if [[ -f "${candidate}" ]]; then
        jobs_log="${candidate}"
        break
      fi
    done
  fi

  if [[ -n "${ss_file}" && -f "${ss_file}" ]]; then
    if grep -E '0\.0\.0\.0:8265|:::8265|\*:8265|:8265' "${ss_file}" 2>/dev/null | grep -vE '127\.0\.0\.1|\[::1\]' >/dev/null 2>&1; then
      cyvidia_finding_add High ray "Ray port 8265 listening on non-loopback" "Dashboard/Jobs port exposed" "${ss_file}" "ray_harden" "" high "ray_job_agent_exposed"
    fi
    if grep -Ei 'job.?agent|ray::JobAgent|/api/jobs|gcs_server|raylet' "${ss_file}" >/dev/null 2>&1 && grep -E '0\.0\.0\.0|:::' "${ss_file}" >/dev/null 2>&1; then
      cyvidia_finding_add Critical ray "Ray job-related listener appears non-loopback" "Unauthenticated Jobs API is a known initial-access class" "${ss_file}" "ray_harden" "" high "ray_job_agent_exposed"
    fi
    if grep -E '127\.0\.0\.1:8265' "${ss_file}" >/dev/null 2>&1 && grep -Ei 'job' "${ss_file}" | grep -E '0\.0\.0\.0|:::' >/dev/null 2>&1; then
      cyvidia_finding_add Critical ray "Dashboard loopback-only but job agent non-loopback" "Matches SANSAR/ShadowRay-class exposure pattern" "${ss_file}" "ray_harden" "" high "ray_job_agent_exposed"
    fi
  elif ! cyvidia_is_fixture_mode; then
    cyvidia_finding_add Info ray "ss unavailable or no listen snapshot" "Install iproute2 for live Ray socket checks" "" "" "" low
  fi

  if [[ -n "${jobs_log}" && -f "${jobs_log}" ]]; then
    if grep -Ei 'nvidia-smi' "${jobs_log}" >/dev/null 2>&1; then
      cyvidia_finding_add High ray "Ray job history references nvidia-smi" "Possible GPU inventory exfil job" "${jobs_log}" "ray_harden" "" medium "ray_job_agent_exposed"
    fi
    if grep -Ei 'reverse.?shell|socket\.connect|/dev/tcp|bash -i' "${jobs_log}" >/dev/null 2>&1; then
      cyvidia_finding_add Critical ray "Ray job history suggests reverse shell" "Suspicious job payload pattern" "${jobs_log}" "ray_harden" "" high "ray_job_agent_exposed"
    fi
  fi

  # Auth / config hints
  local ray_dirs=("/etc/ray" "/home/ray" )
  if cyvidia_is_fixture_mode; then
    ray_dirs=("$(cyvidia_host_path /etc/ray)")
  fi
  local rd
  for rd in "${ray_dirs[@]}"; do
    [[ -d "${rd}" ]] || continue
    if [[ ! -f "${rd}/auth.conf" && ! -f "${rd}/ray_auth" ]]; then
      cyvidia_finding_add Medium ray "No Ray auth config under ${rd}" "Job submission may be unauthenticated" "${rd}" "ray_harden" "" low "ray_job_agent_exposed"
    fi
  done

  if [[ -n "${ss_file}" && ! cyvidia_is_fixture_mode ]]; then
    rm -f "${ss_file}"
  fi
}
