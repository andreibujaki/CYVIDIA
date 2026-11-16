#!/usr/bin/env bash
# Ray dashboard vs job-agent exposure hunt

cyvidia_mod_ray() {
  if cyvidia_is_fixture_mode; then
    local ss_file
    ss_file="$(cyvidia_host_path /var/log/cyvidia-fixture/ss-listen.txt)"
    local jobs_log
    jobs_log="$(cyvidia_host_path /var/log/ray/job-agent.log)"
    if [[ -f "${ss_file}" ]]; then
      if grep -E '0\.0\.0\.0:8265|:::8265|\*:8265' "${ss_file}" >/dev/null 2>&1; then
        cyvidia_finding_add High ray "Ray port 8265 listening on non-loopback" "Dashboard/Jobs port exposed" "${ss_file}" "ray_harden" "" high "ray_job_agent_exposed"
      fi
      if grep -Ei 'job.agent|ray::JobAgent|/api/jobs' "${ss_file}" >/dev/null 2>&1 && grep -E '0\.0\.0\.0|:::' "${ss_file}" >/dev/null 2>&1; then
        cyvidia_finding_add Critical ray "Ray job agent appears internet-reachable" "Unauthenticated Jobs API is a known initial-access class" "${ss_file}" "ray_harden" "" high "ray_job_agent_exposed"
      fi
      if grep -E '127\.0\.0\.1:8265' "${ss_file}" >/dev/null 2>&1 && grep -Ei 'job' "${ss_file}" | grep -E '0\.0\.0\.0|:::' >/dev/null 2>&1; then
        cyvidia_finding_add Critical ray "Dashboard loopback-only but job agent non-loopback" "Matches SANSAR/ShadowRay-class exposure pattern" "${ss_file}" "ray_harden" "" high "ray_job_agent_exposed"
      fi
    fi
    if [[ -f "${jobs_log}" ]]; then
      if grep -Ei 'nvidia-smi' "${jobs_log}" >/dev/null 2>&1; then
        cyvidia_finding_add High ray "Ray job history references nvidia-smi" "Possible GPU inventory exfil job" "${jobs_log}" "ray_harden" "" medium "ray_job_agent_exposed"
      fi
      if grep -Ei 'reverse.?shell|socket\.connect|/dev/tcp|bash -i' "${jobs_log}" >/dev/null 2>&1; then
        cyvidia_finding_add Critical ray "Ray job history suggests reverse shell" "Suspicious job payload pattern" "${jobs_log}" "ray_harden" "" high "ray_job_agent_exposed"
      fi
    fi
    local auth
    auth="$(cyvidia_host_path /etc/ray/auth.conf)"
    if [[ -f "$(cyvidia_host_path /etc/ray)" ]] || [[ -d "$(cyvidia_host_path /etc/ray)" ]]; then
      if [[ ! -f "${auth}" ]]; then
        cyvidia_finding_add Medium ray "No Ray auth.conf found under fixture /etc/ray" "Job submission may be unauthenticated" "$(cyvidia_host_path /etc/ray)" "ray_harden" "" low "ray_job_agent_exposed"
      fi
    fi
    return 0
  fi

  if command -v ss >/dev/null 2>&1; then
    local listen
    listen="$(ss -lntp 2>/dev/null || true)"
    if echo "${listen}" | grep -E ':8265' | grep -vE '127\.0\.0\.1|\[::1\]' >/dev/null 2>&1; then
      cyvidia_finding_add High ray "Port 8265 listening on non-loopback" "Ray dashboard/Jobs port may be exposed" "ss -lntp" "ray_harden" "" medium "ray_job_agent_exposed"
    fi
  fi
}
