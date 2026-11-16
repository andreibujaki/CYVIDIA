#!/usr/bin/env bash
# Secondary GPU telemetry vs NVML idle heuristics

cyvidia_mod_gpu_secondary() {
  local drm
  drm="$(cyvidia_host_path /sys/class/drm)"
  local hwmon
  hwmon="$(cyvidia_host_path /sys/class/hwmon)"
  local smi_out
  smi_out="$(cyvidia_host_path /var/log/cyvidia-fixture/nvidia-smi.txt)"

  local nvml_idle=0
  if [[ -f "${smi_out}" ]]; then
    if grep -Eiq '[[:space:]]0[[:space:]]*%|Utilization.*0' "${smi_out}"; then
      nvml_idle=1
    fi
  elif ! cyvidia_is_fixture_mode && command -v nvidia-smi >/dev/null 2>&1; then
    local live
    live="$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null | head -n1 | tr -d ' ' || true)"
    if [[ "${live}" == "0" ]]; then
      nvml_idle=1
    fi
  fi

  local power_high=0
  local evidence=""

  # Must attempt: sysfs DRM power + hwmon
  if [[ -d "${drm}" ]]; then
    local f
    while IFS= read -r f; do
      [[ -f "${f}" ]] || continue
      local val
      val="$(tr -d ' \n' <"${f}" 2>/dev/null || true)"
      if [[ "${val}" =~ ^[0-9]+$ ]] && [[ "${val}" -gt 50000000 ]]; then
        # microwatts-style readings often huge; treat as activity signal in fixtures via power_high flag files
        power_high=1
        evidence="${evidence};${f}=${val}"
      fi
    done < <(find "${drm}" -type f \( -name 'power1_average' -o -name 'gpu_busy_percent' -o -name '*power*' \) 2>/dev/null | head -n 50)
  else
    cyvidia_finding_add Info gpu_secondary "DRM sysfs not present" "Must-attempt signal skipped" "${drm}" "" "" low
  fi

  if [[ -d "${hwmon}" ]]; then
    local hf
    while IFS= read -r hf; do
      [[ -f "${hf}" ]] || continue
      local hv
      hv="$(tr -d ' \n' <"${hf}" 2>/dev/null || true)"
      if [[ "${hv}" =~ ^[0-9]+$ ]] && [[ "${hv}" -gt 40 ]]; then
        # fixture can set power1_input etc.
        if [[ "${hf}" == *power* ]] && [[ "${hv}" -gt 100000 ]]; then
          power_high=1
          evidence="${evidence};${hf}=${hv}"
        fi
      fi
    done < <(find "${hwmon}" -type f \( -name 'power1_input' -o -name 'power1_average' -o -name 'temp1_input' \) 2>/dev/null | head -n 50)
  else
    cyvidia_finding_add Info gpu_secondary "hwmon sysfs not present" "Must-attempt signal skipped" "${hwmon}" "" "" low
  fi

  # Fixture explicit mismatch marker
  local marker
  marker="$(cyvidia_host_path /var/log/cyvidia-fixture/gpu-mismatch.flag)"
  if [[ -f "${marker}" ]]; then
    nvml_idle=1
    power_high=1
    evidence="${evidence};${marker}"
  fi

  # Best-effort PCIe / BMC
  local pcie
  pcie="$(cyvidia_host_path /sys/bus/pci/devices)"
  if [[ ! -d "${pcie}" ]]; then
    cyvidia_finding_add Info gpu_secondary "PCIe sysfs absent (best-effort skip)" "" "${pcie}" "" "" low
  fi
  local bmc
  bmc="$(cyvidia_host_path /var/log/cyvidia-fixture/bmc-power.txt)"
  if [[ -f "${bmc}" ]]; then
    evidence="${evidence};bmc=$(head -n1 "${bmc}")"
    if grep -Eiq 'high|draw|[5-9][0-9]{2}W' "${bmc}"; then
      power_high=1
    fi
  fi

  if [[ "${nvml_idle}" -eq 1 && "${power_high}" -eq 1 ]]; then
    cyvidia_finding_add High gpu_secondary "NVML looks idle but secondary GPU signals disagree" "Possible NVML telemetry spoof" "${evidence}" "nvml_restore" "sansar.json" high "nvml_spoof_or_mismatch"
  fi
}
