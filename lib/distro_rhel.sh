#!/usr/bin/env bash
# RHEL/Rocky/Alma adapter

cyvidia_pkg_verify_file() {
  local path="$1"
  if command -v rpm >/dev/null 2>&1; then
    rpm -qf "${path}" 2>/dev/null || true
    local pkg
    pkg="$(rpm -qf "${path}" 2>/dev/null || true)"
    if [[ -n "${pkg}" && "${pkg}" != *"not owned"* ]]; then
      rpm --verify "${pkg}" 2>/dev/null || true
    fi
  fi
}

cyvidia_nvidia_reinstall_cmds() {
  cat <<'EOF'
# RHEL/Rocky/Alma — review before running
sudo dnf reinstall -y nvidia-driver nvidia-driver-cuda 2>/dev/null || \
  sudo dnf reinstall -y libnvidia-ml 2>/dev/null || \
  echo "Adjust package names for your NVIDIA CUDA repo / local RPM install"
EOF
}

cyvidia_initramfs_rebuild_cmd() {
  echo "dracut -f"
}

cyvidia_detect_nvidia_runfile_residue() {
  local roots=("/usr/bin/nvidia-uninstall" "/usr/lib/nvidia" "/var/lib/nvidia")
  local hit=0
  local r
  for r in "${roots[@]}"; do
    local p
    p="$(cyvidia_host_path "${r}")"
    if [[ -e "${p}" ]]; then
      echo "${r}"
      hit=1
    fi
  done
  return $((1 - hit))
}
