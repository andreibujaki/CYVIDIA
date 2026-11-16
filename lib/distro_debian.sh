#!/usr/bin/env bash
# Debian/Ubuntu adapter

cyvidia_pkg_verify_file() {
  local path="$1"
  if command -v dpkg >/dev/null 2>&1; then
    dpkg -S "${path}" 2>/dev/null || true
    local pkg
    pkg="$(dpkg -S "${path}" 2>/dev/null | head -n1 | cut -d: -f1 || true)"
    if [[ -n "${pkg}" ]] && command -v debsums >/dev/null 2>&1; then
      debsums -c "${pkg}" 2>/dev/null || true
    fi
  fi
}

cyvidia_nvidia_reinstall_cmds() {
  cat <<'EOF'
# Debian/Ubuntu — review before running
sudo apt-get update
sudo apt-get install --reinstall -y nvidia-driver-libs nvidia-utils 2>/dev/null || \
  sudo apt-get install --reinstall -y libnvidia-ml1 nvidia-utils 2>/dev/null || \
  echo "Adjust package names for your NVIDIA apt repository / CUDA install"
EOF
}

cyvidia_initramfs_rebuild_cmd() {
  echo "update-initramfs -u"
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
