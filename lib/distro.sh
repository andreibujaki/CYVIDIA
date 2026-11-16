#!/usr/bin/env bash
# Distro family detection and adapter dispatch

cyvidia_distro_family() {
  local os_release
  os_release="$(cyvidia_host_path /etc/os-release)"
  if [[ ! -f "${os_release}" ]]; then
    echo "unknown"
    return 0
  fi
  # shellcheck disable=SC1090
  local id_like="" id=""
  id="$(grep -E '^ID=' "${os_release}" | head -n1 | cut -d= -f2 | tr -d '"')"
  id_like="$(grep -E '^ID_LIKE=' "${os_release}" | head -n1 | cut -d= -f2 | tr -d '"')"
  case "${id}" in
    debian|ubuntu) echo "debian"; return 0 ;;
    rhel|centos|rocky|almalinux|fedora) echo "rhel"; return 0 ;;
  esac
  case " ${id_like} " in
    *" debian "*|*" ubuntu "*) echo "debian"; return 0 ;;
    *" rhel "*|*" fedora "*|*" centos "*) echo "rhel"; return 0 ;;
  esac
  echo "unknown"
}

cyvidia_distro_load() {
  local family
  family="$(cyvidia_distro_family)"
  case "${family}" in
    debian)
      # shellcheck source=lib/distro_debian.sh
      source "${CYVIDIA_ROOT}/lib/distro_debian.sh"
      ;;
    rhel)
      # shellcheck source=lib/distro_rhel.sh
      source "${CYVIDIA_ROOT}/lib/distro_rhel.sh"
      ;;
    *)
      cyvidia_warn "unknown distro family; using debian-like command templates"
      # shellcheck source=lib/distro_debian.sh
      source "${CYVIDIA_ROOT}/lib/distro_debian.sh"
      ;;
  esac
}
