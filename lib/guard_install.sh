#!/usr/bin/env bash
# Install/uninstall systemd guard units

cyvidia_guard_install() {
  [[ "$(cyvidia_require_root; echo $?)" == "0" ]] || cyvidia_die "root required for guard install"
  local unit_dir=/etc/systemd/system
  install -d /etc/cyvidia
  if [[ ! -f /etc/cyvidia/config.json ]]; then
    cp "${ROOT}/packaging/cyvidia.config.json.example" /etc/cyvidia/config.json
  fi
  cp "${ROOT}/packaging/cyvidia-guard.service" "${unit_dir}/cyvidia-guard.service"
  cp "${ROOT}/packaging/cyvidia-guard.timer" "${unit_dir}/cyvidia-guard.timer"
  # Rewrite ExecStart to this install path
  sed -i "s|__CYVIDIA_BIN__|${ROOT}/bin/cyvidia|g" "${unit_dir}/cyvidia-guard.service"
  systemctl daemon-reload
  systemctl enable --now cyvidia-guard.timer
  echo "Installed cyvidia-guard.timer (override interval via systemd drop-in)"
}

cyvidia_guard_uninstall() {
  systemctl disable --now cyvidia-guard.timer 2>/dev/null || true
  rm -f /etc/systemd/system/cyvidia-guard.service /etc/systemd/system/cyvidia-guard.timer
  systemctl daemon-reload 2>/dev/null || true
  echo "Uninstalled cyvidia-guard units"
}
