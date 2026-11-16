#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${1:-/opt/cyvidia}"

echo "Installing CYVIDIA to ${DEST}"
mkdir -p "${DEST}"
cp -a "${ROOT}/bin" "${ROOT}/lib" "${ROOT}/python" "${ROOT}/iocs" "${ROOT}/yara" "${ROOT}/packaging" "${ROOT}/docs" "${DEST}/"
chmod +x "${DEST}/bin/cyvidia"
mkdir -p /usr/local/bin
ln -sfn "${DEST}/bin/cyvidia" /usr/local/bin/cyvidia
mkdir -p /etc/cyvidia
if [[ ! -f /etc/cyvidia/config.json ]]; then
  cp "${DEST}/packaging/cyvidia.config.json.example" /etc/cyvidia/config.json
fi
echo "Installed. Try: cyvidia version && cyvidia help"
echo "Optional guard: cyvidia guard install"
