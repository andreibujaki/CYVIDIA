#!/usr/bin/env bash
# Optional read-only Ethereum lookup wrapper

cyvidia_mod_network_eth() {
  local out
  out="$(cyvidia_py "${CYVIDIA_ROOT_NATIVE}/python/cyvidia_eth_call.py" 2>&1 || true)"
  if echo "${out}" | grep -q '"error"'; then
    cyvidia_finding_add Low network_eth "Ethereum RPC lookup failed" "Optional network check; air-gapped hosts can ignore" "${out}" "" "sansar.json" low
  else
    cyvidia_finding_add Info network_eth "Ethereum resolver lookup completed" "Read-only eth_call result captured" "${out}" "" "sansar.json" low
  fi
}
