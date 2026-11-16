# CYVIDIA Design Spec

**Date:** 2026-11-16  
**Status:** Approved for implementation planning (pending user review of this file)  
**Location:** `D:\CYBERSEC\CYVIDIA` (sibling project to CerealBox; not inside CerealBox)  
**License posture:** Authorized defensive use only; no warranty (same stance as CerealBox)

## 1. Purpose

CYVIDIA is a Linux host defensive kit for detecting and, with explicit administrator consent, remediating:

1. **REF3364 / SANSAR-style** GPU cryptomining intrusions (Ray initial access, toolkit under `/opt/vadi_`, NVML telemetry spoofing, `acpi_thermal_mgr` rootkit, `netns` Ethereum-assisted backdoor, Tor C2).
2. **Generic Tor-linked cryptominers** beyond SANSAR, via a pluggable IOC/behavior pack (seeded with families such as XMRig and SRBMiner-MULTI, extensible without code changes).
3. **NVIDIA driver CVE / patch-status** gaps, using a versioned advisory pack and vendor/distro updates under consent.

It does **not** ship NVIDIA binary patches, exploit PoCs, or live attack/C2 interaction beyond an optional read-only Ethereum `eth_call` for the known `netns` resolver contract.

## 2. Phasing

| Phase | Scope | This release train |
|-------|--------|-------------------|
| **v1** | Linux host kit: hunt / harden / guard | **Yes** |
| **v2** | NVIDIA driver CVE patch-status module | **Yes (same train)** |
| **v3** | Windows GPU agent | Later |
| **v4** | Multi-host orchestration UI | Later |

Permanently out of scope: offensive PoCs; interactive or aggressive C2 beyond optional read-only `eth_call`.

## 3. Architecture

### 3.1 Entrypoint and modes

CLI entrypoint: `bin/cyvidia`

| Mode | Behavior |
|------|----------|
| `hunt` | Read-only checks. Emit CLI + JSON; optional Markdown/HTML; journald/syslog lines. Optional `--network`. |
| `harden` | Run hunt, print required `--plan`, obtain admin consent, perform full remediation, re-hunt, write final report. |
| `guard` | systemd timer that re-hunts and alerts via journald. Remediation only when a valid consent file grants actions. Never silent wipe. |

### 3.2 Layers

1. **Bash core** (`lib/`) — host checks and gated remediation; thin distro adapters (Debian/Ubuntu vs RHEL/Rocky/Alma).
2. **Python helpers** (`python/`) — JSON emit/validate, Markdown/HTML reports, optional Ethereum read-only lookup, advisory matching helpers as needed.
3. **IOC / advisory packs** (`iocs/`, `yara/`) — SANSAR hashes/paths, pluggable Tor-miner list, `nvidia-cves.json`.

### 3.3 Safety rules

- Destructive actions never run in plain `hunt`.
- Full remediation requires **administrator consent** (interactive and/or consent file).
- `--plan` is **required** before remediate (dry-run map of actions).
- **Never auto-reboot** (print reboot-required notice after initramfs/rootkit work).
- Root lockfile (e.g. `/run/cyvidia.lock`) prevents concurrent harden/remediate.
- Consent file: `0600`, `root:root` (path e.g. `/etc/cyvidia/consent.json`).
- Reports redact wallets, pool login/URLs, and similar secrets (`***` or truncated hash).

### 3.4 Development vs runtime

- Repository may be authored on Windows at `D:\CYBERSEC\CYVIDIA`.
- Runtime and integration tests target Linux GPU/AI hosts (and Linux CI runners).

## 4. Hunt check modules (v1)

| Module | Checks |
|--------|--------|
| **Ray** | Job agent / dashboard exposure (e.g. port 8265, Jobs API bind/auth). Suspicious job history patterns when logs exist. |
| **SSH persistence** | `authorized_keys` anomalies on Ray/service accounts; evidence tied to hunt findings. |
| **SANSAR filesystem** | `/opt/vadi_/`, `nvml-hook`, `/usr/lib/.libnvidia-ml.so.1.backup`, known names (`sansar`, `kurt`, `tilki`, `lyrebird`, `netns`). |
| **Rootkit / boot** | `acpi_thermal_mgr` module, DKMS/source under `/usr/src/`, initramfs hooks referencing that module. |
| **NVML integrity** | `libnvidia-ml.so.1` (and related) vs package/vendor hashes; hook/backup paths. |
| **systemd** | `netns` or miner-like units; unexpected Tor helper services. |
| **Miner + Tor behavior** | Pluggable list: known miner binaries/hashes **plus** coupling to Tor/arti/lyrebird, `bridges` files, onion-looking endpoints in configs. |
| **Runtime GPU** | `nvidia-smi` shows idle-like util while power/GPU contexts elevated → possible NVML hook. Severity: **High** alone; **Critical** only when combined with file/rootkit/IOC hit. |
| **Optional `--network`** | Read-only `eth_call` to known contract `0x43eb291f56688c63c93e8a93c4591fc997cf6349` (selector `0x6ded96e7`); record result in findings. No exploit traffic. |
| **Optional YARA** | If `yara` is present, run `yara/` rules (Elastic-derived SANSAR/netns patterns); otherwise skip with Info note. |

Findings severities: `Critical`, `High`, `Medium`, `Low`, `Info` (CerealBox-style).

## 5. NVIDIA CVE patch-status (v2)

| Piece | Behavior |
|-------|----------|
| **Pack** | `iocs/nvidia-cves.json` — manually curated; fields include CVE id, affected version ranges, fixed version, vendor advisory URL, severity. Documented import notes from NVIDIA bulletins / NVD; **no live auto-scrape** in this release train. |
| **Detect** | Read installed NVIDIA driver/toolkit version; match against pack → unpatched / unknown / current. |
| **Remediate** | After consent + `--plan`: invoke vendor/distro package update paths (`apt` / `dnf`) where safe, or print exact operator commands. Never ship custom/cracked driver binaries. |
| **Air-gap** | Hunt and local CVE compare work offline. Refresh advisories by replacing `iocs/` files (USB/git). `--network` never required for core hunt. |

## 6. Consent mechanism

1. **Interactive (default for `harden`):** show Critical/High summary and `--plan` → operator types `REMEDIATE` plus hostname confirmation → proceed.
2. **Consent file (guard / automation):** `/etc/cyvidia/consent.json` with hostname binding, expiry, allowed action list; created via `cyvidia consent grant …`.
3. **Both supported.** No valid consent → hunt/report only.
4. Every grant and remediate step audited to journald (who/when/what).

## 7. Full remediation map (after consent)

Order of operations (stop on hard failure; leave rollback notes):

1. Stop matched miner / `sansar` / `netns`-related processes (IOC + behavior match).
2. Disable/mask matching systemd units.
3. Quarantine then remove toolkit paths and known malicious artifacts — copy to `/var/lib/cyvidia/quarantine/<timestamp>/` before delete.
4. **NVML:** prefer package reinstall/restore from NVIDIA/distro packages; if `.backup` verifies as vendor-good, restore from backup; re-hash.
5. **Rootkit:** remove DKMS/source/module; rebuild initramfs **without** `acpi_thermal_mgr` loader; print reboot-required notice (**never auto-reboot**).
6. **Secure Boot:** detect state; if unload/module ops are blocked, stop with clear MOK/reboot guidance — no unsafe force.
7. **SSH:** backup then remove only keys flagged by this hunt.
8. **Ray harden (under consent):** bind job agent off public interfaces and/or apply safe local firewall restrictions where possible; not a Ray upstream code patch.
9. **NVIDIA CVE remediate (v2):** vendor/distro updates per advisory pack / printed commands.
10. **Re-hunt** and write post-remediation report.

**Rollback (v1+v2):** quarantine + `--plan` + partial re-hunt. No full automated reverse of package/initramfs changes; operator restores from quarantine and written notes.

## 8. Data flow

```
hunt → findings → CLI + JSON + journald (+ MD/HTML)
                 ↓
        harden / guard remediate path
                 ↓
        --plan (required) → consent → remediate → re-hunt → final report
```

## 9. Error handling and exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean (no Critical/High), or remediate succeeded and re-hunt clean |
| `1` | Tool error (missing deps, lock held, unreadable core pack, aborted mid-remediate) |
| `2` | Critical/High findings remain (hunt or post-remediate) |
| `3` | Consent required or refused |

Partial module failures become `Info`/`Medium` findings; do not abort the whole hunt unless the core IOC pack is missing.

## 10. Outputs

- CLI severity-colored summary
- JSON findings file
- journald/syslog lines (especially for `guard`)
- Markdown and HTML handoff reports (Python helpers)
- Secret redaction in all durable outputs

## 11. Privileges, fleet, install, localization

| Topic | Decision |
|-------|----------|
| Privileges | Root required for full hunt/harden/guard; unprivileged → reduced hunt + explicit note |
| Fleet | Single-host CLI only in this train; JSON/journald enable later orchestration |
| Containers/K8s GPU | Host-only; containerized Ray/NVIDIA later |
| Install | Copy/tarball + `install.sh` first; `.deb`/`.rpm` later |
| Localization | English-only CLI/reports |
| IoC updates | Static in-repo packs + `docs/ioc-update.md` process |

## 12. Repository layout (target)

```
CYVIDIA/
  bin/cyvidia
  lib/           # bash modules + distro adapters
  python/        # report, JSON, optional network, CVE helpers
  iocs/          # sansar, tor-miners (pluggable), nvidia-cves.json
  yara/          # optional rules
  docs/
    superpowers/specs/2026-11-16-cyvidia-design.md
    ioc-update.md
  tests/         # fixtures only — no live malware
  install.sh
  README.md
```

## 13. Testing and CI

- Safe fixtures only (fake paths, dummy units, crafted JSON)—**no live malware**.
- `shellcheck` on bash; `pytest` on Python helpers.
- Fixture-based hunt runs on Linux.
- Harden `--plan` tests assert action map without disk mutation.
- **GitHub Actions** on Linux runners: shellcheck + pytest + fixture hunts.
- Document: develop on Windows, validate on Linux VM/host.

## 14. Research credit and IOC baseline

Primary public research: Elastic Security Labs — REF3364 / SANSAR (“0% GPU utilization: How SANSAR hides Linux cryptomining”), and related Ray exposure context (e.g. ShadowRay-class unauthenticated Jobs API). IOC hashes, paths, onion indicator, and Ethereum contract details are derived from that public reporting and maintained as a static pack with an update process.

## 15. Success criteria

- Operator can run `cyvidia hunt` on Debian/Ubuntu and RHEL-family GPU hosts and receive CLI + JSON + optional MD/HTML + journald output.
- SANSAR artifacts, Tor-miner behaviors, Ray exposure, NVML integrity issues, and NVIDIA CVE patch gaps surface as structured findings.
- `cyvidia harden --plan` never changes the system; remediate runs only after consent.
- Guard alerts without silent remediation.
- Air-gapped hunt works; network features remain opt-in.
- CI is green on Linux for lint and fixture tests.

## 16. Open items deferred (explicit)

- Windows GPU agent (v3)
- Multi-host orchestration UI (v4)
- Container/Kubernetes-aware checks
- Full automated rollback of package/initramfs
- Native `.deb`/`.rpm` packages
- Live advisory auto-import scrapers
