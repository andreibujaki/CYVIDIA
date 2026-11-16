# CYVIDIA Design Spec

**Date:** 2026-11-16  
**Status:** Revised after design review — pending user confirmation  
**Location:** `D:\CYBERSEC\CYVIDIA` (sibling project to CerealBox; not inside CerealBox)  
**License posture:** Authorized defensive use only; no warranty (same stance as CerealBox)

## 1. Purpose

CYVIDIA is a Linux host defensive kit for detecting and, with explicit administrator consent, remediating:

1. **REF3364 / SANSAR-style** GPU cryptomining intrusions (Ray initial access, toolkit under `/opt/vadi_`, NVML telemetry spoofing, `acpi_thermal_mgr` rootkit, `netns` Ethereum-assisted backdoor, Tor C2).
2. **Generic Tor-linked cryptominers** beyond SANSAR, via a pluggable IOC/behavior pack (seeded with families such as XMRig and SRBMiner-MULTI, extensible without code changes).
3. **NVIDIA driver CVE / patch-status** gaps, using a versioned advisory pack and vendor/distro updates under consent.

It does **not** ship NVIDIA binary patches, exploit PoCs, or live attack/C2 interaction beyond an optional read-only Ethereum `eth_call` for the known `netns` resolver contract.

## 2. Threat model and assumptions

| Assumption | Detail |
|------------|--------|
| Target | Single Linux GPU/AI host (Debian/Ubuntu or RHEL/Rocky/Alma family) |
| Privileges | Root available for full hunt/harden/guard; unprivileged yields reduced coverage |
| Operator access | Console or equivalent access available for Secure Boot / MOK cases |
| Adversary | Post-compromise cryptomining with rootkit + telemetry spoofing; may hide processes/files/sockets |
| Trust boundary | Once `acpi_thermal_mgr` is loaded, runtime `lsmod` / `ps` / directory listings are untrustworthy; prefer disk, package DB, initramfs, and offline guidance |
| Network | Core hunt is air-gap capable; optional `--network` is read-only and never required |
| C2 ceiling | Optional read-only `eth_call` only; no offensive PoCs, no interactive C2 |
| Not assumed | Fleet orchestration, containers/K8s, Windows agents (later phases) |

## 3. Phasing

| Phase | Scope | This release train |
|-------|--------|-------------------|
| **v1** | Linux host kit: hunt / harden / guard | **Yes** |
| **v2** | NVIDIA driver CVE patch-status module | **Yes (same train)** |
| **v3** | Windows GPU agent | Later |
| **v4** | Multi-host orchestration UI | Later |

Permanently out of scope: offensive PoCs; interactive or aggressive C2 beyond optional read-only `eth_call`; full automated rollback of package/initramfs (v1+v2).

## 4. Architecture

### 4.1 Entrypoint and modes

CLI entrypoint: `bin/cyvidia`

| Mode | Behavior |
|------|----------|
| `hunt` | Read-only checks. Emit CLI + versioned JSON; optional Markdown/HTML; journald/syslog. Optional `--network`. |
| `harden` | Run hunt → required `--plan` → admin consent → full remediation → re-hunt → final report. |
| `guard` | systemd timer re-hunts and alerts via journald. Remediation only with valid consent file. Never silent wipe. |
| `consent` | Subcommands: `grant`, `revoke`, `list` for consent file lifecycle. |

### 4.2 Layers

1. **Bash core** (`lib/`) — host checks, gated remediation, distro adapters, correlation hints emitted as findings.
2. **Python helpers** (`python/`) — versioned JSON schema emit/validate, Markdown/HTML reports, optional Ethereum lookup, CVE matching, correlation summary fields.
3. **IOC / advisory packs** (`iocs/`, `yara/`) — concrete SANSAR baseline, pluggable Tor-miner list, `nvidia-cves.json`.

### 4.3 Versioning in every report

Every CLI summary, JSON document, and MD/HTML report includes:

- `tool_version`
- `ioc_pack_version` (from `iocs/sansar.json` / pack manifest)
- `advisory_pack_version` (from `iocs/nvidia-cves.json`)
- `hostname`, `scan_id`, UTC timestamp

### 4.4 Safety rules

- Destructive actions never run in plain `hunt`.
- Full remediation requires administrator consent (interactive and/or consent file).
- `--plan` is **required** before remediate.
- **Never auto-reboot**.
- Root lockfile `/run/cyvidia.lock` — second harden exits `1`.
- Consent file `0600 root:root` at `/etc/cyvidia/consent.json`.
- Reports redact wallets, pool login/URLs, and similar secrets.
- Secure Boot / module signature enforcement: detect and stop with guidance; never force-unload unsigned modules.

### 4.5 Development vs runtime

- Repo authored on Windows at `D:\CYBERSEC\CYVIDIA` as needed.
- Runtime and CI on Linux.

## 5. Exact IOC baseline (required seed)

Ship `iocs/sansar.json` (versioned) seeded from public Elastic REF3364 reporting:

### 5.1 SHA-256 (published)

| Role | SHA-256 |
|------|---------|
| `sansar` | `00c9ac44291f83c72d54302e99d155a3e26d02225a3e516764d5833a99657c9e` |
| `kurt` (XMRig 6.25.0) | `96fc528ca5e7d1c2b3add5e31b8797cb126f704976c8fbeaecdbf0aa4309ad46` |
| `tilki` (SRBMiner-MULTI 3.6.9) | `acc706afc9322a3eae1ef49049749e0a7c9f1a123895ac56dc8a289beb2fb5b7` |
| `lyrebird` 0.8.1 | `cc1ad7f14777a098ccc91fd4e8f6143da14418c2b6fdf23b7f8f6b3d1b0b7f1d` |
| `libnvidia-ml.so.1` wrapper | `675c24728f87f7aa0fa07527027c95c24c246049c65eaef89270ab04ea50a180` |
| `acpi_thermal_mgr.ko` | `6ba1aa275e0e2826e8b48b36473539ca56cbdc41f429e539a45f8532b084d7a4` |
| `netns` | `df8ab6fd699e6ae90e63e9696bae8f01342708bafc2ed88af414337e4f237194` |

### 5.2 Network / chain indicators

| Type | Value |
|------|-------|
| Onion C2 | `efxisnqldelyr5ra25oqfrsut54b34g26e7zrsiuupsoekjof2gho2id.onion:9051` |
| Ethereum contract | `0x43eb291f56688c63c93e8a93c4591fc997cf6349` |
| Contract selector | `0x6ded96e7` |
| `netns` TCP port | `8080` |

### 5.3 Paths and names

- Staging: `/opt/vadi_/`
- NVML hook dir: `/opt/vadi_/nvml-hook/` (incl. `nvml_hook.c`, Makefile)
- Backup: `/usr/lib/.libnvidia-ml.so.1.backup` (and package-managed NVIDIA lib dirs via `ldconfig`)
- Rootkit source: `/usr/src/acpi_thermal_mgr-1.0/` (`acpi_thermal_mgr.c`)
- Module: `acpi_thermal_mgr.ko` / DKMS name `acpi_thermal_mgr`
- Default hidden process names (rootkit defaults): `kurt`, `lyrebird` (plus configurable names)
- Binaries: `sansar`, `kurt`, `tilki`, `lyrebird`, `netns`
- Tor helpers: `arti_data/`, `bridges`, `.client_id`

Pack format is versioned; update process in `docs/ioc-update.md`.

## 6. Hunt check modules (v1)

### 6.1 Ray (expanded)

- Distinguish **dashboard** vs **job agent** listeners (dashboard may be loopback-only while Jobs API remains exposed).
- Detect listen addresses/ports (default dashboard `8265` and related job-agent sockets).
- Auth configuration presence/absence for job submission.
- Recent job history / logs when available: `nvidia-smi` exfil patterns, Python reverse-shell job patterns.
- Ray service account(s) with unexpected `authorized_keys` entries.

### 6.2 SSH persistence

- `authorized_keys` anomalies on Ray/service accounts; tie evidence to Ray findings; backup before any remediate removal.

### 6.3 SANSAR filesystem

- Paths and filenames from §5; hash matches against seeded SHA-256s.

### 6.4 Rootkit / boot (beyond presence)

Because ftrace rootkits can hide themselves (`hide_module`):

- Inspect **initramfs** image contents for `acpi_thermal_mgr` / loader hooks (offline-friendly extract/list).
- DKMS/source trees under `/usr/src/acpi_thermal_mgr*`.
- Module parameters if the module is visible; do not trust `lsmod` alone.
- **Rootkit-active severity escalator:** when disk/initramfs/DKMS evidence exists but runtime views look clean (missing module/process/socket), raise severity and set `confidence` high with `rootkit_hiding_suspected`.
- Operator guidance for **offline disk inspection** when live views are inconsistent (document in Secure Boot / rootkit playbook).

### 6.5 NVML integrity + independent GPU cross-check

- Compare `libnvidia-ml.so.1` to package/vendor hashes; detect hook dir and `.backup`.
- **Secondary signals (required when NVML looks idle):**
  - sysfs power/thermal (`/sys/class/drm/card*/device/`, hwmon nodes)
  - PCIe bandwidth/utilization if available
  - GPU-related process memory / context footprint where observable without trusting NVML
  - external/BMC power readings **when present** (optional evidence, not required)
- Escalate: NVML idle-looking **and** secondary disagreement → High; plus file/rootkit/IOC → Critical.

### 6.6 systemd

- `netns` and miner-like units; unexpected Tor/lyrebird/arti helpers as system or user services.

### 6.7 Miner + Tor behavior (pluggable)

- `iocs/tor-miners.json` (pluggable): seeded XMRig / SRBMiner-MULTI (+ SANSAR renames); extensible.
- Coupling: lyrebird binaries, `bridges` files, Arti/Tor configs referencing known onion or generic onion endpoints, SOCKS-to-Tor patterns in configs.

### 6.8 Process / socket hiding awareness

- Prefer **disk + package DB + initramfs** over pure `ps`/proc listings.
- Emit findings for **expected vs observed**: known miner binary on disk but absent from process list; unit enabled but process missing; sockets expected from configs not visible — flag as possible hiding (not sole Critical without disk/IOC support).

### 6.9 Optional `--network`

- Read-only `eth_call` to seeded contract/selector.
- Document default public RPC endpoints; allow operator override via config/flag.
- Completely isolated from core hunt; never required offline.

### 6.10 Optional YARA

- Bundle Elastic-derived (or clean derivative) rules under `yara/` for SANSAR and `netns`.
- If `yara` binary present → run and attach hits; else Info note. Document exact behavior in README/runbook.

## 7. Finding correlation and JSON schema

### 7.1 Correlation

Lightweight correlation produces a summary object, e.g.:

- `campaign_confidence`: `none` | `low` | `medium` | `high`
- `labels`: e.g. `["sansar_toolkit", "nvml_spoof", "rootkit_hiding_suspected", "ray_exposed"]`

Rules (normative for v1):

- Single NVML/secondary mismatch alone → High finding; campaign confidence low/medium.
- NVML/secondary + rootkit/IOC/file hit → Critical; campaign confidence high (`sansar_toolkit`).
- Disk IOC without runtime visibility → escalate with `rootkit_hiding_suspected`.

### 7.2 Versioned findings JSON (stable for SIEM / v4)

Each finding includes at least:

| Field | Meaning |
|-------|---------|
| `schema_version` | JSON schema version |
| `finding_id` | Stable id for this finding instance |
| `module` | Check module name |
| `severity` | Critical/High/Medium/Low/Info |
| `confidence` | low/medium/high |
| `title` | Short title |
| `detail` | Human detail |
| `evidence` | Paths, hashes, commands, excerpts (redacted) |
| `remediation_hint` | Suggested action family |
| `ioc_refs` | References into IOC pack entries |
| `tool_version` / `ioc_pack_version` / `advisory_pack_version` | Versions |

Document schema under `docs/findings-schema.md` (or embedded JSON Schema file).

## 8. NVIDIA CVE patch-status (v2)

| Piece | Behavior |
|-------|----------|
| Pack | `iocs/nvidia-cves.json` — manual curation; CVE id, affected ranges, fixed version, advisory URL, severity; `advisory_pack_version` |
| Detect | Installed driver/toolkit version vs pack → unpatched / unknown / current |
| Remediate | Consent + `--plan`: distro/vendor package updates or printed commands; never custom driver binaries |
| Distro adapters | Explicit package name maps for Debian/Ubuntu vs RHEL/Rocky/Alma; detect `.run` installer leftovers vs packaged installs |
| Air-gap | Local compare offline; refresh by replacing `iocs/` |

## 9. Consent mechanism and schema

### 9.1 Interactive

Show Critical/High + correlation summary + `--plan` → type `REMEDIATE` + hostname → proceed.

### 9.2 Consent file schema (`/etc/cyvidia/consent.json`)

| Field | Required | Meaning |
|-------|----------|---------|
| `schema_version` | yes | Consent schema version |
| `hostname` | yes | Must match current hostname |
| `created_at` | yes | UTC timestamp |
| `expires_at` | yes | UTC expiry |
| `issuer` | yes | Operator identity string |
| `allowed_actions` | yes | Subset of: `stop_processes`, `quarantine`, `nvml_restore`, `rootkit_remove`, `ssh_key_cleanup`, `ray_harden`, `cve_update`, `disable_units` |
| `signature` / `hmac` | no | Optional integrity field for later hardening |
| `notes` | no | Free text |

CLI: `cyvidia consent grant|revoke|list`.

No valid consent → hunt/report only. Guard checks consent before any remediation action.

## 10. Quarantine, audit, and rollback notes

### 10.1 Quarantine layout

```
/var/lib/cyvidia/quarantine/<timestamp>/
  metadata.json      # finding_ids, plan_id, original paths, before hashes, timestamps, tool/ioc versions
  tree/              # mirrored original paths under tree/
  ROLLBACK.md        # human-readable rollback
  rollback.json      # machine-readable rollback snippets per step
```

### 10.2 Audit events (journald + metadata)

Each grant/remediate step logs: actor, hostname, plan_id, action, before/after hashes where applicable, result, consent reference.

### 10.3 Rollback notes (required per step)

Every remediate step writes human + machine rollback snippets: commands, quarantine location, expected hashes. **No full automated package/initramfs rollback** in v1+v2.

## 11. Full remediation map (after consent)

1. Acquire lockfile; refuse if held.
2. Stop matched miner/`sansar`/`netns` processes (IOC + behavior).
3. Disable/mask matching systemd units.
4. Quarantine then remove toolkit artifacts (metadata + hashes first).
5. **NVML:** package reinstall/restore preferred; verified `.backup` restore if vendor-good; re-hash.
6. **Rootkit:** remove DKMS/source/module; rebuild initramfs without loader; reboot-required notice only.
7. **Secure Boot:** if blocked, stop with MOK/playbook guidance — never force-unload.
8. **SSH:** backup then remove only hunt-flagged keys.
9. **Ray harden:** bind job agent off public interfaces / safe local firewall where possible.
10. **CVE update (v2):** vendor/distro updates or printed commands.
11. Re-hunt; write final report including correlation and versions.

## 12. Guard mode details

| Setting | v1 default |
|---------|------------|
| Timer interval | Every 6 hours (configurable) |
| Alert channel | journald (priority by severity) |
| Minimum alert severity | High (configurable; Critical always alerts) |
| Throttling | Same `finding_id` signature suppressed for one timer period unless severity rises |
| Remediation | Only if consent file valid for required `allowed_actions`; otherwise alert-only |

## 13. Data flow

```
hunt → findings + correlation → CLI + versioned JSON + journald (+ MD/HTML)
                              ↓
                   harden / guard remediate path
                              ↓
         --plan (required) → consent → lock → remediate (+ quarantine/audit/rollback notes)
                              ↓
                         re-hunt → final report
```

## 14. Error handling and exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean (no Critical/High), or remediate succeeded and re-hunt clean |
| `1` | Tool error (deps, lock held, missing core IOC pack, aborted mid-remediate) |
| `2` | Critical/High findings remain |
| `3` | Consent required or refused |

Partial module failures → Info/Medium; abort whole hunt only if core IOC pack missing.

## 15. Distro adapters

Supported families: **Debian/Ubuntu** and **RHEL/Rocky/Alma**.

Adapters must define:

- Package query commands for NVIDIA library/driver packages
- Reinstall/restore command templates
- Detection of `.run` installer residue vs distro packages
- initramfs rebuild commands (`update-initramfs` vs `dracut`)

## 16. Privileges, fleet, install, localization

| Topic | Decision |
|-------|----------|
| Privileges | Root for full function; unprivileged reduced hunt + capability note |
| Fleet | Single-host CLI; JSON/journald for later orchestration |
| Containers/K8s | Host-only this train |
| Install | Tarball + `install.sh`; `.deb`/`.rpm` later |
| Localization | English-only |
| IoC updates | Static packs + `docs/ioc-update.md` |

## 17. Repository layout (target)

```
CYVIDIA/
  bin/cyvidia
  lib/                 # bash modules + distro adapters + correlation helpers
  python/              # report, JSON schema, network, CVE helpers
  iocs/
    sansar.json        # concrete REF3364 seed
    tor-miners.json    # pluggable
    nvidia-cves.json
    pack-manifest.json # versions
  yara/                # optional Elastic-derived rules
  docs/
    superpowers/specs/2026-11-16-cyvidia-design.md
    ioc-update.md
    findings-schema.md
    runbook-operator.md
    playbook-secure-boot-rootkit.md
  tests/fixtures/      # no live malware
  install.sh
  README.md
```

## 18. Documentation (required)

| Doc | Purpose |
|-----|---------|
| `docs/ioc-update.md` | How to bump IOC/advisory packs |
| `docs/findings-schema.md` | Stable JSON schema |
| `docs/runbook-operator.md` | hunt → plan → consent → remediate → verify |
| `docs/playbook-secure-boot-rootkit.md` | What to do when Secure Boot blocks rootkit removal; offline inspection guidance |

## 19. Testing and CI

Safe fixtures only — **no live malware**.

Expanded fixture matrix:

- Rootkit-hidden files / expected-vs-observed mismatch
- Poisoned NVML + secondary power disagreement
- Ray unauthenticated job agent (dashboard loopback-only scenario)
- Consent expiry and hostname mismatch
- Concurrent lock (`/run/cyvidia.lock`)
- Partial remediation failure + rollback notes present
- Air-gapped run (no network)
- Optional network helper with mocked RPC
- YARA present vs absent

CI (GitHub Actions, Linux runners): `shellcheck`, `pytest`, fixture hunts, `--plan` dry-run assertions.

## 20. Research credit

Elastic Security Labs — REF3364 / SANSAR (“0% GPU utilization: How SANSAR hides Linux cryptomining”). Related Ray exposure context includes ShadowRay-class unauthenticated Jobs API reporting. IOC hashes, paths, onion, and contract details are from that public research and maintained as a versioned static pack.

## 21. Success criteria

- Concrete IOC seed present and reported with pack versions.
- Hunt covers Ray depth, SSH, filesystem IOCs, initramfs/DKMS rootkit checks, NVML + secondary GPU signals, Tor-miner behaviors, hiding awareness, optional YARA/network.
- Correlation + stable JSON schema in outputs.
- Consent schema + grant/revoke/list; quarantine metadata + per-step rollback notes.
- Harden requires `--plan` + consent; never auto-reboot; Secure Boot stop/guidance.
- Guard: interval/throttle/min severity; alert-only without consent.
- Air-gapped hunt works; CVE module works offline against local advisory pack.
- CI green on Linux fixture suite.

## 22. Deferred (explicit)

- Windows GPU agent (v3)
- Multi-host orchestration UI (v4)
- Container/Kubernetes-aware checks
- Full automated package/initramfs rollback
- Native `.deb`/`.rpm`
- Live advisory auto-import scrapers
- Interactive HTML severity filters (nice-to-have)
- IOC pack cryptographic signing (nice-to-have; optional HMAC on consent is enough for now)
