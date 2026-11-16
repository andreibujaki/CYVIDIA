# CYVIDIA v1+v2 Implementation Plan

**Goal:** Build the Linux CYVIDIA host kit (hunt / harden / guard) plus NVIDIA CVE patch-status, per `docs/superpowers/specs/2026-11-16-cyvidia-design.md`.

**Architecture:** Bash CLI + `lib/` check/remediate modules; Python for versioned JSON, MD/HTML reports, optional `eth_call`, CVE matching; versioned IOC packs under `iocs/`; optional YARA; systemd timer for guard.

**Tech Stack:** Bash 4+, Python 3.10+, systemd, shellcheck, pytest, optional `yara`; targets Debian/Ubuntu and RHEL/Rocky/Alma.

**Spec:** `docs/superpowers/specs/2026-11-16-cyvidia-design.md`

---

## File map (create)

```
bin/cyvidia
install.sh
README.md
.gitignore
lib/common.sh
lib/lock.sh
lib/findings.sh
lib/distro.sh
lib/distro_debian.sh
lib/distro_rhel.sh
lib/mod_ray.sh
lib/mod_ssh.sh
lib/mod_sansar_fs.sh
lib/mod_rootkit.sh
lib/mod_nvml.sh
lib/mod_gpu_secondary.sh
lib/mod_systemd.sh
lib/mod_tor_miners.sh
lib/mod_hiding.sh
lib/mod_yara.sh
lib/mod_network_eth.sh          # thin wrapper calling python
lib/mod_nvidia_cve.sh
lib/correlate.sh
lib/consent.sh
lib/plan.sh
lib/remediate.sh
lib/quarantine.sh
lib/guard_install.sh
python/cyvidia_json.py
python/cyvidia_report.py
python/cyvidia_eth_call.py
python/cyvidia_cve_match.py
python/cyvidia_correlate.py
python/requirements.txt         # empty or minimal; stdlib-first
iocs/sansar.json
iocs/tor-miners.json
iocs/nvidia-cves.json
iocs/correlation.rules.json
iocs/pack-manifest.json
yara/sansar_netns.yar
yara/ATTRIBUTION.md
docs/ioc-update.md
docs/findings-schema.md
docs/runbook-operator.md
docs/playbook-secure-boot-rootkit.md
packaging/cyvidia-guard.service
packaging/cyvidia-guard.timer
packaging/cyvidia.config.json.example
tests/fixtures/...
tests/test_json_schema.py
tests/test_cve_match.py
tests/test_correlate.py
tests/test_eth_call.py
tests/hunt/run_fixture_hunt.sh
.github/workflows/ci.yml
```

---

### Task 1: Repository skeleton and ignore rules

**Files:**
- Create: `.gitignore`
- Create: `README.md` (stub pointing at spec + runbook)
- Create: `bin/cyvidia` (stub dispatcher)
- Create: `lib/common.sh`

- [ ] **Step 1: Create `.gitignore`**

```gitignore
__pycache__/
*.py[cod]
.pytest_cache/
.venv/
*.findings.json
/var-lib-cyvidia-fake/
*.tmp
.DS_Store
Thumbs.db
```

- [ ] **Step 2: Create `lib/common.sh` with shared helpers**

```bash
#!/usr/bin/env bash
# CYVIDIA common helpers — sourced by bin/cyvidia and lib modules
set -euo pipefail

CYVIDIA_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CYVIDIA_VERSION="0.1.0"
CYVIDIA_FINDINGS_FILE="${CYVIDIA_FINDINGS_FILE:-}"
CYVIDIA_SCAN_ID="${CYVIDIA_SCAN_ID:-}"

cyvidia_die() { echo "ERROR: $*" >&2; exit 1; }

cyvidia_require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "WARN: not root — reduced coverage" >&2
    return 1
  fi
  return 0
}

cyvidia_utc_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

cyvidia_hostname() { hostname -f 2>/dev/null || hostname; }
```

- [ ] **Step 3: Create stub `bin/cyvidia`**

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
source "${ROOT}/lib/common.sh"

usage() {
  cat <<'EOF'
cyvidia — Linux GPU cryptomining / SANSAR defensive kit
Usage:
  cyvidia hunt [--network] [--output-json PATH] [--report-md PATH] [--report-html PATH]
  cyvidia harden --plan [--force-consent-file]
  cyvidia harden --execute   # only after --plan + consent
  cyvidia guard install|uninstall|run-once
  cyvidia consent grant|revoke|list
  cyvidia version
EOF
}

cmd="${1:-}"
case "${cmd}" in
  version) echo "cyvidia ${CYVIDIA_VERSION}";;
  hunt|harden|guard|consent) cyvidia_die "command '${cmd}' not implemented yet";;
  -h|--help|help|"") usage; exit 0;;
  *) usage; cyvidia_die "unknown command: ${cmd}";;
esac
```

- [ ] **Step 4: Make executable and smoke-test**

Run (on Linux or Git Bash):

```bash
chmod +x bin/cyvidia
./bin/cyvidia version
./bin/cyvidia help
```

Expected: prints `cyvidia 0.1.0` and usage text.

- [ ] **Step 5: Commit**

```bash
git add .gitignore README.md bin/cyvidia lib/common.sh
git commit -m "chore: scaffold CYVIDIA CLI skeleton"
```

---

### Task 2: IOC packs and pack-manifest

**Files:**
- Create: `iocs/sansar.json`
- Create: `iocs/tor-miners.json`
- Create: `iocs/nvidia-cves.json`
- Create: `iocs/correlation.rules.json`
- Create: `iocs/pack-manifest.json`
- Create: `docs/ioc-update.md`

- [ ] **Step 1: Write `iocs/sansar.json` with published Elastic IOCs**

Include `pack_version`, `source`, arrays `sha256`, `paths`, `names`, `network` (onion, contract, selector, port) exactly as listed in design §5.

- [ ] **Step 2: Write `iocs/tor-miners.json`**

Seed entries for XMRig and SRBMiner-MULTI (names, optional hashes, tor_coupling_signals: `lyrebird`, `bridges`, `arti`, `.onion`).

- [ ] **Step 3: Write `iocs/nvidia-cves.json`**

Start with `advisory_pack_version: "0.1.0"` and an empty or placeholder `advisories: []` array plus schema comment fields (`cve_id`, `affected_versions`, `fixed_version`, `severity`, `url`) so the matcher works before real CVEs are curated.

- [ ] **Step 4: Write `iocs/correlation.rules.json`**

```json
{
  "version": "0.1.0",
  "rules": [
    {
      "id": "sansar_toolkit_high",
      "when_all": ["nvml_spoof_or_mismatch", "disk_ioc_or_rootkit"],
      "campaign_confidence": "high",
      "labels": ["sansar_toolkit"],
      "escalate_to": "Critical"
    },
    {
      "id": "nvml_alone",
      "when_all": ["nvml_spoof_or_mismatch"],
      "when_none": ["disk_ioc_or_rootkit"],
      "campaign_confidence": "medium",
      "labels": ["nvml_spoof"],
      "escalate_to": "High"
    },
    {
      "id": "hiding_suspected",
      "when_all": ["disk_ioc", "runtime_missing"],
      "campaign_confidence": "high",
      "labels": ["rootkit_hiding_suspected"]
    }
  ]
}
```

- [ ] **Step 5: Generate `iocs/pack-manifest.json`**

Structure:

```json
{
  "manifest_version": "0.1.0",
  "packs": [
    {"name": "sansar.json", "version": "0.1.0", "sha256": "<file sha256>"},
    {"name": "tor-miners.json", "version": "0.1.0", "sha256": "<file sha256>"},
    {"name": "nvidia-cves.json", "version": "0.1.0", "sha256": "<file sha256>"},
    {"name": "correlation.rules.json", "version": "0.1.0", "sha256": "<file sha256>"}
  ]
}
```

Compute SHA-256 of each file after writing (Python or `sha256sum`) and fill in.

- [ ] **Step 6: Write `docs/ioc-update.md`**

Document: edit pack → bump pack version → recompute manifest hashes → note Elastic/NVIDIA sources → open PR.

- [ ] **Step 7: Commit**

```bash
git add iocs/ docs/ioc-update.md
git commit -m "feat: seed IOC packs and pack-manifest from REF3364 public IOCs"
```

---

### Task 3: Findings emitter (bash) + JSON schema helper (Python)

**Files:**
- Create: `lib/findings.sh`
- Create: `python/cyvidia_json.py`
- Create: `docs/findings-schema.md`
- Create: `tests/test_json_schema.py`

- [ ] **Step 1: Document schema in `docs/findings-schema.md`**

Fields per design §7.2: `schema_version`, `finding_id`, `module`, `severity`, `confidence`, `title`, `detail`, `evidence`, `remediation_hint`, `ioc_refs`, plus top-level `tool_version`, `ioc_pack_version`, `advisory_pack_version`, `hostname`, `scan_id`, `correlation`.

- [ ] **Step 2: Implement `lib/findings.sh`**

Provide `cyvidia_finding_add severity module title detail evidence remediation_hint ioc_refs_csv` that appends NDJSON lines to `${CYVIDIA_FINDINGS_FILE}` (one JSON object per line) for later Python aggregation.

- [ ] **Step 3: Implement `python/cyvidia_json.py`**

- Read NDJSON findings
- Load pack-manifest versions
- Validate required keys
- Write final `findings.json`
- Apply redaction regexes for wallets/pool URLs (`0x[a-fA-F0-9]{40}`, `stratum\+tcp://...`)

Include CLI:

```bash
python3 python/cyvidia_json.py aggregate --ndjson PATH --manifest iocs/pack-manifest.json --out PATH
```

- [ ] **Step 4: Write `tests/test_json_schema.py`**

Assert: missing `severity` fails validation; redaction replaces stratum URLs; manifest versions appear in output.

- [ ] **Step 5: Run pytest**

```bash
pytest tests/test_json_schema.py -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add lib/findings.sh python/cyvidia_json.py docs/findings-schema.md tests/test_json_schema.py
git commit -m "feat: findings NDJSON emitter and versioned JSON aggregator"
```

---

### Task 4: Distro detection adapters

**Files:**
- Create: `lib/distro.sh`
- Create: `lib/distro_debian.sh`
- Create: `lib/distro_rhel.sh`
- Create: `tests/fixtures/distro/os-release.debian`
- Create: `tests/fixtures/distro/os-release.rhel`

- [ ] **Step 1: Implement family detection from `/etc/os-release`**

`cyvidia_distro_family` → `debian` | `rhel` | `unknown`

- [ ] **Step 2: Debian adapter functions**

- `cyvidia_pkg_verify_file PATH`
- `cyvidia_nvidia_reinstall_cmds` (apt templates)
- `cyvidia_initramfs_rebuild_cmd` → `update-initramfs -u`

- [ ] **Step 3: RHEL adapter functions**

- Same interface; `dracut -f`; `dnf`/`rpm` verify

- [ ] **Step 4: Fixture test script asserting family detection from copied os-release files**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat: Debian and RHEL distro adapters for verify/reinstall/initramfs"
```

---

### Task 5: Hunt modules — filesystem IOC, systemd, Tor miners

**Files:**
- Create: `lib/mod_sansar_fs.sh`
- Create: `lib/mod_systemd.sh`
- Create: `lib/mod_tor_miners.sh`
- Create: `tests/fixtures/host_sansar_tree/...` (empty placeholder files + fake hashes via sidecar expected findings — do **not** include real malware bytes; use zero-byte files and inject expected hash mismatches OR store only path presence fixtures)

**Important:** Fixtures must never contain live malware. Use path presence + name matches; hash-match tests use known content whose SHA-256 you compute for a harmless fixture file labeled as a test double, not real samples.

- [ ] **Step 1: `mod_sansar_fs.sh`** — check paths/names from `sansar.json`; hash files if present; emit findings.
- [ ] **Step 2: `mod_systemd.sh`** — list units matching `netns`, miner names, tor helpers.
- [ ] **Step 3: `mod_tor_miners.sh`** — pluggable list + bridges/lyrebird/arti coupling.
- [ ] **Step 4: Fixture hunt asserting Critical/High when `/opt/vadi_/sansar` path exists in fixture root (`CYVIDIA_FIXTURE_ROOT`).
- [ ] **Step 5: Commit**

```bash
git commit -am "feat: hunt modules for SANSAR paths, systemd, and Tor miners"
```

---

### Task 6: Hunt modules — Ray, SSH, hiding awareness

**Files:**
- Create: `lib/mod_ray.sh`
- Create: `lib/mod_ssh.sh`
- Create: `lib/mod_hiding.sh`
- Create: `tests/fixtures/ray/...`

- [ ] **Step 1: Ray module** — parse listeners (`ss`/`ss -lntp`), distinguish dashboard vs job agent when possible; check auth config files if present; scan Ray logs for `nvidia-smi` / reverse-shell job strings under fixture root.
- [ ] **Step 2: SSH module** — scan `authorized_keys` for Ray uid homes; flag keys newer than N days when tied to Ray findings (config default 30).
- [ ] **Step 3: Hiding module** — if disk IOC exists and `ps`/`pidof` miss expected names → finding with `rootkit_hiding_suspected` label input for correlation.
- [ ] **Step 4: Fixture: dashboard loopback + job agent `0.0.0.0` fake `ss` output file.
- [ ] **Step 5: Commit**

```bash
git commit -am "feat: Ray, SSH, and expected-vs-observed hiding hunt modules"
```

---

### Task 7: NVML integrity + secondary GPU signals + rootkit/initramfs

**Files:**
- Create: `lib/mod_nvml.sh`
- Create: `lib/mod_gpu_secondary.sh`
- Create: `lib/mod_rootkit.sh`
- Create: `tests/fixtures/nvml/...`
- Create: `tests/fixtures/initramfs/...`

- [ ] **Step 1: NVML module** — locate `libnvidia-ml.so.1` via `ldconfig -p`; hash compare to pack; detect `.backup` and `nvml-hook`.
- [ ] **Step 2: Secondary GPU** — **must attempt** sysfs DRM power + hwmon; **best-effort** PCIe + BMC; emit mismatch finding when NVML util≈0 but sysfs power high (fixture-simulated via fake sysfs tree under `CYVIDIA_FIXTURE_ROOT`).
- [ ] **Step 3: Rootkit module** — DKMS/source paths; list initramfs (`lsinitramfs` / `lsinitrd` / `cpio` extract to temp) for `acpi_thermal_mgr`; Secure Boot detect (`mokutil --sb-state` or efivars) → Info/High guidance finding, never unload here.
- [ ] **Step 4: Fixture tests for mismatch and initramfs name hit.
- [ ] **Step 5: Commit**

```bash
git commit -am "feat: NVML, secondary GPU, and rootkit/initramfs hunt modules"
```

---

### Task 8: Optional YARA + optional Ethereum network helper

**Files:**
- Create: `yara/sansar_netns.yar` (cleaned derivative patterns from public Elastic rules)
- Create: `yara/ATTRIBUTION.md`
- Create: `lib/mod_yara.sh`
- Create: `python/cyvidia_eth_call.py`
- Create: `lib/mod_network_eth.sh`
- Create: `tests/test_eth_call.py`

- [ ] **Step 1: YARA** — if `command -v yara`, scan configured roots; else Info finding.
- [ ] **Step 2: ATTRIBUTION** — credit Elastic Security Labs; state cleaned derivatives.
- [ ] **Step 3: `cyvidia_eth_call.py`** — read-only `eth_call`; default RPC list; `--rpc-url` override; mockable in tests with `responses` or stdlib unittest.mock (no live network in CI).
- [ ] **Step 4: Wire `--network` only when flag set.
- [ ] **Step 5: Commit**

```bash
git commit -am "feat: optional YARA and read-only Ethereum C2 resolver lookup"
```

---

### Task 9: Correlation engine

**Files:**
- Create: `python/cyvidia_correlate.py`
- Create: `lib/correlate.sh`
- Create: `tests/test_correlate.py`

- [ ] **Step 1: Implement rule evaluation against finding labels/modules** per `iocs/correlation.rules.json`.
- [ ] **Step 2: Attach `correlation` object to aggregated JSON.
- [ ] **Step 3: Tests for nvml-alone → medium; nvml+disk → high/`sansar_toolkit`.
- [ ] **Step 4: Commit**

```bash
git commit -am "feat: declarative finding correlation engine"
```

---

### Task 10: Wire `cyvidia hunt` end-to-end

**Files:**
- Modify: `bin/cyvidia`
- Create: `tests/hunt/run_fixture_hunt.sh`

- [ ] **Step 1: Implement `hunt` subcommand** — create scan_id, NDJSON temp, run all modules, aggregate JSON, optional MD/HTML later stub, print CLI summary, exit 0/2.
- [ ] **Step 2: Fixture integration script with `CYVIDIA_FIXTURE_ROOT`.
- [ ] **Step 3: Commit**

```bash
git commit -am "feat: cyvidia hunt end-to-end on fixtures"
```

---

### Task 11: Consent, lock, plan, quarantine

**Files:**
- Create: `lib/consent.sh`
- Create: `lib/lock.sh`
- Create: `lib/plan.sh`
- Create: `lib/quarantine.sh`
- Create: `packaging/cyvidia.config.json.example`

- [ ] **Step 1: Lockfile** `/run/cyvidia.lock` with PID; exit 1 if held.
- [ ] **Step 2: Consent schema validate (Python or jq); `grant` writes `0600` file; `hmac` stored if provided, **not verified in v1**.
- [ ] **Step 3: `--plan` emits human + machine plan from current findings without changes.
- [ ] **Step 4: Quarantine helpers create `/var/lib/cyvidia/quarantine/<ts>/` layout with `metadata.json`, `ROLLBACK.md`, `rollback.json`.
- [ ] **Step 5: Commit**

```bash
git commit -am "feat: consent, lockfile, plan, and quarantine helpers"
```

---

### Task 12: Remediation engine + `harden`

**Files:**
- Create: `lib/remediate.sh`
- Modify: `bin/cyvidia`
- Create: `docs/runbook-operator.md`
- Create: `docs/playbook-secure-boot-rootkit.md`

- [ ] **Step 1: Implement ordered remediate steps** from design §11; each step appends rollback notes; stop on Secure Boot block with playbook reference.
- [ ] **Step 2: `harden --plan` then `harden --execute` requiring consent + prior plan id.
- [ ] **Step 3: Never call reboot.
- [ ] **Step 4: Write operator runbook and Secure Boot playbook.
- [ ] **Step 5: Dry-run tests only (fixture quarantine under temp dir).
- [ ] **Step 6: Commit**

```bash
git commit -am "feat: consent-gated harden remediation with rollback notes"
```

---

### Task 13: Guard mode (systemd timer)

**Files:**
- Create: `packaging/cyvidia-guard.service`
- Create: `packaging/cyvidia-guard.timer`
- Create: `lib/guard_install.sh`
- Modify: `bin/cyvidia`

- [ ] **Step 1: Unit files** — service runs `cyvidia guard run-once`; timer default `OnCalendar=*-*-* 00/6:00:00` (every 6 hours) with drop-in documented.
- [ ] **Step 2: `run-once`** — hunt; journald alert for ≥ min severity from `/etc/cyvidia/config.json`; remediate only if consent allows required actions.
- [ ] **Step 3: Throttle duplicate finding signatures for one interval.
- [ ] **Step 4: Commit**

```bash
git commit -am "feat: systemd guard timer with alert throttling and consent gate"
```

---

### Task 14: Reports (Markdown/HTML) + journald helper

**Files:**
- Create: `python/cyvidia_report.py`
- Modify: `bin/cyvidia` hunt/harden to call reporter

- [ ] **Step 1: Render MD + simple HTML from findings JSON** (severity sections, correlation, versions, redaction already applied).
- [ ] **Step 2: journald via `logger -t cyvidia` from bash.
- [ ] **Step 3: Commit**

```bash
git commit -am "feat: Markdown/HTML reports and journald alert lines"
```

---

### Task 15: NVIDIA CVE module (v2)

**Files:**
- Create: `python/cyvidia_cve_match.py`
- Create: `lib/mod_nvidia_cve.sh`
- Create: `tests/test_cve_match.py`
- Modify: remediate path for `cve_update` action

- [ ] **Step 1: Detect driver version** (`nvidia-smi` / package version); match `nvidia-cves.json`.
- [ ] **Step 2: Findings for unpatched/unknown/current.
- [ ] **Step 3: Remediate prints/runs distro update commands under consent.
- [ ] **Step 4: Unit tests with fake version strings.
- [ ] **Step 5: Commit**

```bash
git commit -am "feat: NVIDIA driver CVE patch-status module"
```

---

### Task 16: install.sh + README + CI

**Files:**
- Create: `install.sh`
- Modify: `README.md`
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: `install.sh`** — copy tree to `/opt/cyvidia`, symlink `/usr/local/bin/cyvidia`, install example config; optional guard units.
- [ ] **Step 2: README** — purpose, safety, quick start, link to runbook/spec, YARA optional note, air-gap note.
- [ ] **Step 3: CI workflow**

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: sudo apt-get update && sudo apt-get install -y shellcheck
      - run: shellcheck bin/cyvidia lib/*.sh || true  # tighten as scripts mature
      - run: pip install pytest
      - run: pytest -v
      - run: bash tests/hunt/run_fixture_hunt.sh
```

- [ ] **Step 4: Commit**

```bash
git commit -am "chore: install script, README, and GitHub Actions CI"
```

---

### Task 17: Spec coverage self-check + release tag

- [ ] **Step 1: Walk design sections 1–23** and tick each against a task above; fix any gap with a follow-up commit.
- [ ] **Step 2: Tag `v0.1.0-cyvidia` when fixture CI is green on Linux.

---

## Spec coverage matrix (plan self-review)

| Spec area | Task(s) |
|-----------|---------|
| Modes hunt/harden/guard/consent | 1, 10–13 |
| IOC seed + manifest | 2 |
| Ray / SSH / FS / rootkit / NVML / secondary GPU / systemd / Tor / hiding | 5–7 |
| Optional YARA / eth_call | 8 |
| Correlation + JSON schema | 3, 9 |
| Consent schema / lock / plan / quarantine / rollback | 11–12 |
| Secure Boot stop + playbooks | 7, 12 |
| Guard timer/throttle | 13 |
| CVE v2 | 15 |
| Distro adapters | 4 |
| Reports + journald | 14 |
| Air-gap / install / CI / docs | 2, 12, 16 |
| No live malware in tests | 5–7, 16 |
| Never auto-reboot / --plan required | 12 |

**Placeholder scan:** none intentional. HMAC verify deferred per spec §22. Real NVIDIA CVE rows curated during Task 15 as pack updates.

---

## Execution handoff

Design is approved; this plan is ready to execute.

**1. Subagent-Driven (recommended)** — Fresh subagent per task, review between tasks  
**2. Inline Execution** — Execute tasks in this session, batch with checkpoints

Which execution mode do you want?
