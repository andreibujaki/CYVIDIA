# CYVIDIA

**CYVIDIA** is a Linux host defensive kit for **REF3364 / SANSAR-style** GPU cryptojacking and related abuse: exposed Ray job APIs, dishonest NVIDIA Management Library (**NVML**) telemetry, Tor-linked miners, rootkit/initramfs persistence, and NVIDIA driver CVE patch-status.

Built for GPU / AI platform teams who need something they can **run on the host**—readable, auditable, and safe by default.

**Authorized defensive use only.** No warranty.

---

## What it does

| Mode | What happens |
|------|----------------|
| `hunt` | **Read-only** checks → CLI + versioned JSON (+ optional Markdown/HTML) |
| `harden --plan` | Required dry-run plan derived from findings |
| `harden --execute` | Remediation **only with consent**; never auto-reboots |
| `guard` | systemd timer / run-once alerts via journald |
| `consent` | `grant` / `revoke` / `list` (hostname-bound, time-limited) |

### Hunt coverage (high level)

- Ray job-agent exposure (listeners, logs, auth gaps)
- SSH key persistence heuristics on Ray-like accounts
- SANSAR filesystem IoCs (`/opt/vadi_/`, NVML `.backup`, rootkit source trees, hashes)
- systemd unit hints (`netns`, miners, Tor helpers)
- Tor-linked miner coupling (pluggable pack)
- Expected-versus-observed hiding signals
- NVML integrity + secondary GPU telemetry (sysfs / hwmon)
- Rootkit / initramfs / Secure Boot guidance
- Optional YARA; optional read-only Ethereum `eth_call` (`--network`)
- NVIDIA Linux driver CVE patch-status (vendor updates only—**no homemade driver binaries**)

Findings can correlate into campaign labels such as `sansar_toolkit`. Quarantine lands under `/var/lib/cyvidia/quarantine/<timestamp>/` with rollback notes.

---

## How to use it

### Requirements

- **Run on Linux** GPU hosts (Debian/Ubuntu or RHEL-family). You may author on Windows; runtime truth is Linux.
- Root (or equivalent) for full listener / package-verify / remediation visibility.
- Optional: `yara`, outbound HTTPS only if you pass `--network`.

### Quick start

```bash
chmod +x bin/cyvidia install.sh
./bin/cyvidia version

# 1) Read-only hunt
./bin/cyvidia hunt --output-json /tmp/cyvidia.json --report-md /tmp/cyvidia.md

# 2) Required plan (no changes yet)
./bin/cyvidia harden --plan --findings /tmp/cyvidia.json

# 3) Consent, then execute (IR-approved only)
./bin/cyvidia consent grant "$USER" 24
./bin/cyvidia harden --execute --plan-file /path/from/plan

# 4) Verify
./bin/cyvidia hunt --output-json /tmp/cyvidia-after.json
```

Exit codes: `0` = no Critical/High · `2` = Critical/High · `3` = consent required/refused · `1` = tool/lock failure.

### Install (optional)

```bash
sudo ./install.sh /opt/cyvidia
sudo cyvidia guard install   # alert-oriented timer; remediates only with consent
```

### Air-gapped racks

Omit `--network`. Refresh IOC JSON offline per `docs/ioc-update.md`.

### Safety rules (non-negotiable)

- Hunt does not quarantine, unload modules, or rewrite keys.
- Harden never auto-reboots (especially Secure Boot hosts—see `docs/playbook-secure-boot-rootkit.md`).
- Restore NVML only from **vendor/distro packages**.
- Tests use **fixtures only**—no live malware samples in this repository.

---

## Repository layout

```text
bin/cyvidia          # CLI entrypoint
lib/                 # Bash modules + distro adapters
python/              # Reports, correlation, CVE match, eth_call helper
iocs/                # sansar, tor-miners, nvidia-cves, correlation, pack-manifest
yara/                # Optional cleaned-derivative rules (+ ATTRIBUTION)
docs/                # Operator runbook, Secure Boot playbook, IOC update, schema
tests/               # Fixture hunts + pytest
packaging/           # systemd unit/timer examples
install.sh
tools/               # Maintainer helpers (e.g. local diagram renderer)
```

Long-form LinkedIn articles, banners, and design planning under `local/` are **gitignored** and are not published.

---

## Docs

| Doc | Purpose |
|-----|---------|
| `docs/runbook-operator.md` | Day-to-day operator steps |
| `docs/playbook-secure-boot-rootkit.md` | Secure Boot / rootkit removal discipline |
| `docs/ioc-update.md` | How to refresh packs |
| `docs/findings-schema.md` | JSON findings shape |
| `docs/qa-arya-cdp.md` | Arya CDP QA harness notes |

---

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -v
bash tests/hunt/run_fixture_hunt.sh
# optional harden fixture:
bash tests/harden/run_fixture_harden.sh
```

CI: `.github/workflows/ci.yml`.

---

## Research credit

- Elastic Security Labs — [0% GPU utilization: How SANSAR hides Linux cryptomining](https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware) (REF3364 / SANSAR)
- Related Ray exposure context: Oligo ShadowRay / ShadowRay 2.0 public research
- YARA: cleaned derivatives; see `yara/ATTRIBUTION.md`

---

## Custom solutions

For custom detection / remediation engineering around GPU estates, Ray exposure, and NVML integrity programs: **AryaNet Security Custom solutions** — [@Andrei.Bujaki](https://www.linkedin.com/in/andrei-bujaki/).
