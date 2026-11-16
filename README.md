# CYVIDIA

Linux host defensive kit for **REF3364 / SANSAR-style** GPU cryptomining, Tor-linked miners, Ray exposure, NVML integrity spoofing, rootkit/initramfs artifacts, and NVIDIA driver CVE patch-status.

**Authorized defensive use only.** No warranty.

## Quick start (Linux)

```bash
chmod +x bin/cyvidia install.sh
./bin/cyvidia version
./bin/cyvidia hunt --output-json /tmp/cyvidia.json --report-md /tmp/cyvidia.md
./bin/cyvidia harden --plan --findings /tmp/cyvidia.json
./bin/cyvidia consent grant "$USER" 24
# then: ./bin/cyvidia harden --execute --plan-file /path/from/plan
```

Optional install:

```bash
sudo ./install.sh /opt/cyvidia
sudo cyvidia guard install   # systemd timer; alert-oriented
```

## Modes

| Mode | Behavior |
|------|----------|
| `hunt` | Read-only checks → CLI + JSON (+ optional MD/HTML) |
| `harden --plan` | Required dry-run plan from findings |
| `harden --execute` | Full remediation only with consent; never auto-reboot |
| `guard` | Timer / run-once alerts via journald |
| `consent` | `grant` / `revoke` / `list` |

## Safety

- Air-gapped hunt works; `--network` is optional read-only Ethereum `eth_call`
- Quarantine under `/var/lib/cyvidia/quarantine/<timestamp>/`
- Tests use fixtures only — **no live malware**
- Develop on Windows if needed; **run on Linux**

## Docs (product)

- Operator runbook: `docs/runbook-operator.md`
- Secure Boot playbook: `docs/playbook-secure-boot-rootkit.md`
- IOC updates: `docs/ioc-update.md`
- Findings schema: `docs/findings-schema.md`
- Arya QA harness notes: `docs/qa-arya-cdp.md`

Design/implementation planning lives under `local/planning/` (gitignored; not published to GitHub).

## Tests

```bash
python -m pytest -v
bash tests/hunt/run_fixture_hunt.sh
```

## Research credit

Elastic Security Labs — REF3364 / SANSAR public research. YARA rules are cleaned derivatives; see `yara/ATTRIBUTION.md`.
