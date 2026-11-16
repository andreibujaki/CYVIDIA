# CYVIDIA findings JSON schema (v0.1.0)

## Top-level document

| Field | Type | Meaning |
|-------|------|---------|
| `schema_version` | string | Findings document schema version |
| `tool_version` | string | CYVIDIA tool version |
| `ioc_pack_version` | string | From `sansar.json` via pack-manifest |
| `advisory_pack_version` | string | From `nvidia-cves.json` |
| `correlation_rules_version` | string | From `correlation.rules.json` |
| `tor_miners_pack_version` | string | From `tor-miners.json` |
| `manifest_version` | string | Pack manifest version |
| `hostname` | string | Scanned host |
| `scan_id` | string | Unique scan identifier |
| `generated_at` | string | UTC ISO-8601 |
| `findings` | array | Finding objects |
| `correlation` | object | Campaign confidence summary |

## Finding object

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | string | yes | Finding object schema |
| `finding_id` | string | yes | UUID |
| `module` | string | yes | Check module name |
| `severity` | string | yes | Critical/High/Medium/Low/Info |
| `confidence` | string | yes | low/medium/high |
| `title` | string | yes | Short title |
| `detail` | string | no | Human detail |
| `evidence` | string | no | Paths, hashes, excerpts (redacted) |
| `remediation_hint` | string | no | Action family hint |
| `ioc_refs` | array[string] | no | IOC pack references |
| `labels` | array[string] | no | Correlation input labels |
| `timestamp` | string | no | UTC time emitted |

## Correlation object

| Field | Type | Meaning |
|-------|------|---------|
| `campaign_confidence` | string | none/low/medium/high |
| `labels` | array[string] | Aggregated labels |
| `matched_rules` | array[string] | Rule ids from `correlation.rules.json` |

## Redaction

Aggregator redacts stratum pool URLs, long hex wallet-like values, and `wallet=` / `login=` / `password=` style assignments before durable output.
