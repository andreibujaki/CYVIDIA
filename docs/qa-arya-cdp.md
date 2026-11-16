# CYVIDIA QA via Arya CDP test framework

CYVIDIA is exercised as a first-class project inside  
`D:\rtx\arya-guard-cdp-tests` using the **`cyvidia` adapter** (CLI/fixture driver, not Electron CDP).

## Run

```powershell
cd D:\rtx\arya-guard-cdp-tests
$env:CYVIDIA_ROOT = "D:\CYBERSEC\CYVIDIA"
npm run test:cyvidia
```

Or:

```powershell
node packages/cli/src/cli.mjs --project cyvidia --suite cyvidia
```

## Suite cases

| ID | What it checks |
|----|----------------|
| C1-hunt-fixture | Fixture hunt detects SANSAR + correlation |
| C2-harden-fixture | Plan → consent → quarantine checkpoint |
| C3-pytest | Python unit tests |
| C4-cve-pack | NVIDIA advisory pack non-empty |
| C5-ioc-manifest | pack-manifest intact |

## Oracles

`cyvidiaHuntOk`, `cyvidiaCriticalOrHigh`, `cyvidiaSansarCorrelation`, `cyvidiaHardenOk`, `cyvidiaPytestOk`, `cyvidiaCvePackOk`, `cyvidiaManifestOk`

Reports land under `D:\rtx\arya-guard-cdp-tests\sessions\latest\` (`REPORT.md`, `REPORT.json`, JUnit).
