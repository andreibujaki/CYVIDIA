#!/usr/bin/env python3
"""Aggregate CYVIDIA NDJSON findings into a versioned findings JSON document."""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "0.1.0"
TOOL_VERSION = "0.1.0"

REDACT_PATTERNS = [
    (re.compile(r"stratum\+tcp://[^\s\"']+", re.I), "stratum+tcp://***"),
    (re.compile(r"stratum\+ssl://[^\s\"']+", re.I), "stratum+ssl://***"),
    (re.compile(r"\b0x[a-fA-F0-9]{40}\b"), "0x***REDACTED***"),
    (re.compile(r"(?i)(wallet|login|user|pass(?:word)?)\s*[:=]\s*\S+"), r"\1=***"),
]

REQUIRED_FINDING_KEYS = {
    "schema_version",
    "finding_id",
    "module",
    "severity",
    "confidence",
    "title",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact_text(value: str) -> str:
    out = value
    for pattern, repl in REDACT_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj


def load_ndjson(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not path.exists():
        return findings
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid NDJSON at {path}:{line_no}: {exc}") from exc
        missing = REQUIRED_FINDING_KEYS - set(obj)
        if missing:
            raise SystemExit(f"finding missing keys {sorted(missing)} at {path}:{line_no}")
        findings.append(obj)
    return findings


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def pack_versions(manifest: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for pack in manifest.get("packs", []):
        out[pack["name"]] = pack.get("version", "unknown")
    return out


def aggregate(
    ndjson_path: Path,
    manifest_path: Path,
    out_path: Path,
    scan_id: str,
    hostname: str | None = None,
    correlation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    findings = [redact_obj(f) for f in load_ndjson(ndjson_path)]
    manifest = load_manifest(manifest_path)
    versions = pack_versions(manifest)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "ioc_pack_version": versions.get("sansar.json", "unknown"),
        "advisory_pack_version": versions.get("nvidia-cves.json", "unknown"),
        "correlation_rules_version": versions.get("correlation.rules.json", "unknown"),
        "tor_miners_pack_version": versions.get("tor-miners.json", "unknown"),
        "manifest_version": manifest.get("manifest_version", "unknown"),
        "hostname": hostname or socket.gethostname(),
        "scan_id": scan_id,
        "generated_at": utc_now(),
        "findings": findings,
        "correlation": correlation
        or {
            "campaign_confidence": "none",
            "labels": [],
            "matched_rules": [],
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CYVIDIA findings JSON aggregator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    agg = sub.add_parser("aggregate", help="Aggregate NDJSON findings")
    agg.add_argument("--ndjson", required=True, type=Path)
    agg.add_argument("--manifest", required=True, type=Path)
    agg.add_argument("--out", required=True, type=Path)
    agg.add_argument("--scan-id", required=True)
    agg.add_argument("--hostname", default=None)
    agg.add_argument("--correlation-json", default=None, help="Optional correlation JSON object/file")

    args = parser.parse_args(argv)
    if args.cmd == "aggregate":
        correlation = None
        if args.correlation_json:
            p = Path(args.correlation_json)
            if p.exists():
                correlation = json.loads(p.read_text(encoding="utf-8"))
            else:
                correlation = json.loads(args.correlation_json)
        aggregate(
            args.ndjson,
            args.manifest,
            args.out,
            args.scan_id,
            hostname=args.hostname,
            correlation=correlation,
        )
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
