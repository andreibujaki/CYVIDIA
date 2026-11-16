#!/usr/bin/env python3
"""Evaluate declarative correlation rules against finding labels."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def collect_labels(findings: list[dict[str, Any]]) -> set[str]:
    labels: set[str] = set()
    for f in findings:
        for lab in f.get("labels", []) or []:
            labels.add(lab)
        # derive convenience flags
        sev = f.get("severity", "")
        mod = f.get("module", "")
        if mod in {"sansar_fs", "tor_miners"} and sev in {"Critical", "High"}:
            labels.add("disk_ioc")
            labels.add("disk_ioc_or_rootkit")
        if mod in {"nvml", "gpu_secondary"} and sev in {"Critical", "High"}:
            labels.add("nvml_spoof_or_mismatch")
        if mod == "rootkit" and sev in {"Critical", "High"}:
            labels.add("disk_ioc_or_rootkit")
        if mod == "ray" and "ray_job_agent_exposed" in (f.get("labels") or []):
            labels.add("ray_job_agent_exposed")
        if mod == "hiding" and "runtime_missing" in (f.get("labels") or []):
            labels.add("runtime_missing")
            labels.add("disk_ioc")
    return labels


def evaluate(rules_path: Path, findings: list[dict[str, Any]]) -> dict[str, Any]:
    rules_doc = json.loads(rules_path.read_text(encoding="utf-8"))
    labels = collect_labels(findings)
    matched: list[str] = []
    out_labels: set[str] = set()
    confidence = "none"
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}

    for rule in rules_doc.get("rules", []):
        need = set(rule.get("when_all", []))
        forbid = set(rule.get("when_none", []))
        if need and not need.issubset(labels):
            continue
        if forbid & labels:
            continue
        matched.append(rule["id"])
        out_labels.update(rule.get("labels", []))
        conf = rule.get("campaign_confidence", "low")
        if order.get(conf, 0) > order.get(confidence, 0):
            confidence = conf

    return {
        "campaign_confidence": confidence,
        "labels": sorted(out_labels),
        "matched_rules": matched,
        "input_labels": sorted(labels),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--findings-json", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    doc = json.loads(args.findings_json.read_text(encoding="utf-8"))
    findings = doc.get("findings", doc if isinstance(doc, list) else [])
    result = evaluate(args.rules, findings)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
