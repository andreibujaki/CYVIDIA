#!/usr/bin/env python3
"""Match installed NVIDIA driver version against advisory pack."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def parse_version(v: str) -> tuple[int, ...]:
    parts: list[int] = []
    for p in v.replace("-", ".").split("."):
        if p.isdigit():
            parts.append(int(p))
        else:
            num = "".join(ch for ch in p if ch.isdigit())
            parts.append(int(num) if num else 0)
    return tuple(parts) if parts else (0,)


def in_range(ver: tuple[int, ...], low: str | None, high: str | None) -> bool:
    if low and ver < parse_version(low):
        return False
    if high and ver > parse_version(high):
        return False
    return True


def match(version: str, pack_path: Path) -> list[tuple[str, str, str, str]]:
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    advisories = pack.get("advisories") or []
    ver = parse_version(version)
    rows: list[tuple[str, str, str, str]] = []
    if not advisories:
        rows.append(("Info", f"Driver {version} — advisory pack empty", "No CVE rows curated yet", version))
        return rows
    hits = 0
    for adv in advisories:
        affected_low = adv.get("affected_from")
        affected_high = adv.get("affected_to")
        fixed = adv.get("fixed_version")
        if in_range(ver, affected_low, affected_high):
            if fixed and ver >= parse_version(fixed):
                continue
            sev = adv.get("severity", "High")
            cve = adv.get("cve_id", "CVE-UNKNOWN")
            rows.append(
                (
                    sev,
                    f"Unpatched {cve} for driver {version}",
                    f"fixed_version={fixed} url={adv.get('url','')}",
                    version,
                )
            )
            hits += 1
    if hits == 0:
        rows.append(("Info", f"Driver {version} has no matching unpatched advisories", "current or unknown", version))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--pack", required=True, type=Path)
    args = parser.parse_args(argv)
    for sev, title, detail, evidence in match(args.version, args.pack):
        print(f"{sev}\t{title}\t{detail}\t{evidence}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
