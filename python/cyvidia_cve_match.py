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


def branch_major(ver: tuple[int, ...]) -> int:
    return int(ver[0]) if ver else 0


def is_unpatched(ver: tuple[int, ...], adv: dict) -> bool:
    """True when installed version is on the advisory branch and below fixed_version."""
    fixed = adv.get("fixed_version")
    if not fixed:
        return False
    fixed_t = parse_version(fixed)
    major = adv.get("branch_major")
    if major is None:
        major = branch_major(fixed_t)
    if branch_major(ver) != int(major):
        return False
    affected_from = adv.get("affected_from")
    if affected_from and ver < parse_version(affected_from):
        return False
    affected_to = adv.get("affected_to")
    if affected_to and ver > parse_version(affected_to):
        return False
    return ver < fixed_t


def match(version: str, pack_path: Path) -> list[tuple[str, str, str, str]]:
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    advisories = [a for a in (pack.get("advisories") or []) if a.get("os", "linux") == "linux"]
    ver = parse_version(version)
    rows: list[tuple[str, str, str, str]] = []
    if not advisories:
        rows.append(("Info", f"Driver {version} — advisory pack empty", "No CVE rows curated yet", version))
        return rows

    seen: set[str] = set()
    for adv in advisories:
        if not is_unpatched(ver, adv):
            continue
        cve = adv.get("cve_id", "CVE-UNKNOWN")
        key = f"{cve}:{adv.get('fixed_version')}"
        if key in seen:
            continue
        seen.add(key)
        sev = adv.get("severity", "High")
        rows.append(
            (
                sev,
                f"Unpatched {cve} for driver {version}",
                f"fixed_version>={adv.get('fixed_version')} bulletin={adv.get('bulletin','')} url={adv.get('url','')}",
                version,
            )
        )

    if not rows:
        rows.append(
            (
                "Info",
                f"Driver {version} has no matching unpatched Linux advisories in pack",
                f"advisory_pack_version={pack.get('advisory_pack_version')} branch_major={branch_major(ver)}",
                version,
            )
        )
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
