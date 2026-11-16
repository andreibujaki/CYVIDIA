#!/usr/bin/env python3
"""Render Markdown and simple HTML reports from findings JSON."""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path


def to_markdown(doc: dict) -> str:
    lines = [
        f"# CYVIDIA report — {doc.get('hostname')}",
        "",
        f"- tool_version: `{doc.get('tool_version')}`",
        f"- ioc_pack_version: `{doc.get('ioc_pack_version')}`",
        f"- advisory_pack_version: `{doc.get('advisory_pack_version')}`",
        f"- scan_id: `{doc.get('scan_id')}`",
        f"- generated_at: `{doc.get('generated_at')}`",
        "",
        "## Correlation",
        "",
        f"- campaign_confidence: **{doc.get('correlation', {}).get('campaign_confidence')}**",
        f"- labels: {', '.join(doc.get('correlation', {}).get('labels') or []) or '(none)'}",
        f"- matched_rules: {', '.join(doc.get('correlation', {}).get('matched_rules') or []) or '(none)'}",
        "",
        "## Findings",
        "",
    ]
    for f in doc.get("findings", []):
        lines.append(f"### [{f.get('severity')}] {f.get('title')}")
        lines.append("")
        lines.append(f"- module: `{f.get('module')}`")
        lines.append(f"- confidence: `{f.get('confidence')}`")
        if f.get("detail"):
            lines.append(f"- detail: {f.get('detail')}")
        if f.get("evidence"):
            lines.append(f"- evidence: `{f.get('evidence')}`")
        if f.get("remediation_hint"):
            lines.append(f"- remediation_hint: `{f.get('remediation_hint')}`")
        lines.append("")
    return "\n".join(lines) + "\n"


def to_html(doc: dict) -> str:
    mdish = to_markdown(doc)
    body = html.escape(mdish).replace("\n", "<br>\n")
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>CYVIDIA {html.escape(str(doc.get('hostname')))}</title>"
        "<style>body{font-family:Segoe UI,Arial,sans-serif;max-width:960px;margin:2rem auto;line-height:1.4}"
        "code{background:#f4f4f4;padding:0.1rem 0.3rem}</style></head><body>"
        f"<pre>{body}</pre></body></html>\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings-json", required=True, type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--html", type=Path)
    args = parser.parse_args(argv)
    doc = json.loads(args.findings_json.read_text(encoding="utf-8"))
    if args.md:
        args.md.write_text(to_markdown(doc), encoding="utf-8")
    if args.html:
        args.html.write_text(to_html(doc), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
