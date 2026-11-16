#!/usr/bin/env python3
"""Optional read-only Ethereum eth_call for netns C2 resolver contract."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any

DEFAULT_RPCS = [
    "https://cloudflare-eth.com",
    "https://rpc.ankr.com/eth",
    "https://ethereum.publicnode.com",
]

DEFAULT_CONTRACT = "0x43eb291f56688c63c93e8a93c4591fc997cf6349"
DEFAULT_SELECTOR = "0x6ded96e7"


def eth_call(
    rpc_url: str,
    contract: str,
    selector: str,
    timeout: float = 8.0,
) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": contract, "data": selector}, "latest"],
    }
    req = urllib.request.Request(
        rpc_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return {"rpc_url": rpc_url, "response": body}


def lookup(
    contract: str = DEFAULT_CONTRACT,
    selector: str = DEFAULT_SELECTOR,
    rpc_urls: list[str] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    for url in rpc_urls or DEFAULT_RPCS:
        try:
            return eth_call(url, contract, selector)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{url}: {exc}")
    return {"error": "all_rpc_failed", "details": errors}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only eth_call helper")
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--selector", default=DEFAULT_SELECTOR)
    parser.add_argument("--rpc-url", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true", help="Do not contact network; print plan")
    args = parser.parse_args(argv)
    if args.dry_run:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "contract": args.contract,
                    "selector": args.selector,
                    "rpc_urls": args.rpc_url or DEFAULT_RPCS,
                },
                indent=2,
            )
        )
        return 0
    result = lookup(args.contract, args.selector, args.rpc_url or None)
    print(json.dumps(result, indent=2))
    return 0 if "error" not in result else 1


if __name__ == "__main__":
    sys.exit(main())
