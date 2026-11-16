#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

import cyvidia_eth_call as eth  # noqa: E402


class TestEthCall(unittest.TestCase):
    def test_dry_run(self) -> None:
        rc = eth.main(["--dry-run"])
        self.assertEqual(rc, 0)

    def test_lookup_mocked(self) -> None:
        fake = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x01"}).encode()

        class Resp:
            def read(self):
                return fake

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with mock.patch("urllib.request.urlopen", return_value=Resp()):
            out = eth.lookup(rpc_urls=["http://example.invalid"])
        self.assertIn("response", out)
        self.assertEqual(out["response"]["result"], "0x01")


if __name__ == "__main__":
    unittest.main()
