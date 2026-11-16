#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cyvidia_cve_match import match  # noqa: E402


class TestCveMatch(unittest.TestCase):
    def test_empty_pack(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "n.json"
            p.write_text(json.dumps({"advisory_pack_version": "0.1.0", "advisories": []}), encoding="utf-8")
            rows = match("550.54.14", p)
            self.assertEqual(rows[0][0], "Info")

    def test_unpatched(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "n.json"
            p.write_text(
                json.dumps(
                    {
                        "advisory_pack_version": "0.1.0",
                        "advisories": [
                            {
                                "cve_id": "CVE-2099-0001",
                                "affected_from": "500.0.0",
                                "affected_to": "560.0.0",
                                "fixed_version": "560.0.1",
                                "severity": "High",
                                "url": "https://example.invalid",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            rows = match("550.54.14", p)
            self.assertEqual(rows[0][0], "High")
            self.assertIn("CVE-2099-0001", rows[0][1])


if __name__ == "__main__":
    unittest.main()
