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
    def test_pack_flags_old_r580(self) -> None:
        pack = ROOT / "iocs" / "nvidia-cves.json"
        rows = match("580.82.00", pack)
        self.assertTrue(any(r[0] == "High" and "CVE-2025-33219" in r[1] for r in rows))

    def test_pack_current_r580(self) -> None:
        pack = ROOT / "iocs" / "nvidia-cves.json"
        rows = match("580.126.09", pack)
        self.assertTrue(all(r[0] == "Info" for r in rows))

    def test_fixture_version_550_unrelated_branch(self) -> None:
        pack = ROOT / "iocs" / "nvidia-cves.json"
        rows = match("550.54.14", pack)
        # 550 is outside curated R535/R570/R580/R590 rows → Info
        self.assertTrue(all(r[0] == "Info" for r in rows))

    def test_unpatched_custom(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "n.json"
            p.write_text(
                json.dumps(
                    {
                        "advisory_pack_version": "0.1.0",
                        "advisories": [
                            {
                                "cve_id": "CVE-2099-0001",
                                "os": "linux",
                                "branch_major": 550,
                                "affected_from": "550.0.0",
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
