#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cyvidia_json import aggregate, load_ndjson, redact_text  # noqa: E402


class TestJsonSchema(unittest.TestCase):
    def test_redact_stratum(self) -> None:
        raw = "pool stratum+tcp://xmr.example:3333 user=abc"
        out = redact_text(raw)
        self.assertIn("stratum+tcp://***", out)
        self.assertNotIn("xmr.example", out)

    def test_missing_severity_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            nd = Path(td) / "f.ndjson"
            nd.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1.0",
                        "finding_id": "x",
                        "module": "test",
                        "confidence": "low",
                        "title": "t",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                load_ndjson(nd)

    def test_aggregate_includes_manifest_versions(self) -> None:
        manifest = ROOT / "iocs" / "pack-manifest.json"
        with tempfile.TemporaryDirectory() as td:
            nd = Path(td) / "f.ndjson"
            out = Path(td) / "out.json"
            nd.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1.0",
                        "finding_id": "11111111-1111-1111-1111-111111111111",
                        "module": "test",
                        "severity": "High",
                        "confidence": "medium",
                        "title": "demo",
                        "detail": "pool stratum+tcp://evil:3333",
                        "evidence": "",
                        "remediation_hint": "",
                        "ioc_refs": [],
                        "labels": ["nvml_spoof_or_mismatch"],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            doc = aggregate(nd, manifest, out, scan_id="scan-test", hostname="testhost")
            self.assertEqual(doc["hostname"], "testhost")
            self.assertEqual(doc["ioc_pack_version"], "0.1.0")
            self.assertEqual(doc["advisory_pack_version"], "0.2.0")

            self.assertIn("stratum+tcp://***", doc["findings"][0]["detail"])
            self.assertTrue(out.exists())


if __name__ == "__main__":
    unittest.main()
