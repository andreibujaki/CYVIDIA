#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cyvidia_correlate import evaluate  # noqa: E402


class TestCorrelate(unittest.TestCase):
    def test_nvml_alone(self) -> None:
        rules = ROOT / "iocs" / "correlation.rules.json"
        findings = [
            {
                "module": "gpu_secondary",
                "severity": "High",
                "labels": ["nvml_spoof_or_mismatch"],
            }
        ]
        result = evaluate(rules, findings)
        self.assertIn("nvml_alone", result["matched_rules"])
        self.assertEqual(result["campaign_confidence"], "medium")

    def test_nvml_plus_disk(self) -> None:
        rules = ROOT / "iocs" / "correlation.rules.json"
        findings = [
            {"module": "gpu_secondary", "severity": "High", "labels": ["nvml_spoof_or_mismatch"]},
            {"module": "sansar_fs", "severity": "Critical", "labels": ["disk_ioc", "disk_ioc_or_rootkit"]},
        ]
        result = evaluate(rules, findings)
        self.assertIn("sansar_toolkit_high", result["matched_rules"])
        self.assertEqual(result["campaign_confidence"], "high")
        self.assertIn("sansar_toolkit", result["labels"])


if __name__ == "__main__":
    unittest.main()
