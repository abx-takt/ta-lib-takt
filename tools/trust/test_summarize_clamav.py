# SPDX-License-Identifier: MIT
from pathlib import Path
import subprocess
import tempfile
import unittest

from summarize_clamav import summary


class ClamAVSummaryTests(unittest.TestCase):
    def test_records_zero_infected_engine_and_dated_actual_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan, definitions, update = [root / name for name in ["scan.txt", "defs.txt", "update.txt"]]
            scan.write_text("Engine version: 1.5.4\nInfected files: 0\n")
            definitions.write_text("ClamAV 1.5.4/12345/Sat Oct 31 00:00:00 2026\n")
            update.write_text("Database updated, fixture only\n")
            result = summary(scan, definitions, update)
            self.assertEqual(result["infected_files"], 0)
            self.assertEqual(result["daily_database_version"], 12345)
            self.assertEqual(result["engine_version"], "1.5.4")
            self.assertEqual(len(result["logs_sha256"]), 3)

    def test_infected_missing_date_and_ambiguous_summary_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan, definitions, update = [root / name for name in ["scan", "defs", "update"]]
            update.write_text("fixture update\n")
            for scan_text, definition in [
                ("Engine version: 1.5.4\nInfected files: 1\n", "ClamAV 1.5.4/123/Date\n"),
                ("Engine version: 1.5.4\nInfected files: 0\n", "ClamAV 1.5.4\n"),
                ("Engine version: 1.5.4\nInfected files: 0\nInfected files: 0\n", "ClamAV 1.5.4/123/Date\n"),
                ("Engine version: 1.5.3\nInfected files: 0\n", "ClamAV 1.5.4/123/Date\n")]:
                scan.write_text(scan_text)
                definitions.write_text(definition)
                with self.subTest(scan=scan_text), self.assertRaises(ValueError):
                    summary(scan, definitions, update)

    def test_tee_keeps_scanner_failure_with_pipefail(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "scan.txt"
            result = subprocess.run(["bash", "-o", "pipefail", "-c",
                                     '(printf "fixture failure\\n"; exit 2) 2>&1 | tee "$1"', "bash", str(log)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(log.read_text(), "fixture failure\n")
            self.assertEqual(log.stat().st_uid, __import__("os").getuid())


if __name__ == "__main__":
    unittest.main()
