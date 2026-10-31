# SPDX-License-Identifier: MIT
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

import virustotal_hashes as vt


class VirusTotalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        wheel = self.root / "fixture.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("fixture.txt", b"public test fixture")
        self.manifest = self.root / "fixture.store.json"
        self.manifest.write_text(json.dumps({"wheel": wheel.name,
            "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "files": {"fixture.txt": {"sha256": hashlib.sha256(b"public test fixture").hexdigest()}}}))
        self.digests = {item["sha256"] for item in vt.collect_files([self.manifest])}
        self.urls = "\n".join("https://www.virustotal.com/gui/file/" + item for item in sorted(self.digests))
        self.observed = dt.datetime.now(dt.timezone.utc).isoformat()

    def generate(self, **kwargs):
        return vt.generate([self.manifest], True, True, 30, 0, **kwargs)

    @mock.patch.dict(os.environ, {"VT_API_KEY": ""})
    @mock.patch.object(vt, "query", side_effect=AssertionError("manual mode must not use API"))
    @mock.patch.object(vt.urllib.request, "build_opener", side_effect=AssertionError("no HTTP"))
    def test_complete_manual_links_without_network(self, *_):
        result, code = self.generate(manual_report_urls=self.urls, observed_at=self.observed)
        self.assertEqual(code, 0)
        self.assertEqual(result["requests"], "NONE")
        self.assertEqual(result["release_gate"], "OWNER_LINKS_COMPLETE_CONTENT_UNVERIFIED")
        self.assertTrue(all(not x["report_content_verified"] for x in result["hash_reports"].values()))
        for digest in self.digests:
            self.assertIn(digest, vt.markdown(result))

    @mock.patch.dict(os.environ, {"VT_API_KEY": ""})
    def test_missing_links_date_and_stale_refused(self):
        stale = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=31)).isoformat()
        for urls, date in [(self.urls.split()[0], self.observed), (self.urls, ""), ("", self.observed),
                           (self.urls, stale)]:
            with self.subTest(urls=urls, date=date):
                result, code = self.generate(manual_report_urls=urls, observed_at=date)
                self.assertEqual(code, 3)
                self.assertEqual(result["release_gate"], "NEED_REPORTS")

    def test_bad_urls_dates_and_foreign_hashes(self):
        for url in [self.urls.split()[0] + "?x=1", self.urls.split()[0] + "/", "http://example.com/",
                    "https://www.virustotal.com/gui/file/" + "0" * 64]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.generate(manual_report_urls=url, observed_at=self.observed)
        for date in ["2026-10-31", "invalid", (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).isoformat()]:
            with self.subTest(date=date), self.assertRaises(ValueError):
                self.generate(manual_report_urls=self.urls, observed_at=date)

    def test_final_wheel_and_member_digests_checked(self):
        data = json.loads(self.manifest.read_text())
        data["files"]["fixture.txt"]["sha256"] = "0" * 64
        self.manifest.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.generate()
        (self.root / "fixture.whl").write_bytes(b"changed final bytes")
        with self.assertRaises(ValueError):
            self.generate()

    @mock.patch.dict(os.environ, {"VT_API_KEY": "test-not-a-real-key"})
    @mock.patch.object(vt, "query")
    def test_api_requires_commercial_confirmation_and_preserves_flagged_gate(self, query):
        result, code = self.generate()
        self.assertEqual(code, 3)
        query.assert_not_called()
        self.assertEqual(result["requests"], "NONE")
        query.return_value = {"status": "OBSERVED_NO_DETECTIONS"}
        result, code = self.generate(commercial_api_authorized=True)
        self.assertEqual(code, 0)
        self.assertEqual(query.call_count, len(self.digests))
        query.return_value = {"status": "FLAGGED"}
        result, code = self.generate(commercial_api_authorized=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["release_gate"], "FLAGGED")


if __name__ == "__main__":
    unittest.main()
