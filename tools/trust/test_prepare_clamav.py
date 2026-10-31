# SPDX-License-Identifier: MIT
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from prepare_clamav import prepare


class ClamAVConfigTests(unittest.TestCase):
    def test_cli_uses_explicit_updater_owner_without_running_scanner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("prepare_clamav.py")),
                                     "--root", str(root / "db-root"), "--owner", "clamav",
                                     "--metadata", str(root / "metadata.json")],
                                    capture_output=True, text=True, check=True)
            metadata = json.loads(result.stdout)
            self.assertEqual(metadata["owner"], "clamav")
            self.assertFalse(metadata["scanner_execution"])
            self.assertIn(b"DatabaseOwner clamav\n", Path(metadata["config"]).read_bytes())

    def test_exact_configuration_exists_with_lf_directives_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "clamav-runtime"
            result = prepare(root, "runner")
            config = Path(result["config"])
            expected = ("DatabaseMirror database.clamav.net\nDatabaseDirectory "
                        + str(root / "db") + "\nDatabaseOwner runner\n").encode()
            self.assertEqual(config.read_bytes(), expected)
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / "db").stat().st_mode & 0o777, 0o700)
            self.assertEqual(result["config_sha256"], hashlib.sha256(expected).hexdigest())
            self.assertEqual(result["network_requests"], 0)
            self.assertFalse(result["scanner_execution"])

    def test_invalid_values_refused_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            for path, owner in [("bad\npath", "runner"), ("bad path", "runner"),
                                ("bad\\path", "runner"), ('bad"path', "runner"),
                                ("normal", "runner\nDatabaseMirror attacker.invalid")]:
                root = Path(directory) / path
                with self.subTest(path=path, owner=owner), self.assertRaises(ValueError):
                    prepare(root, owner)
                self.assertFalse(root.exists())

    def test_existing_workspace_or_symlink_is_not_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "scanner"
            prepare(root, "runner")
            with self.assertRaises(FileExistsError):
                prepare(root, "runner")
            link = Path(directory) / "link"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(FileExistsError):
                prepare(link, "runner")


if __name__ == "__main__":
    unittest.main()
