# SPDX-License-Identifier: MIT
import hashlib
from pathlib import Path
import tempfile
import unittest

from prepare_clamav import prepare


class ClamAVConfigTests(unittest.TestCase):
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
