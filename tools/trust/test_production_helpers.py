"""Offline metadata controls; crypto commands and network are mocked."""
import base64
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import fetch_private_inputs as inputs
import generate_vendor_key_offline as keys


class ProductionHelpers(unittest.TestCase):
    def archive(self, root, entries):
        path = root / "inputs.zip"
        with zipfile.ZipFile(path, "w") as target:
            for name, data in entries:
                target.writestr(name, data)
        return path

    def descriptor(self, archive, files):
        return {"sha256": inputs.digest(archive.read_bytes()), "files": {
            name: {"bytes": len(data), "sha256": inputs.digest(data)}
            for name, data in files}}

    def test_pinned_inputs_and_member_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = [("input.so", b"native bytes"), ("reference.whl", b"reference")]
            archive = self.archive(root, files)
            descriptor = self.descriptor(archive, files)
            self.assertEqual(inputs.extract(archive, descriptor, root / "good"), 2)
            self.assertEqual((root / "good/input.so").read_bytes(), b"native bytes")
            descriptor["files"]["input.so"]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                inputs.extract(archive, descriptor, root / "bad")
            self.assertFalse((root / "bad").exists())

    def test_asset_tampering_traversal_duplicate_and_extra(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = [("input.so", b"x")]
            archive = self.archive(root, files)
            descriptor = self.descriptor(archive, files)
            descriptor["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                inputs.extract(archive, descriptor, root / "out")
            for members in [[("../escape", b"x")], files + files,
                            files + [("unexpected", b"y")]]:
                archive = self.archive(root, members)
                descriptor = self.descriptor(archive, members if members[0][0].startswith("..") else files)
                with self.assertRaises(ValueError):
                    inputs.extract(archive, descriptor, root / "out")
            self.assertFalse((root / "out").exists())

    def test_symlink_input_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "inputs.zip"
            with zipfile.ZipFile(archive, "w") as target:
                info = zipfile.ZipInfo("input.so")
                info.external_attr = 0o120777 << 16
                target.writestr(info, b"/secret")
            with self.assertRaises(ValueError):
                inputs.extract(archive, self.descriptor(archive, [("input.so", b"/secret")]), root / "out")

    def test_owner_key_only_persists_ciphertext_and_public_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recipient = root / "recipient.txt"
            recipient.write_text("age1" + "a" * 58)
            der = bytes.fromhex("302a300506032b6570032100") + b"A" * 32
            public = b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der) + b"\n-----END PUBLIC KEY-----\n"
            private = b"MOCK_PRIVATE_NOT_A_REAL_KEY"
            ciphertext = b"age-encryption.org/v1\nMOCK_CIPHERTEXT"
            stdout = io.StringIO()
            with patch.object(keys, "command", side_effect=[private, public, ciphertext]) as called:
                metadata = keys.generate(recipient, root / "private", [root / "public"])
            self.assertEqual(called.call_args_list[0].args[0][-1], "ED25519")
            self.assertEqual((root / "private/vendor-entitlement-v1.pkcs8.pem.age").read_bytes(), ciphertext)
            self.assertEqual((root / "private").stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "public/vendor-entitlement-v1.pub.pem").stat().st_mode & 0o777, 0o644)
            for path in root.rglob("*"):
                if path.is_file():
                    self.assertNotIn(private, path.read_bytes())
            self.assertEqual(metadata["key_id"], "sha256:" + hashlib.sha256(der).hexdigest())
            self.assertNotIn("PRIVATE", json.dumps(metadata) + stdout.getvalue())
            with patch.object(keys, "command") as called:
                with self.assertRaises(FileExistsError):
                    keys.generate(recipient, root / "private", [root / "public"])
                called.assert_not_called()

    def test_bad_owner_recipient_does_not_generate_a_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recipient = root / "recipient.txt"
            recipient.write_text("an SSH identity or invalid recipient")
            with patch.object(keys, "command") as called:
                with self.assertRaises(ValueError):
                    keys.generate(recipient, root / "private", [root / "public"])
                called.assert_not_called()


if __name__ == "__main__":
    unittest.main()
