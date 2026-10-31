# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import stat
import struct
import tempfile
import unittest
import zipfile

import desktop_wheel as wheel
from test_desktop_bootstrap import pe


class WheelControls(unittest.TestCase):
    def make_wheel(self, folder, extras=(), target="windows_x86_64"):
        data = bytes(pe())
        profile = {"profile": "store", "target_platform": target, "executable_packer": False,
                   "anti_debug_wrapper": False, "code_obfuscator": False,
                   "native": {"demo/native.dll": {"sha256": wheel.digest(data)}}}
        entries = {"demo/native.dll": data, "demo/__init__.py": b"# unchanged wrapper\n",
                   "demo/verify/STORE_PROFILE.json": json.dumps(profile).encode(),
                   "demo-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nTag: cp312-cp312-win_amd64\n",
                   "demo-1.0.dist-info/METADATA": b"Name: demo\nVersion: 1.0\n",
                   "demo-1.0.dist-info/RECORD": b""}
        path = folder / "source.whl"
        with zipfile.ZipFile(path, "w") as out:
            for name, value in entries.items(): out.writestr(name, value)
            for name, value in extras: out.writestr(name, value)
        return path, wheel.digest(path.read_bytes())

    def test_signed_repack_checks_every_record_and_preserves_wrapper(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source, sha = self.make_wheel(root); prepared = root / "prepared"
            wheel.prepare(source, sha, "windows_x86_64", prepared)
            path = prepared / "subjects/demo/native.dll"; data = bytearray(path.read_bytes())
            struct.pack_into("<II", data, 232, len(data), 16); data += bytes(16); path.write_bytes(data)
            result = wheel.finish(source, prepared, root / "demo-1.0-cp312-cp312-win_amd64.whl", verifier=lambda *args: {"verified": True, "test_mock_only": True})
            self.assertTrue(result["full_RECORD_verified"])
            self.assertFalse(result["release_ready"])
            self.assertIn("BLOCKED_NATIVE", result["publication_gate"])
            with zipfile.ZipFile(root / "demo-1.0-cp312-cp312-win_amd64.whl") as out:
                self.assertEqual(out.read("demo/__init__.py"), b"# unchanged wrapper\n")

    def test_unknown_source_pin_refused_before_staging(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source, sha = self.make_wheel(root)
            with self.assertRaisesRegex(ValueError, "SHA256"):
                wheel.prepare(source, "0" * 64, "windows_x86_64", root / "prepared")
            self.assertFalse((root / "prepared").exists())

    def test_duplicate_and_traversal_refused(self):
        for member in ["demo/native.dll", "../escape", "a\\escape", "/absolute"]:
            with self.subTest(member=member), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); source, sha = self.make_wheel(root, extras=[(member, b"bad")])
                with self.assertRaises(ValueError): wheel.prepare(source, sha, "windows_x86_64", root / "prepared")

    def test_symlink_archive_member_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source, sha = self.make_wheel(root)
            with zipfile.ZipFile(source, "a") as out:
                info = zipfile.ZipInfo("demo/link"); info.external_attr = (stat.S_IFLNK | 0o777) << 16; out.writestr(info, b"/outside")
            with self.assertRaisesRegex(ValueError, "REGULAR"):
                wheel.prepare(source, wheel.digest(source.read_bytes()), "windows_x86_64", root / "prepared")

    def test_wrong_target_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source, sha = self.make_wheel(root)
            with self.assertRaisesRegex(ValueError, "TARGET"):
                wheel.prepare(source, sha, "macos_arm64", root / "prepared")

    def test_code_byte_mutation_refused_even_with_claimed_signature(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source, sha = self.make_wheel(root); prepared = root / "prepared"
            wheel.prepare(source, sha, "windows_x86_64", prepared)
            path = prepared / "subjects/demo/native.dll"; data = bytearray(path.read_bytes()); data[448] ^= 1; path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "CODE_DATA_CHANGED"):
                wheel.finish(source, prepared, root / "demo-1.0-cp312-cp312-win_amd64.whl", verifier=lambda *args: {"verified": True})

    def test_missing_os_signature_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source, sha = self.make_wheel(root); prepared = root / "prepared"
            wheel.prepare(source, sha, "windows_x86_64", prepared)
            with self.assertRaisesRegex(ValueError, "OS_SIGNATURE_NOT_VERIFIED"):
                wheel.finish(source, prepared, root / "demo-1.0-cp312-cp312-win_amd64.whl", verifier=lambda *args: {"verified": False})

    def test_extra_subject_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source, sha = self.make_wheel(root); prepared = root / "prepared"
            wheel.prepare(source, sha, "windows_x86_64", prepared)
            (prepared / "subjects/extra.dll").write_bytes(b"not authorised")
            with self.assertRaisesRegex(ValueError, "SUBJECT_SET_CHANGED"):
                wheel.finish(source, prepared, root / "demo-1.0-cp312-cp312-win_amd64.whl", verifier=lambda *args: {"verified": True})

    def test_wrong_final_wheel_tag_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source, sha = self.make_wheel(root); prepared = root / "prepared"
            wheel.prepare(source, sha, "windows_x86_64", prepared)
            with self.assertRaisesRegex(ValueError, "FILENAME_TAG"):
                wheel.finish(source, prepared, root / "demo-1.0-cp312-cp312-manylinux_2_29_x86_64.whl", verifier=lambda *args: {"verified": True})


if __name__ == "__main__": unittest.main()
