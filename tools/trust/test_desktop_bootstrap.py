# SPDX-License-Identifier: MIT
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import desktop_bootstrap as subject


def pe(flags=0x60000020):
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<HH", data, 68, 0x8664, 1)
    struct.pack_into("<H", data, 84, 240)
    struct.pack_into("<H", data, 88, 0x20B)
    struct.pack_into("<I", data, 88 + 108, 16)
    data[328:336] = b".text\0\0\0"
    struct.pack_into("<IIII", data, 336, 64, 4096, 64, 448)
    struct.pack_into("<I", data, 328 + 36, flags)
    return data


def macho(cpu=0x01000007, subtype=3, protection=5, extra=b""):
    segment = bytearray(72)
    struct.pack_into("<II", segment, 0, 0x19, 72)
    struct.pack_into("<QQ", segment, 40, 0, 104 + len(extra))
    struct.pack_into("<I", segment, 60, protection)
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, cpu, subtype, 6, 1 + bool(extra), 72 + len(extra), 0, 0)
    return bytearray(header + segment + extra)


class InventoryControls(unittest.TestCase):
    def repository_root(self):
        folder = Path(subject.__file__).resolve().parent
        if folder.name == "desktop_trust":
            self.skipTest("Repository integration controls run in each of the three clones")
        return folder

    def test_repository_resource_pins_and_helper_copy(self):
        folder = self.repository_root()
        resource = folder / "resources-desktop-v1/verify"
        pins = json.loads((folder / "DESKTOP_RESOURCE_PINS_V1.json").read_text())
        self.assertEqual(pins["status"], "INCOMPLETE_NATIVE_COLLECTOR_MISSING")
        self.assertEqual(set(pins["sha256"]), {"desktop_bootstrap.py", "pure.ps1", "pure.sh", "README.md", "LICENSE-MIT"})
        for name, expected in pins["sha256"].items():
            self.assertEqual(hashlib.sha256((resource / name).read_bytes()).hexdigest(), expected)
        self.assertEqual((resource / "desktop_bootstrap.py").read_bytes(), Path(subject.__file__).read_bytes())
        attributes = (folder.parents[1] / ".gitattributes").read_text()
        self.assertIn("tools/trust/resources-desktop-v1/** text eol=lf", attributes)
        self.assertIn("tools/trust/desktop_bootstrap.py text eol=lf", attributes)

    def test_repository_bootstrap_is_opt_in_without_signing_environment(self):
        folder = self.repository_root()
        workflow = (folder.parents[1] / ".github/workflows/store-release.yml").read_text()
        entry = workflow.split("      desktop_bootstrap:\n", 1)[1].split("permissions:\n", 1)[0]
        self.assertIn("default: false", entry)
        job = workflow.split("  desktop-bootstrap:\n", 1)[1].split("  assemble:\n", 1)[0]
        self.assertIn("if: inputs.desktop_bootstrap && github.ref == 'refs/heads/main'", job)
        self.assertNotIn("secrets.", job)
        self.assertNotIn("environment:", job)
        for name in ["windows_x86_64", "macos_x86_64", "macos_arm64"]:
            self.assertIn("target: " + name, job)

    def test_pe_has_no_signature_claim(self):
        d = subject.inspect_native(pe(), "windows_x86_64")
        self.assertFalse(d["signature_verified"])
        self.assertEqual(d["status"], "STRUCTURAL_CHECKS_ONLY_RELEASE_NEED")

    def test_pe_write_execute_rejected(self):
        with self.assertRaisesRegex(ValueError, "Writable executable"):
            subject.inspect_native(pe(0xE0000020), "windows_x86_64")

    def test_pe_wrong_architecture(self):
        data = pe(); struct.pack_into("<H", data, 68, 0xAA64)
        with self.assertRaises(ValueError): subject.inspect_native(data, "windows_x86_64")

    def test_pe_section_file_bounds(self):
        data = pe(); struct.pack_into("<I", data, 348, 500)
        with self.assertRaisesRegex(ValueError, "outside file"):
            subject.inspect_native(data, "windows_x86_64")

    def test_pe_missing_import_terminator(self):
        data = pe(); struct.pack_into("<II", data, 208, 4096, 20)
        struct.pack_into("<IIIII", data, 448, 0, 0, 0, 4120, 1)
        data[472:480] = b"abc.dll\0"
        with self.assertRaisesRegex(ValueError, "Unterminated PE import"):
            subject.inspect_native(data, "windows_x86_64")

    def test_pe_import_outside_section(self):
        data = pe(); struct.pack_into("<II", data, 208, 9000, 20)
        with self.assertRaisesRegex(ValueError, "Unmapped import"):
            subject.inspect_native(data, "windows_x86_64")

    def test_pe_invalid_certificate_bounds(self):
        data = pe(); struct.pack_into("<II", data, 232, 500, 20)
        with self.assertRaisesRegex(ValueError, "certificate"):
            subject.inspect_native(data, "windows_x86_64")

    def test_pe_unknown_directories(self):
        data = pe(); struct.pack_into("<I", data, 196, 17)
        with self.assertRaisesRegex(ValueError, "directory count"):
            subject.inspect_native(data, "windows_x86_64")

    def test_all_truncations_rejected(self):
        for data, target in [(pe(), "windows_x86_64"), (macho(), "macos_x86_64")]:
            for end in [0, 2, 4, 16, 31, 40, 63, 72, 100]:
                with self.subTest(target=target, end=end), self.assertRaises(ValueError):
                    subject.inspect_native(data[:end], target)

    def test_macho_architectures(self):
        self.assertEqual(subject.inspect_native(macho(), "macos_x86_64")["architecture"], "x86_64")
        self.assertEqual(subject.inspect_native(macho(0x0100000C, 0), "macos_arm64")["architecture"], "arm64")

    def test_macho_write_execute_rejected(self):
        with self.assertRaisesRegex(ValueError, "Writable executable"):
            subject.inspect_native(macho(protection=7), "macos_x86_64")

    def test_macho_wrong_target(self):
        with self.assertRaisesRegex(ValueError, "mismatch"):
            subject.inspect_native(macho(), "macos_arm64")

    def test_macho_specialized_subtype_rejected(self):
        with self.assertRaisesRegex(ValueError, "subtype"):
            subject.inspect_native(macho(subtype=8), "macos_x86_64")

    def test_macho_load_command_count(self):
        data = macho(); struct.pack_into("<I", data, 16, 2)
        with self.assertRaises(ValueError): subject.inspect_native(data, "macos_x86_64")

    def test_macho_dylib_string_cannot_escape_command(self):
        command = struct.pack("<IIIIII", 0xC, 24, 400, 0, 0, 0)
        with self.assertRaises(ValueError):
            subject.inspect_native(macho(extra=command), "macos_x86_64")

    def test_macho_signature_blob_is_not_verification(self):
        command = struct.pack("<IIII", 0x1D, 16, 120, 16)
        d = subject.inspect_native(macho(extra=command) + bytes(16), "macos_x86_64")
        self.assertTrue(d["signature_blob_present"])
        self.assertFalse(d["signature_verified"])

    def test_macho_signature_cannot_point_to_header(self):
        command = struct.pack("<IIII", 0x1D, 16, 0, 16)
        with self.assertRaisesRegex(ValueError, "signature blob"):
            subject.inspect_native(macho(extra=command), "macos_x86_64")

    def test_macho_32_bit_segment_cannot_skip_protection_check(self):
        data = macho(); struct.pack_into("<I", data, 32, 1)
        with self.assertRaisesRegex(ValueError, "32-bit segment"):
            subject.inspect_native(data, "macos_x86_64")

    def test_fat_requires_separate_admission(self):
        with self.assertRaisesRegex(ValueError, "fat/unknown"):
            subject.inspect_native(b"\xca\xfe\xba\xbe" + bytes(200), "macos_arm64")

    def test_known_packer_is_refused(self):
        with self.assertRaisesRegex(ValueError, "packer"):
            subject.inspect_native(pe() + b"UPX!", "windows_x86_64")

    def test_probe_never_reports_release_ready(self):
        with mock.patch.object(subject.platform, "system", return_value="Darwin"), mock.patch.object(subject.platform, "machine", return_value="arm64"):
            d = subject.probe("macos_arm64")
        self.assertTrue(d["target_matches_runner"])
        self.assertFalse(d["release_ready"])
        self.assertEqual(d["purity"], "INCOMPLETE_NATIVE_COLLECTOR_MISSING")

    def test_wrong_runner(self):
        with mock.patch.object(subject.platform, "system", return_value="Linux"):
            d = subject.probe("windows_x86_64")
        self.assertEqual(d["status"], "INCOMPLETE_WRONG_NATIVE_RUNNER")

    def test_pure_does_not_execute_user_command(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); marker = root / "should-not-exist"; receipt = root / "result.json"
            r = subprocess.run([sys.executable, str(Path(subject.__file__).resolve()), "--target", "windows_x86_64", "--output", str(receipt), "--pure", "--", sys.executable, "-c", "from pathlib import Path;Path(" + repr(str(marker)) + ").touch()"], capture_output=True)
            self.assertEqual(r.returncode, 3)
            self.assertFalse(marker.exists())
            data = json.loads(receipt.read_text())
            self.assertFalse(data["target_executed"])
            self.assertNotIn("should-not-exist", receipt.read_text())


if __name__ == "__main__":
    unittest.main()
