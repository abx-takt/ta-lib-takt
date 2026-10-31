# SPDX-License-Identifier: MIT
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

import desktop_signing as signing


def apple_env():
    return {"ENABLE_SIGNING": "true", "ENABLE_PUBLISHING": "false", "APPLE_TEAM_ID": "TEAM123456",
            "APPLE_SIGNING_CERT_SHA1": "a" * 40, "APPLE_SIGNING_CERT_SHA256": "b" * 64,
            "APPLE_SIGNING_P12_B64": base64.b64encode(b"MOCK_PRIVATE_NOT_REAL_P12").decode(),
            "APPLE_SIGNING_P12_PASSWORD": "MOCK_PASSWORD_NOT_REAL", "APPLE_ASC_KEY_P8_B64": base64.b64encode(b"MOCK_PRIVATE_NOT_REAL_P8").decode(),
            "APPLE_ASC_KEY_ID": "KEY1234567", "APPLE_ASC_ISSUER_ID": "12345678-1234-1234-1234-123456789abc"}


class SigningControls(unittest.TestCase):
    def test_protocol_cannot_publish_or_implicitly_sign(self):
        for env in [{}, {"ENABLE_SIGNING": "false"}, {"ENABLE_SIGNING": "true", "ENABLE_PUBLISHING": "true"}]:
            with self.subTest(env=env), self.assertRaises(ValueError):
                signing.require_protocol(env)

    def test_apple_configuration_missing_before_native_calls(self):
        with mock.patch.object(signing, "require_host"), mock.patch.object(signing, "command") as called:
            with self.assertRaisesRegex(ValueError, "COORDINATOR"):
                signing.macos_smoke("macos_arm64", Path("unused"), {"ENABLE_SIGNING": "true"})
        called.assert_not_called()

    def test_bad_apple_anchor_before_native_calls(self):
        env = apple_env(); env["APPLE_TEAM_ID"] = "bad\nvalue"
        with mock.patch.object(signing, "require_host"), mock.patch.object(signing, "command") as called:
            with self.assertRaisesRegex(ValueError, "ANCHOR"):
                signing.macos_smoke("macos_arm64", Path("unused"), env)
        called.assert_not_called()

    def test_secret_file_is_private_and_no_invalid_file_created(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "secret"
            signing.decode_secret(base64.b64encode(b"MOCK_PRIVATE").decode(), p)
            self.assertEqual(p.read_bytes(), b"MOCK_PRIVATE")
            if os.name != "nt": self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError): signing.decode_secret("!bad!", Path(folder) / "invalid")
            self.assertFalse((Path(folder) / "invalid").exists())

    def test_native_command_strips_secret_env_and_sanitizes_failure(self):
        result = subprocess.CompletedProcess([], 1, stdout=b"MOCK_PRIVATE", stderr=b"MOCK_PRIVATE")
        with mock.patch.object(signing.subprocess, "run", return_value=result) as called:
            with self.assertRaisesRegex(RuntimeError, "^NATIVE_TOOL_FAILED_security$"):
                signing.command(["security", "secret-looking-argv"], env=apple_env())
        passed = called.call_args.kwargs["env"]
        self.assertFalse(set(signing.PRIVATE_ENV) & set(passed))

    def test_macos_verification_checks_actual_leaf_fingerprints(self):
        cert = b"MOCK_PUBLIC_CERTIFICATE_NOT_A_KEY"
        env = apple_env(); env["APPLE_SIGNING_CERT_SHA1"] = signing.hashlib.sha1(cert).hexdigest(); env["APPLE_SIGNING_CERT_SHA256"] = signing.digest(cert)
        calls = []
        def native(args, **kwargs):
            calls.append([str(x) for x in args])
            for arg in args:
                if str(arg).startswith("--extract-certificates="):
                    Path(str(arg).split("=", 1)[1] + "0").write_bytes(cert)
            return subprocess.CompletedProcess(args, 0, b"", b"TeamIdentifier=TEAM123456\n")
        with mock.patch.object(signing, "require_host"), mock.patch.object(signing, "command", side_effect=native):
            result = signing.verify_macos(Path("fixture.dylib"), "macos_arm64", env)
        self.assertTrue(result["verified"])
        self.assertEqual(result["certificate_sha256"], signing.digest(cert))
        self.assertIn("anchor apple generic", calls[0][-2])
        self.assertIn(env["APPLE_SIGNING_CERT_SHA1"], calls[0][-2])

    def test_macos_adhoc_or_wrong_team_never_passes(self):
        for text in [b"TeamIdentifier=OTHER12345\n", b"TeamIdentifier=TEAM123456\nSignature=adhoc\n"]:
            with self.subTest(text=text), mock.patch.object(signing, "require_host"), mock.patch.object(signing, "command", return_value=subprocess.CompletedProcess([], 0, b"", text)):
                with self.assertRaisesRegex(ValueError, "TEAM_OR_ADHOC"):
                    signing.verify_macos(Path("fixture"), "macos_arm64", apple_env())

    def test_macos_cleanup_even_when_notary_rejects(self):
        self.simulate_macos("Invalid", expect_failure=True)

    def test_macos_zip_only_public_subjects_no_staple_claim(self):
        result = self.simulate_macos("Accepted", expect_failure=False)
        self.assertEqual(result["status"], "BOOTSTRAP_SIGNING_PASS")
        self.assertEqual(result["spctl_library_rc"], 1)
        self.assertEqual(result["stapler"], "NOT_APPLICABLE_BARE_EXECUTABLE_DYLIB_ZIP")

    def simulate_macos(self, notary_status, expect_failure):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); output = root / "public"; env = apple_env(); env["RUNNER_TEMP"] = folder; calls = []
            def prepare(target, out):
                (out / "subjects").mkdir(parents=True)
                for name in ["desktop-signing-smoke", "libdesktop-signing-smoke-lib.dylib"]: (out / "subjects" / name).write_bytes(b"PUBLIC_CONTROL_ONLY")
            def native(args, **kwargs):
                strings = [str(x) for x in args]; calls.append(strings)
                if strings[:3] == ["xcrun", "notarytool", "submit"]:
                    return subprocess.CompletedProcess(args, 0, json.dumps({"id": "12345678-1234-1234-1234-123456789abc", "status": notary_status}).encode(), b"")
                rc = 1 if strings[0] == "spctl" and strings[-1].endswith(".dylib") else 0
                return subprocess.CompletedProcess(args, rc, b"", b"")
            with mock.patch.object(signing, "require_host"), mock.patch.object(signing, "prepare_smoke", side_effect=prepare), mock.patch.object(signing, "subject_receipts", return_value={"public": {"verified": True}}), mock.patch.object(signing, "command", side_effect=native), mock.patch.object(signing, "license_bytes", return_value=b"MOCK_PUBLIC_MIT_NOTICE"):
                if expect_failure:
                    with self.assertRaisesRegex(ValueError, "NOTARY_ACCEPTED"):
                        signing.macos_smoke("macos_arm64", output, env)
                    result = None
                else: result = signing.macos_smoke("macos_arm64", output, env)
            self.assertTrue(any(c[:2] == ["security", "delete-keychain"] for c in calls))
            self.assertTrue(any(c[:5] == ["security", "list-keychains", "-d", "user", "-s"] for c in calls))
            self.assertFalse(any(c[0] == "stapler" for c in calls))
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["public"])
            with zipfile.ZipFile(output / "notary-subjects.zip") as archive:
                self.assertEqual(set(archive.namelist()), {"desktop-signing-smoke", "libdesktop-signing-smoke-lib.dylib", "LICENSE-MIT.txt"})
                self.assertNotIn(b"MOCK_PRIVATE", b"".join(archive.read(n) for n in archive.namelist()))
            self.assertNotIn("MOCK_PASSWORD", json.dumps(result))
            return result

    def test_windows_configuration_rejects_foreign_endpoint(self):
        env = {k: "12345678-1234-1234-1234-123456789abc" for k in ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"]}
        env.update(AZURE_SIGNING_ENDPOINT="https://eus.codesigning.azure.net", AZURE_SIGNING_ACCOUNT="account", AZURE_SIGNING_CERTIFICATE_PROFILE="profile", WINDOWS_PUBLISHER_NAME="PUBLIC TEST ORG")
        self.assertTrue(signing.windows_configuration(env)["configured"])
        env["AZURE_SIGNING_ENDPOINT"] = "https://other.invalid?secret=do-not-send"
        with self.assertRaisesRegex(ValueError, "ENDPOINT"): signing.windows_configuration(env)

    def test_windows_rotating_leaf_fingerprints_are_captured(self):
        for char in ["a", "b"]:
            payload = {"verified": True, "publisher": "PUBLIC TEST ORG", "certificate_sha1": char * 40,
                       "certificate_sha256": char * 64, "timestamp_present": True}
            def native(args, **kwargs):
                return subprocess.CompletedProcess(args, 0, json.dumps(payload).encode(), b"")
            with mock.patch.object(signing, "require_host"), mock.patch.object(signing, "signtool", return_value="signtool"), mock.patch.object(signing, "command", side_effect=native):
                data = signing.verify_windows(Path("control.exe"), {"WINDOWS_PUBLISHER_NAME": "PUBLIC TEST ORG"})
            self.assertEqual(data["certificate_sha256"], char * 64)

    def test_windows_bad_publisher_or_missing_timestamp_refused(self):
        for changes in [{"publisher": "OTHER ORG"}, {"timestamp_present": False}, {"certificate_sha256": "invalid"}]:
            payload = {"verified": True, "publisher": "PUBLIC TEST ORG", "certificate_sha1": "a" * 40,
                       "certificate_sha256": "b" * 64, "timestamp_present": True, **changes}
            with mock.patch.object(signing, "require_host"), mock.patch.object(signing, "signtool", return_value="signtool"), mock.patch.object(signing, "command", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload).encode(), b"")):
                with self.assertRaisesRegex(ValueError, "AUTHENTICODE"):
                    signing.verify_windows(Path("control.exe"), {"WINDOWS_PUBLISHER_NAME": "PUBLIC TEST ORG"})


if __name__ == "__main__": unittest.main()
