# SPDX-License-Identifier: MIT
"""SSH/release transport controls. No keys generated and no network connections."""
import base64
import hashlib
import io
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import fetch_private_inputs as inputs


class InputTransportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("native.so", b"fake fixture bytes, not executable")
        self.archive = stream.getvalue()
        self.descriptor = {
            "repository": "abx-takt/store-build-inputs", "tag": "inputs-git-2026-10-31-v6",
            "release_tag": "store-inputs-2026-10-31-v6", "commit": "7f34571" + "a" * 33,
            "asset": "fixture-inputs.zip", "path": "inputs/fixture-inputs.zip",
            "sha256": inputs.digest(self.archive), "files": {"native.so": {
                "bytes": len(b"fake fixture bytes, not executable"),
                "sha256": inputs.digest(b"fake fixture bytes, not executable")}}}
        self.identity = None

    def git(self, command, **kwargs):
        env = kwargs["env"]
        self.assertNotIn("STORE_INPUTS_DEPLOY_KEY", env)
        self.assertNotIn("GH_TOKEN", env)
        ssh = shlex.split(env["GIT_SSH_COMMAND"])
        self.identity = Path(ssh[ssh.index("-i") + 1])
        self.assertEqual(self.identity.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.identity.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.identity.read_text(), "MOCK_SECRET_NOT_A_KEY\n")
        self.assertNotIn("MOCK_SECRET_NOT_A_KEY", str(command))
        self.assertIn("StrictHostKeyChecking=yes", ssh)
        self.assertIn("IdentityAgent=none", ssh)
        self.assertIn("HostKeyAlgorithms=ssh-ed25519", ssh)
        self.assertNotIn("MOCK_SECRET_NOT_A_KEY", str(env))
        if "clone" in command:
            self.assertIn("--no-checkout", command)
            self.assertIn("git@github.com:abx-takt/store-build-inputs.git", command)
            payload = b""
        elif "rev-parse" in command:
            payload = self.descriptor["commit"].encode() + b"\n"
        elif "ls-tree" in command:
            payload = b"100644 blob " + b"1" * 40 + b"\t" + command[-1].encode() + b"\0"
        elif command[-1] == "HEAD:inputs/SHA256SUMS":
            payload = (self.descriptor["sha256"] + "  fixture-inputs.zip\n").encode()
        else:
            self.assertEqual(command[-1], "HEAD:inputs/fixture-inputs.zip")
            payload = self.archive
        return subprocess.CompletedProcess(command, 0, payload, b"")

    @patch.dict(os.environ, {"STORE_INPUTS_DEPLOY_KEY": "MOCK_SECRET_NOT_A_KEY", "GH_TOKEN": "MOCK_PAT"})
    def test_auto_ssh_pins_identity_and_cleans_up(self):
        with patch.object(inputs.subprocess, "run", side_effect=self.git) as run:
            self.assertEqual(inputs.fetch(self.descriptor, self.root / "output"), 1)
        self.assertTrue(all(call.args[0][0] == "git" for call in run.call_args_list))
        self.assertEqual((self.root / "output/native.so").read_bytes(), b"fake fixture bytes, not executable")
        self.assertFalse(self.identity.parent.exists())

    @patch.dict(os.environ, {"STORE_INPUTS_DEPLOY_KEY": "MOCK_SECRET_NOT_A_KEY"})
    def test_wrong_tag_commit_stops_before_blob_reads(self):
        def changed(command, **kwargs):
            result = self.git(command, **kwargs)
            if "rev-parse" in command:
                result.stdout = b"0" * 40 + b"\n"
            return result
        with patch.object(inputs.subprocess, "run", side_effect=changed) as run:
            with self.assertRaises(ValueError):
                inputs.fetch(self.descriptor, self.root / "output", "ssh")
        self.assertEqual(run.call_count, 2)
        self.assertFalse((self.root / "output").exists())
        self.assertFalse(self.identity.parent.exists())

    @patch.dict(os.environ, {"STORE_INPUTS_DEPLOY_KEY": "MOCK_SECRET_NOT_A_KEY"})
    def test_symlink_and_checksum_disagreement_refused(self):
        for kind in ["symlink", "checksum"]:
            def changed(command, **kwargs):
                result = self.git(command, **kwargs)
                if kind == "symlink" and "ls-tree" in command:
                    result.stdout = result.stdout.replace(b"100644", b"120000")
                if kind == "checksum" and command[-1] == "HEAD:inputs/SHA256SUMS":
                    result.stdout = ("0" * 64 + "  fixture-inputs.zip\n").encode()
                return result
            with self.subTest(kind=kind), patch.object(inputs.subprocess, "run", side_effect=changed):
                with self.assertRaises(ValueError):
                    inputs.fetch(self.descriptor, self.root / kind, "ssh")
            self.assertFalse((self.root / kind).exists())
            self.assertFalse(self.identity.parent.exists())

    @patch.dict(os.environ, {"STORE_INPUTS_DEPLOY_KEY": "MOCK_SECRET_NOT_A_KEY"})
    def test_invalid_path_commit_repository_tag_refused_before_network(self):
        for key, value in [("path", "../inputs.zip"), ("commit", "short"),
                           ("repository", "another/repo"), ("tag", "--upload-pack=bad")]:
            descriptor = {**self.descriptor, key: value}
            with self.subTest(key=key), patch.object(inputs.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    inputs.fetch(descriptor, self.root / key, "ssh")
                run.assert_not_called()

    @patch.dict(os.environ, {"STORE_INPUTS_DEPLOY_KEY": "", "GH_TOKEN": ""})
    def test_missing_credentials_refused(self):
        for mode in ["auto", "ssh", "pat"]:
            with self.subTest(mode=mode), patch.object(inputs.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    inputs.fetch(self.descriptor, self.root / mode, mode)
                run.assert_not_called()

    @patch.dict(os.environ, {"STORE_INPUTS_DEPLOY_KEY": "DO_NOT_PASS_TO_GH", "GH_TOKEN": "MOCK_PAT"})
    def test_pat_alternative_keeps_release_tag_and_existing_sha_checks(self):
        def gh(command, **kwargs):
            self.assertNotIn("STORE_INPUTS_DEPLOY_KEY", kwargs["env"])
            if command[1] == "api":
                return subprocess.CompletedProcess(command, 0, "true\n", "")
            self.assertEqual(command[3], self.descriptor["release_tag"])
            (Path(command[-1]) / self.descriptor["asset"]).write_bytes(self.archive)
            return subprocess.CompletedProcess(command, 0)
        with patch.object(inputs.subprocess, "run", side_effect=gh):
            self.assertEqual(inputs.fetch(self.descriptor, self.root / "pat", "pat"), 1)

    def test_host_key_matches_github_documented_fingerprint(self):
        raw = base64.b64decode(inputs.GITHUB_KNOWN_HOST.split()[2])
        actual = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        self.assertEqual(actual, "+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU")


if __name__ == "__main__":
    unittest.main()
