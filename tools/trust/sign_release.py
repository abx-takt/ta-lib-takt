#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Sign only immutable allowlisted final artifacts; never execute payloads."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sign(bundle, output, cosign, mode, identity, key, pubkey, config, trusted_root):
    if mode == "keyless" and (not identity or not os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")):
        raise RuntimeError("NEED_GITHUB_OIDC_AND_EXPECTED_WORKFLOW_IDENTITY")
    if mode == "test-key" and not all((key, pubkey, config, trusted_root)):
        raise ValueError("Offline test requires key/public key and empty-service config/trusted root")
    output.mkdir(parents=True, exist_ok=False)
    index = json.loads((bundle / "release_files.json").read_text())["files"]
    receipts = []
    for item in index:
        original_path = bundle / item["path"]
        path = original_path.resolve()
        if not path.is_relative_to(bundle.resolve()) or original_path.is_symlink() or not path.is_file():
            raise ValueError("Artifact path leaves approved bundle")
        if item["kind"] not in {"wheel", "native", "manifest"}:
            raise ValueError("Non-release payload in signing list")
        if digest(path) != item["sha256"]:
            raise ValueError("Final bytes changed before signing")
        if item["kind"] == "wheel" and not path.name.endswith(".whl"):
            raise ValueError("Unexpected wheel filename")
        if item["kind"] == "native" and not path.read_bytes().startswith(b"\x7fELF"):
            raise ValueError("Expected final ordinary ELF payload")
        if item["kind"] == "manifest" and path.name != "STORE_MANIFEST.json":
            raise ValueError("Only the final manifest may be signed as metadata")
        signature = output / (path.name + "." + item["sha256"][:16] + ".sigstore.json")
        command = [str(cosign), "sign-blob", "--yes", "--bundle", str(signature)]
        verify = [str(cosign), "verify-blob", str(path), "--bundle", str(signature)]
        if mode == "keyless":
            command += ["--oidc-provider", "github-actions"]
            verify += ["--certificate-identity", identity, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"]
        else:
            command += ["--key", str(key), "--signing-config", str(config), "--trusted-root", str(trusted_root),
                        "--oidc-disable-ambient-providers"]
            verify += ["--key", str(pubkey), "--trusted-root", str(trusted_root), "--insecure-ignore-tlog"]
        subprocess.run([*command, str(path)], check=True)
        subprocess.run(verify, check=True)
        if digest(path) != item["sha256"]:
            raise ValueError("Final bytes changed during signing")
        receipts.append({"artifact": item["path"], "sha256": item["sha256"],
                         "bundle": signature.name, "bundle_sha256": digest(signature),
                         "mode": "PRODUCTION_KEYLESS" if mode == "keyless" else "TEST_ONLY_LOCAL_KEY_NO_PUBLISHER_IDENTITY"})
    (output / "SIGNED_FILES.json").write_text(json.dumps({"identity": identity if mode == "keyless" else None,
        "files": receipts, "payload_execution": False, "byte_transforms_after_signing": 0}, indent=2) + "\n")
    return receipts


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--cosign", type=Path, required=True)
    p.add_argument("--mode", choices=("keyless", "test-key"), default="keyless")
    p.add_argument("--identity")
    p.add_argument("--key", type=Path)
    p.add_argument("--public-key", type=Path)
    p.add_argument("--signing-config", type=Path)
    p.add_argument("--trusted-root", type=Path)
    a = p.parse_args()
    rows = sign(a.bundle.resolve(), a.output.resolve(), a.cosign.resolve(), a.mode, a.identity,
                a.key, a.public_key, a.signing_config, a.trusted_root)
    print(json.dumps({"signed_files": len(rows), "mode": a.mode}))
