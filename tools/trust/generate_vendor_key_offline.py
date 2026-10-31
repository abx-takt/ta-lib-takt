#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""OWNER ONLY: generate Ed25519 in memory; persist private material only through age."""
import argparse
import base64
import hashlib
import json
import os
import re
import resource
import subprocess
from pathlib import Path


def command(argv, data=None):
    # X25519 age recipient only: no agent/plugin or network service is involved.
    return subprocess.run(["unshare", "-rn", "--", *argv], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout


def write_new(path, data, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    os.fchmod(descriptor, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def generate(recipient_file, private_directory, public_directories):
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    recipient = recipient_file.read_text().strip()
    if not re.fullmatch(r"age1[0-9a-z]{58}", recipient):
        raise ValueError("Supply exactly one trusted owner X25519 age recipient")
    names = ("vendor-entitlement-v1.pub.pem", "vendor-entitlement-v1.json")
    if private_directory.exists() or any((p / n).exists() for p in public_directories for n in names):
        raise FileExistsError("Existing keys/anchors are never overwritten")
    private = command(["openssl", "genpkey", "-algorithm", "ED25519"])
    try:
        public = command(["openssl", "pkey", "-pubout"], private)
        der = base64.b64decode(b"".join(public.splitlines()[1:-1]), validate=True)
        if len(der) != 44 or not der.startswith(bytes.fromhex("302a300506032b6570032100")):
            raise ValueError("Expected Ed25519 SubjectPublicKeyInfo")
        encrypted = command(["age", "--encrypt", "--recipient", recipient], private)
        if not encrypted.startswith(b"age-encryption.org/v1\n"):
            raise ValueError("age encryption did not produce its expected format")
    finally:
        # Python cannot promise secure memory wiping. No private plaintext file/log is created.
        del private
    private_directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    write_new(private_directory / "vendor-entitlement-v1.pkcs8.pem.age", encrypted, 0o600)
    metadata = {"schema": 1, "status": "OWNER_GENERATED", "algorithm": "Ed25519",
                "purpose": "offline vendor entitlement certificates, no binary licence checks",
                "key_id": "sha256:" + hashlib.sha256(der).hexdigest(),
                "public_key": names[0], "public_key_sha256": hashlib.sha256(public).hexdigest()}
    for directory in public_directories:
        directory.mkdir(parents=True, exist_ok=True)
        write_new(directory / names[0], public, 0o644)
        write_new(directory / names[1], (json.dumps(metadata, indent=2) + "\n").encode(), 0o644)
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipient-file", required=True, type=Path)
    parser.add_argument("--private-directory", required=True, type=Path)
    parser.add_argument("--public-directory", required=True, action="append", type=Path)
    args = parser.parse_args()
    try:
        result = generate(args.recipient_file, args.private_directory, args.public_directory)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit("Key generation stopped: " + type(error).__name__ + "; inspect local output paths") from None
    print(json.dumps(result))  # Public metadata only; never key/recipient/private bytes.
