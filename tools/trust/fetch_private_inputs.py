#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fetch a private release asset and extract only its reviewed, pinned files."""
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def extract(archive, descriptor, output):
    if digest(archive.read_bytes()) != descriptor["sha256"]:
        raise ValueError("Private asset SHA256 mismatch")
    expected = descriptor["files"]
    if not expected or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", n) for n in expected):
        raise ValueError("Invalid input filenames")
    contents = {}
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) != len(expected) or {x.filename for x in members} != set(expected):
            raise ValueError("Missing, duplicate or unexpected private inputs")
        for member in members:
            pin = expected[member.filename]
            if member.is_dir() or stat.S_IFMT(member.external_attr >> 16) not in (0, stat.S_IFREG):
                raise ValueError("Only regular input files are allowed")
            if member.file_size != pin["bytes"] or not 0 < member.file_size <= 512 * 1024**2:
                raise ValueError("Private input size mismatch")
            data = source.read(member)
            if digest(data) != pin["sha256"]:
                raise ValueError("Private input SHA256 mismatch")
            contents[member.filename] = data
    output.mkdir(parents=True, exist_ok=False)
    for name, data in contents.items():
        (output / name).write_bytes(data)
    return len(contents)


def fetch(descriptor, output):
    if descriptor["repository"] != "abx-takt/store-build-inputs":
        raise ValueError("Unapproved private input repository")
    for field in ("tag", "asset"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", descriptor[field]):
            raise ValueError("Invalid release identity")
    if not os.environ.get("GH_TOKEN"):
        raise ValueError("STORE_INPUTS_READ_TOKEN is required")
    private = subprocess.run(["gh", "api", "repos/" + descriptor["repository"], "--jq", ".private"],
                             capture_output=True, text=True, check=True).stdout.strip()
    if private != "true":
        raise ValueError("Input repository must be private")
    with tempfile.TemporaryDirectory(prefix="store-private-") as directory:
        subprocess.run(["gh", "release", "download", descriptor["tag"], "--repo", descriptor["repository"],
                        "--pattern", descriptor["asset"], "--dir", directory],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        return extract(Path(directory) / descriptor["asset"], descriptor, output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        count = fetch(json.loads(args.descriptor.read_text()), args.output)
        print(json.dumps({"status": "HASH_VERIFIED", "files": count}))
    except (ValueError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        raise SystemExit("Private input fetch refused: " + type(error).__name__) from None
