#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fetch pinned private inputs via a read-only SSH deploy key or release PAT."""
import argparse
import hashlib
import json
import os
import re
import shlex
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


GITHUB_KNOWN_HOST = (
    "github.com ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
)


def fetch_ssh(descriptor, output):
    if descriptor.get("path") != "inputs/" + descriptor["asset"]:
        raise ValueError("Invalid private git input path")
    if not re.fullmatch(r"[0-9a-f]{40}", descriptor.get("commit", "")):
        raise ValueError("A full git commit pin is required")
    key = os.environ.get("STORE_INPUTS_DEPLOY_KEY", "")
    if not key:
        raise ValueError("STORE_INPUTS_DEPLOY_KEY is required")
    with tempfile.TemporaryDirectory(prefix="store-private-ssh-") as directory:
        root = Path(directory)
        identity = root / "identity"
        with os.fdopen(os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as target:
            target.write(key.rstrip("\r\n") + "\n")
        known_hosts = root / "known_hosts"
        known_hosts.write_text(GITHUB_KNOWN_HOST)
        env = {k: v for k, v in os.environ.items() if k not in {
            "STORE_INPUTS_DEPLOY_KEY", "GH_TOKEN", "GITHUB_TOKEN", "SSH_AUTH_SOCK", "SSH_AGENT_PID",
            "GIT_SSH", "GIT_SSH_COMMAND", "GIT_CONFIG_COUNT"}}
        env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                   GIT_SSH_VARIANT="ssh", GIT_SSH_COMMAND=shlex.join([
                       "ssh", "-F", "/dev/null", "-i", str(identity), "-o", "IdentitiesOnly=yes",
                       "-o", "IdentityAgent=none", "-o", "BatchMode=yes", "-o", "ForwardAgent=no",
                       "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
                       "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
                       "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "GlobalKnownHostsFile=/dev/null",
                       "-o", "UserKnownHostsFile=" + str(known_hosts)]))
        checkout = root / "checkout"
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "clone", "--no-checkout", "--depth", "1",
                        "--single-branch", "--branch", descriptor["tag"],
                        "git@github.com:" + descriptor["repository"] + ".git", str(checkout)],
                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=120)

        def git(*args):
            return subprocess.run(["git", "-C", str(checkout), *args], env=env,
                                  capture_output=True, check=True, timeout=30).stdout

        if git("rev-parse", "HEAD").decode().strip() != descriptor["commit"]:
            raise ValueError("Private git tag commit differs from pin")

        def blob(path):
            entry = git("ls-tree", "-z", "HEAD", "--", path)
            fields = entry.rstrip(b"\0").split(b"\t")
            if (len(fields) != 2 or fields[1] != path.encode()
                    or not fields[0].startswith(b"100644 blob ")):
                raise ValueError("Private git input must be one regular blob")
            return git("cat-file", "blob", "HEAD:" + path)

        sums = {}
        for line in blob("inputs/SHA256SUMS").decode("ascii").splitlines():
            fields = line.split()
            if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]) or fields[1] in sums:
                raise ValueError("Invalid private input SHA256SUMS")
            sums[fields[1]] = fields[0]
        if sums.get(descriptor["asset"]) != descriptor["sha256"]:
            raise ValueError("Private git SHA256SUMS differs from reviewed descriptor")
        archive = root / descriptor["asset"]
        archive.write_bytes(blob(descriptor["path"]))
        return extract(archive, descriptor, output)


def fetch_pat(descriptor, output):
    tag = descriptor.get("release_tag", descriptor["tag"])
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", tag):
        raise ValueError("Invalid private release tag")
    env = {k: v for k, v in os.environ.items() if k != "STORE_INPUTS_DEPLOY_KEY"}
    if not env.get("GH_TOKEN"):
        raise ValueError("STORE_INPUTS_READ_TOKEN is required")
    private = subprocess.run(["gh", "api", "repos/" + descriptor["repository"], "--jq", ".private"],
                             env=env, capture_output=True, text=True, check=True).stdout.strip()
    if private != "true":
        raise ValueError("Input repository must be private")
    with tempfile.TemporaryDirectory(prefix="store-private-") as directory:
        subprocess.run(["gh", "release", "download", tag, "--repo", descriptor["repository"],
                        "--pattern", descriptor["asset"], "--dir", directory], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        return extract(Path(directory) / descriptor["asset"], descriptor, output)


def fetch(descriptor, output, transport="auto"):
    if descriptor["repository"] != "abx-takt/store-build-inputs":
        raise ValueError("Unapproved private input repository")
    for field in ("tag", "asset"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", descriptor[field]):
            raise ValueError("Invalid release identity")
    if transport == "auto":
        transport = "ssh" if os.environ.get("STORE_INPUTS_DEPLOY_KEY") else "pat"
    if transport == "ssh":
        return fetch_ssh(descriptor, output)
    if transport == "pat":
        return fetch_pat(descriptor, output)
    raise ValueError("Invalid input transport")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--transport", choices=("auto", "ssh", "pat"), default="auto")
    args = parser.parse_args()
    try:
        count = fetch(json.loads(args.descriptor.read_text()), args.output, args.transport)
        print(json.dumps({"status": "HASH_VERIFIED", "files": count}))
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        raise SystemExit("Private input fetch refused: " + type(error).__name__) from None
