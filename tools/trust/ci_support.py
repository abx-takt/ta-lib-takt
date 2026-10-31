#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Assemble and check approved store inputs in unprivileged CI jobs."""

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

from build_store_wheel import build

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_record(wheel):
    with zipfile.ZipFile(wheel) as archive:
        files = set(archive.namelist())
        record = next(n for n in files if n.endswith(".dist-info/RECORD"))
        listed = set()
        for name, encoded, length in csv.reader(io.StringIO(archive.read(record).decode())):
            listed.add(name)
            if name == record:
                if encoded or length:
                    raise ValueError("Invalid self RECORD")
                continue
            data = archive.read(name)
            expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            if encoded != expected or length != str(len(data)):
                raise ValueError("Wheel RECORD mismatch: " + name)
        if listed != files:
            raise ValueError("Unrecorded/missing wheel member")
        return len(files)


def assemble(manifest_path, output):
    manifest = json.loads(manifest_path.read_text())
    output.mkdir(parents=True, exist_ok=False)
    result = build(manifest, output / "dist")
    wheel = output / "dist" / result["wheel"]
    validate_record(wheel)
    reference = output / "reference"
    reference.mkdir()
    source = Path(manifest["source_wheel"]["path"])
    shutil.copyfile(source, reference / source.name)
    release_files = [{"path": "dist/" + wheel.name, "sha256": digest(wheel), "kind": "wheel"}]
    with zipfile.ZipFile(wheel) as archive:
        for member, info in result["profile"]["native"].items():
            target = output / "native" / manifest["package"] / Path(member).name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))
            if digest(target) != info["sha256"]:
                raise ValueError("Extracted final native digest mismatch")
            release_files.append({"path": str(target.relative_to(output)), "sha256": digest(target), "kind": "native"})
    inventory = {"package": manifest["package"], "version": manifest["version"], "profile": "store",
                 "files": release_files.copy(), "source_wheel": source.name,
                 "source_wheel_sha256": manifest["source_wheel"]["sha256"],
                 "import_package": manifest["import_package"],
                 "provenance_boundary": "assembly of approved pinned native inputs, not full reproducibility of closed native source"}
    (output / "STORE_MANIFEST.json").write_text(json.dumps(inventory, indent=2) + "\n")
    release_files.append({"path": "STORE_MANIFEST.json", "sha256": digest(output / "STORE_MANIFEST.json"), "kind": "manifest"})
    (output / "release_files.json").write_text(json.dumps({"files": release_files}, indent=2) + "\n")
    (output / "SHA256SUMS").write_text("".join(item["sha256"] + "  " + item["path"] + "\n" for item in release_files))
    return inventory


def check(bundle, report):
    info = json.loads((bundle / "STORE_MANIFEST.json").read_text())
    report.mkdir(parents=True, exist_ok=False)
    wheel = bundle / next(x["path"] for x in info["files"] if x["kind"] == "wheel")
    original = bundle / "reference" / info["source_wheel"]
    if digest(original) != info["source_wheel_sha256"]:
        raise ValueError("Reference source wheel hash mismatch")
    record_count = validate_record(wheel)
    values = {}
    for mode, candidate in (("reference", original), ("store", wheel)):
        site = report / (mode + "_site")
        subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(site), str(candidate)],
                       check=True, stdout=subprocess.DEVNULL)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("LD_", "PYTHONHOME"))}
        env.update(PYTHONPATH=str(site), PYTHONDONTWRITEBYTECODE="1", OMP_NUM_THREADS="1",
                   OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS="1", NUMEXPR_NUM_THREADS="1")
        command = [sys.executable, "-B", str(HERE / "smoke.py"), info["package"]]
        result = subprocess.run(command, env=env, capture_output=True, timeout=120, check=True)
        values[mode] = result.stdout
        if mode == "store":
            verify = site / info["import_package"] / "verify"
            for source in (HERE / "resources-v6/verify").iterdir():
                if source.is_file() and digest(source) != digest(verify / source.name):
                    raise ValueError("Bundled verifier differs from reviewed source: " + source.name)
            observed = subprocess.run(["sh", str(verify / "pure.sh"), "--safe-fds", "--", *command], env=env,
                                      capture_output=True, timeout=120)
            (report / "pure.stdout").write_bytes(observed.stdout)
            (report / "pure.stderr").write_bytes(observed.stderr)
            if observed.returncode != 0 or not observed.stdout.startswith(values["store"]):
                raise RuntimeError("Pure check incomplete/failed or scientific output changed; inspect local receipts")
    if values["reference"] != values["store"]:
        raise ValueError("Complete native smoke output differs")
    result = {"package": info["package"], "version": info["version"], "full_smoke_BYTE_EXACT": True,
              "stdout_bytes": len(values["store"]), "stdout_sha256": hashlib.sha256(values["store"]).hexdigest(),
              "pure_status": "PASS", "wheel_RECORD_files": record_count,
              "wheel_sha256": digest(wheel), "scope": "declared smoke only; all stdout bytes compared, no new speed claim",
              "threads": 1, "python_bytecode_writes": "disabled explicitly with -B"}
    (report / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("assemble", "check"))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()
    result = assemble(args.manifest.resolve(), args.output.resolve()) if args.action == "assemble" else check(args.bundle.resolve(), args.output.resolve())
    print(json.dumps(result))
