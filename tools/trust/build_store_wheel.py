#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Assemble a store wheel from hash-pinned inputs; never invoke a protector.

Manifest keys: package, version, import_package, source_wheel{path,sha256},
native_replacements[{member,path,sha256,evidence}], upstream_native_members.
Evidence describes the pre-protection/compiler input pin, not public source.
"""

import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import zipfile


HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_plain_elf(data, member):
    if not data.startswith(b"\x7fELF\x02\x01"):
        raise ValueError("Expected little-endian ELF64: " + member)
    if struct.unpack_from("<H", data, 18)[0] != 62:
        raise ValueError("This store profile is for x86-64 only")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    for index in range(count):
        kind, flags = struct.unpack_from("<II", data, offset + index * size)
        if kind == 1 and flags & 3 == 3:
            raise ValueError("Writable executable LOAD segment: " + member)
    if any(marker in data for marker in (b"UPX!", b"UPX0\0", b"UPX1\0", b".themida\0", b".aspack\0")):
        raise ValueError("Known executable packer marker: " + member)
    return {"format": "ELF64 x86-64", "no_writable_executable_LOAD": True,
            "known_packer_markers_absent": True,
            "limitation": "Structural check, not a proof that arbitrary code contains no packing or anti-debugging"}


def build(manifest, output):
    if manifest.get("profile") != "store":
        raise ValueError("Explicit profile=store is required")
    package = manifest["package"]
    version = manifest["version"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", package) or not re.fullmatch(r"[0-9][A-Za-z0-9.]+", version):
        raise ValueError("Invalid package/version")
    source = Path(manifest["source_wheel"]["path"])
    source_bytes = source.read_bytes()
    if sha(source_bytes) != manifest["source_wheel"]["sha256"]:
        raise ValueError("Source wheel SHA mismatch")
    with zipfile.ZipFile(io.BytesIO(source_bytes)) as archive:
        entries = {i.filename: archive.read(i) for i in archive.infolist() if not i.is_dir()}
    old_dist = next(name.rsplit("/", 1)[0] for name in entries if name.endswith(".dist-info/METADATA"))
    new_dist = package.replace("-", "_") + "-" + version + ".dist-info"
    entries = {(new_dist + name[len(old_dist):] if name.startswith(old_dist + "/") else name): data
               for name, data in entries.items() if not name.endswith(("/RECORD", "/RECORD.jws", "/RECORD.p7s"))}
    evidence = {}
    replacements = manifest["native_replacements"]
    if not replacements:
        raise ValueError("At least one explicitly pinned store native replacement is required")
    for replacement in replacements:
        member = replacement["member"]
        if member not in entries:
            raise ValueError("No such native member in source wheel: " + member)
        data = Path(replacement["path"]).read_bytes()
        if sha(data) != replacement["sha256"]:
            raise ValueError("Native input SHA mismatch: " + member)
        if not replacement.get("evidence"):
            raise ValueError("Store producer evidence is required")
        entries[member] = data
        evidence[member] = replacement["evidence"]
    native = {name: data for name, data in entries.items() if data.startswith(b"\x7fELF")}
    declared = {r["member"] for r in replacements} | set(manifest.get("upstream_native_members", []))
    if set(native) != declared:
        raise ValueError("Every native member must be accounted for by replacement or unchanged upstream input")
    native_inventory = {name: {"sha256": sha(data), "bytes": len(data), **check_plain_elf(data, name),
                              "producer": "store input" if name in evidence else "unchanged input wheel member"}
                        for name, data in sorted(native.items())}
    verify_root = manifest["import_package"] + "/verify"
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", manifest["import_package"]):
        raise ValueError("Invalid import_package")
    for path in sorted((HERE / "resources-v6/verify").iterdir()):
        if path.is_file() and path.name in {"pure.sh", "pure_runner.py", "trace_check.py", "signature.sh", "README.md", "LICENSE-MIT"}:
            entries[verify_root + "/" + path.name] = path.read_bytes()
    profile = {
        "profile": "store", "verifier_profile": "resources-v6", "package": package, "version": version,
        "executable_packer": False, "anti_debug_wrapper": False, "code_obfuscator": False,
        "build_boundary": "Hash-pinned wheel assembly from pre-protection/compiler native inputs; no protector invocation",
        "source_wheel_sha256": sha(source_bytes), "native": native_inventory,
        "input_evidence": evidence,
        "purity_scope": "verify/pure.sh observes only its concrete invocation; upstream user-requested I/O remains available",
        "signing": "Sign final wheel and exact native payloads outside wheel; no embedded self-signature claim",
    }
    entries[verify_root + "/STORE_PROFILE.json"] = (json.dumps(profile, indent=2, sort_keys=True) + "\n").encode()
    metadata = entries[new_dist + "/METADATA"].decode()
    metadata = re.sub(r"(?m)^Name: .+$", "Name: " + package, metadata)
    metadata = re.sub(r"(?m)^Version: .+$", "Version: " + version, metadata)
    metadata = re.sub(r"(?m)^License-Expression: (.+)$", lambda m: "License-Expression: (" + m[1] + ") AND MIT", metadata)
    head, body = metadata.split("\n\n", 1)
    head += "\nLicense-File: LICENSE-TAKT-TRUST-MIT"
    body += ("\n\nStore profile: native inputs bypass executable packing, code obfuscation and anti-debug wrappers. "
             "The bundled verify/pure.sh observes a concrete command and its inputs; upstream user-requested I/O remains available. "
             "Verify final release signatures/provenance separately; no safety certificate is implied.\n")
    metadata = head + "\n\n" + body
    entries[new_dist + "/METADATA"] = metadata.encode()
    entries[new_dist + "/licenses/LICENSE-TAKT-TRUST-MIT"] = (HERE / "resources-v6/verify/LICENSE-MIT").read_bytes()
    wheel = entries[new_dist + "/WHEEL"].decode()
    wheel = re.sub(r"(?m)^Generator: .+$", "Generator: takt-store-assembly-v1", wheel)
    entries[new_dist + "/WHEEL"] = wheel.encode()
    rows = []
    for name, data in sorted(entries.items()):
        encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        rows.append([name, "sha256=" + encoded, str(len(data))])
    record = io.StringIO()
    csv.writer(record, lineterminator="\n").writerows(rows + [[new_dist + "/RECORD", "", ""]])
    entries[new_dist + "/RECORD"] = record.getvalue().encode()
    tag = "-".join(source.name.removesuffix(".whl").split("-")[-3:])
    wheel_name = package.replace("-", "_") + "-" + version + "-" + tag + ".whl"
    output.mkdir(parents=True, exist_ok=True)
    target = output / wheel_name
    if target.exists():
        raise FileExistsError(target)
    with zipfile.ZipFile(target, "x") as archive:
        for name, data in sorted(entries.items()):
            item = zipfile.ZipInfo(name, date_time=(2026, 10, 30, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = (0o755 if data.startswith(b"\x7fELF") or name.endswith(".sh") else 0o644) << 16
            archive.writestr(item, data)
    result = {"wheel": target.name, "wheel_sha256": sha(target.read_bytes()), "profile": profile,
              "files": {name: {"sha256": sha(data), "bytes": len(data),
                                "virustotal_url": "https://www.virustotal.com/gui/file/" + sha(data)}
                        for name, data in sorted(entries.items())}}
    (output / (wheel_name + ".store.json")).write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = build(json.loads(args.manifest.read_text()), args.output.resolve())
    print(json.dumps({"wheel": result["wheel"], "sha256": result["wheel_sha256"]}))
