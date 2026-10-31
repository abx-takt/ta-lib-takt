#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage/repack a reviewed desktop store wheel around OS signing; never publish."""
import argparse
import base64
import csv
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

from desktop_bootstrap import TARGETS, inspect_native
from desktop_signing import code_data_fingerprint, digest, verify_native


def safe_member(name):
    parts = name.rstrip("/").split("/")
    if not name or "\\" in name or ":" in name or PurePosixPath(name).is_absolute() or any(x in {"", ".", ".."} for x in parts):
        raise ValueError("UNSAFE_WHEEL_MEMBER")


def read_wheel(path, expected):
    if path.stat().st_size > 1024**3:
        raise ValueError("SOURCE_WHEEL_FILE_CAP")
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError("SOURCE_WHEEL_SHA256_MISMATCH")
    entries, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        seen = set()
        for info in archive.infolist():
            safe_member(info.filename)
            if info.filename in seen:
                raise ValueError("DUPLICATE_WHEEL_MEMBER")
            seen.add(info.filename)
            if info.is_dir():
                continue
            if stat.S_IFMT(info.external_attr >> 16) not in {0, stat.S_IFREG}:
                raise ValueError("WHEEL_MEMBERS_MUST_BE_REGULAR")
            total += info.file_size
            if info.file_size > 512 * 1024**2 or total > 2 * 1024**3:
                raise ValueError("WHEEL_UNPACK_CAP")
            entries[info.filename] = archive.read(info)
    return entries


def profile_and_native(entries, target):
    profiles = [name for name in entries if name.endswith("/verify/STORE_PROFILE.json")]
    if len(profiles) != 1:
        raise ValueError("ONE_REVIEWED_STORE_PROFILE_REQUIRED")
    profile = json.loads(entries[profiles[0]])
    if profile.get("profile") != "store" or profile.get("target_platform") != target:
        raise ValueError("DESKTOP_STORE_PROFILE_TARGET_MISMATCH")
    if any(profile.get(key) is not False for key in ["executable_packer", "anti_debug_wrapper", "code_obfuscator"]):
        raise ValueError("EXPLICIT_UNPACKED_STORE_PROFILE_REQUIRED")
    wheel_metadata = [name for name in entries if name.endswith(".dist-info/WHEEL")]
    if len(wheel_metadata) != 1:
        raise ValueError("ONE_WHEEL_METADATA_REQUIRED")
    tags = re.findall(r"(?m)^Tag: [^-\r\n]+-[^-\r\n]+-([^\r\n]+)$", entries[wheel_metadata[0]].decode())
    if not tags:
        raise ValueError("WHEEL_PLATFORM_TAG_REQUIRED")
    minimum_tag = None
    for tag in tags:
        if target == "windows_x86_64":
            if tag != "win_amd64":
                raise ValueError("WHEEL_PLATFORM_TAG_MISMATCH")
        else:
            arch = "arm64" if target.endswith("arm64") else "x86_64"
            match = re.fullmatch(r"macosx_([0-9]+)_([0-9]+)_" + arch, tag)
            if not match:
                raise ValueError("WHEEL_PLATFORM_TAG_MISMATCH")
            version = [int(match[1]), int(match[2]), 0]
            minimum_tag = min(minimum_tag, version) if minimum_tag else version
    native = {name: data for name, data in entries.items()
              if data.startswith((b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"))}
    if not native or set(native) != set(profile.get("native", {})):
        raise ValueError("ALL_NATIVE_WHEEL_MEMBERS_MUST_BE_DECLARED")
    for name, data in native.items():
        info = inspect_native(data, target)
        if target.startswith("macos_") and (not info["minimum_macos"] or info["minimum_macos"] > minimum_tag):
            raise ValueError("MACHO_MINIMUM_OS_EXCEEDS_WHEEL_TAG_OR_IS_UNKNOWN")
        if digest(data) != profile["native"][name].get("sha256"):
            raise ValueError("PROFILE_NATIVE_SHA256_MISMATCH")
    return profiles[0], profile, native


def prepare(wheel, expected, target, output):
    if target not in TARGETS:
        raise ValueError("UNKNOWN_DESKTOP_TARGET")
    entries = read_wheel(wheel, expected)
    profile_name, profile, native = profile_and_native(entries, target)
    output.mkdir(parents=True, exist_ok=False)
    rows = {}
    for name, data in native.items():
        path = output / "subjects" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        rows[name] = {"sha256_before": digest(data), "code_data_sha256": code_data_fingerprint(data, target)}
    manifest = {"schema": 1, "scope": "REVIEWED_UNSIGNED_STORE_WHEEL_OS_SIGNING", "target": target,
                "source_wheel_sha256": expected, "profile_member": profile_name, "subjects": rows,
                "release_ready": False, "native_purity": "MISSING", "full_numerical_evidence": "MISSING"}
    (output / "UNSIGNED_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def finish(wheel, prepared, final, *, verifier=verify_native):
    manifest = json.loads((prepared / "UNSIGNED_MANIFEST.json").read_text())
    if manifest.get("scope") != "REVIEWED_UNSIGNED_STORE_WHEEL_OS_SIGNING":
        raise ValueError("UNSIGNED_MANIFEST_SCOPE_MISMATCH")
    target = manifest["target"]
    entries = read_wheel(wheel, manifest["source_wheel_sha256"])
    profile_name, profile, original = profile_and_native(entries, target)
    if set(original) != set(manifest["subjects"]):
        raise ValueError("UNSIGNED_MANIFEST_SUBJECT_MISMATCH")
    folder = prepared / "subjects"
    files = {p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file() or p.is_symlink()}
    if files != set(original):
        raise ValueError("SIGNED_SUBJECT_SET_CHANGED")
    receipts = {}
    for name, before in manifest["subjects"].items():
        safe_member(name)
        if digest(original[name]) != before["sha256_before"]:
            raise ValueError("UNSIGNED_SUBJECT_PIN_MISMATCH")
        path = folder / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024**2:
            raise ValueError("SIGNED_SUBJECT_MUST_BE_BOUNDED_REGULAR_FILE")
        data = path.read_bytes()
        if code_data_fingerprint(data, target) != before["code_data_sha256"]:
            raise ValueError("CODE_DATA_CHANGED_BY_SIGNING")
        signature = verifier(path, target)
        if signature.get("verified") is not True:
            raise ValueError("OS_SIGNATURE_NOT_VERIFIED")
        entries[name] = data
        receipts[name] = {**before, "sha256_after": digest(data), "code_data_sections_equal": True, "OS_signature": signature}
        profile["native"][name].update(sha256=digest(data), bytes=len(data), OS_signature=signature)
    profile["desktop_OS_signing"] = {"scope": "NATIVE_SUBJECTS_ONLY", "wheel_stapled": False,
                                      "native_install_and_purity": "MISSING", "numerical_SKU_evidence": "MISSING"}
    entries[profile_name] = (json.dumps(profile, indent=2, sort_keys=True) + "\n").encode()
    records = [name for name in entries if name.endswith(".dist-info/RECORD")]
    if len(records) != 1:
        raise ValueError("ONE_WHEEL_RECORD_REQUIRED")
    record_name = records[0]
    entries = {name: data for name, data in entries.items() if not name.endswith(("/RECORD", "/RECORD.jws", "/RECORD.p7s"))}
    rows = [[name, "sha256=" + base64.urlsafe_b64encode(bytes.fromhex(digest(data))).rstrip(b"=").decode(), str(len(data))]
            for name, data in sorted(entries.items())]
    record = io.StringIO()
    csv.writer(record, lineterminator="\n").writerows(rows + [[record_name, "", ""]])
    entries[record_name] = record.getvalue().encode()
    if final.exists() or final.resolve() == wheel.resolve():
        raise ValueError("FINAL_WHEEL_MUST_BE_NEW_FILE")
    wheel_metadata = next(name for name in entries if name.endswith(".dist-info/WHEEL"))
    tags = re.findall(r"(?m)^Tag: ([^\r\n]+)$", entries[wheel_metadata].decode())
    if len(tags) != 1 or not final.name.endswith("-" + tags[0] + ".whl"):
        raise ValueError("FINAL_WHEEL_FILENAME_TAG_MISMATCH")
    final.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(final, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 31, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    # Re-open all full members and validate every RECORD digest/length.
    with zipfile.ZipFile(final) as archive:
        actual = {name: archive.read(name) for name in archive.namelist()}
    listed = list(csv.reader(io.StringIO(actual[record_name].decode())))
    if len(listed) != len(actual) or {row[0] for row in listed} != set(actual):
        raise ValueError("FINAL_RECORD_MEMBER_SET_MISMATCH")
    for name, check, size in listed:
        if name == record_name:
            if check or size:
                raise ValueError("INVALID_RECORD_SELF_ENTRY")
        elif check != "sha256=" + base64.urlsafe_b64encode(bytes.fromhex(digest(actual[name]))).rstrip(b"=").decode() or size != str(len(actual[name])):
            raise ValueError("FINAL_RECORD_DIGEST_MISMATCH")
    result = {"schema": 1, "status": "FINAL_WHEEL_OS_SIGNED_RELEASE_BLOCKED", "target": target,
              "source_wheel_sha256": manifest["source_wheel_sha256"], "final_wheel_sha256": digest(final.read_bytes()),
              "subjects": receipts, "full_RECORD_verified": True, "release_ready": False,
              "publication_gate": "BLOCKED_NATIVE_FULL_NUMERICAL_AND_COMPLETE_PURITY_EVIDENCE_MISSING",
              "scanners_and_external_attestations": "MUST_RUN_ON_THESE_FINAL_BYTES",
              "mutation_check_scope": "loadable code/data sections, not a full semantic equivalence proof"}
    final.with_suffix(final.suffix + ".desktop-signing.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--wheel", type=Path, required=True)
    prepare_parser.add_argument("--expected-sha256", required=True)
    prepare_parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    finish_parser = commands.add_parser("finish")
    finish_parser.add_argument("--wheel", type=Path, required=True)
    finish_parser.add_argument("--prepared", type=Path, required=True)
    finish_parser.add_argument("--final", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(args.wheel, args.expected_sha256, args.target, args.output)
        print(json.dumps({"status": "HASH_PINNED_UNSIGNED_SUBJECTS_STAGED", "release_ready": False}))
    else:
        result = finish(args.wheel, args.prepared, args.final)
        print(json.dumps({"status": result["status"], "release_ready": result["release_ready"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
