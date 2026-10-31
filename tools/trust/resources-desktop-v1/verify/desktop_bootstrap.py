#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Desktop structural inventory and fail-closed bootstrap; never sign or publish."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct

TARGETS = {
    "windows_x86_64": ("Windows", {"amd64", "x86_64"}),
    "macos_x86_64": ("Darwin", {"x86_64", "amd64"}),
    "macos_arm64": ("Darwin", {"arm64", "aarch64"}),
}
PACKERS = (b"UPX!", b"UPX0\0", b"UPX1\0", b".themida\0", b".aspack\0")


def unpack(fmt, data, offset):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError("Truncated native structure")
    return struct.unpack_from(fmt, data, offset)


def string(data, offset, end):
    if offset < 0 or offset >= end or end > len(data):
        raise ValueError("Invalid string offset")
    stop = data.find(b"\0", offset, min(end, offset + 4096))
    if stop < 0:
        raise ValueError("Unterminated native string")
    return data[offset:stop].decode("utf-8", errors="strict")


def pe64(data):
    offset = unpack("<I", data, 0x3C)[0]
    if offset < 64 or data[offset:offset + 4] != b"PE\0\0":
        raise ValueError("Invalid PE signature")
    machine, sections = unpack("<HH", data, offset + 4)
    if machine != 0x8664 or not 0 < sections <= 4096:
        raise ValueError("Only PE64 x86-64 is admitted by this profile")
    optional_size = unpack("<H", data, offset + 20)[0]
    optional = offset + 24
    if optional_size < 112 or unpack("<H", data, optional)[0] != 0x20B:
        raise ValueError("Expected PE32+ optional header")
    table = optional + optional_size
    unpack("<" + "B" * (40 * sections), data, table)
    section_rows = []
    for i in range(sections):
        pos = table + 40 * i
        virtual_size, rva, raw_size, raw = unpack("<IIII", data, pos + 8)
        flags = unpack("<I", data, pos + 36)[0]
        if flags & 0x20000000 and flags & 0x80000000:
            raise ValueError("Writable executable PE section")
        if raw_size and (raw < table + 40 * sections or raw + raw_size > len(data)):
            raise ValueError("PE section outside file")
        section_rows.append((rva, max(virtual_size, raw_size), raw, raw_size))

    def file_offset(rva):
        for start, span, raw, raw_size in section_rows:
            if start <= rva < start + span:
                delta = rva - start
                if delta >= raw_size:
                    raise ValueError("Import RVA points outside stored section bytes")
                return raw + delta
        raise ValueError("Unmapped import RVA")

    imports = []
    directories = unpack("<I", data, optional + 108)[0]
    if directories > 16:
        raise ValueError("Unsupported PE data-directory count")
    if directories and optional_size < 112 + min(directories, 16) * 8:
        raise ValueError("Truncated PE data directories")
    if directories > 1:
        rva, size = unpack("<II", data, optional + 120)
        if bool(rva) != bool(size):
            raise ValueError("Incomplete PE import directory")
        if rva:
            base = file_offset(rva)
            terminated = False
            for i in range(min(size // 20, 4096)):
                fields = unpack("<IIIII", data, base + i * 20)
                if not any(fields):
                    terminated = True
                    break
                name = file_offset(fields[3])
                imports.append(string(data, name, len(data)))
            if not terminated:
                raise ValueError("Unterminated PE import directory")
    cert = False
    if directories > 4:
        position, size = unpack("<II", data, optional + 144)
        if bool(position) != bool(size) or (size and position + size > len(data)):
            raise ValueError("Invalid PE certificate-table bounds")
        cert = bool(size)
    return {"format": "PE64", "architecture": "x86_64", "dependencies": imports,
            "signature_blob_present": cert, "no_writable_executable_section": True}


def macho64(data):
    endian = "<" if data[:4] == b"\xcf\xfa\xed\xfe" else ">"
    cpu, subtype, kind, count, total, flags, reserved = unpack(endian + "IIIIIII", data, 4)
    architecture = {0x01000007: "x86_64", 0x0100000C: "arm64"}.get(cpu)
    if architecture is None or kind not in {2, 6, 8} or count > 4096 or 32 + total > len(data):
        raise ValueError("Unsupported or truncated Mach-O64")
    if (architecture == "x86_64" and subtype & 0xFFFFFF != 3) or (architecture == "arm64" and subtype & 0xFFFFFF != 0):
        raise ValueError("Specialized Mach-O subtype requires a separate profile")
    position = 32
    dependencies, rpaths, signed, minimum = [], [], False, None
    for _ in range(count):
        cmd, size = unpack(endian + "II", data, position)
        if size < 8 or size % 8 or position + size > 32 + total:
            raise ValueError("Invalid Mach-O load command")
        base = cmd & 0x7FFFFFFF
        if base == 1:
            raise ValueError("32-bit segment command in Mach-O64")
        if base == 0x19:
            if size < 72:
                raise ValueError("Truncated Mach-O segment")
            fileoff, filesize = unpack(endian + "QQ", data, position + 40)
            protection = unpack(endian + "I", data, position + 60)[0]
            if protection & 2 and protection & 4:
                raise ValueError("Writable executable Mach-O segment")
            if fileoff + filesize > len(data):
                raise ValueError("Mach-O segment outside file")
        elif base in {0xC, 0x18, 0x1F, 0x23}:
            if size < 24:
                raise ValueError("Truncated dylib command")
            name = unpack(endian + "I", data, position + 8)[0]
            if name < 24:
                raise ValueError("Invalid dylib name offset")
            dependencies.append(string(data, position + name, position + size))
        elif base == 0x1C:
            if size < 16:
                raise ValueError("Truncated rpath command")
            name = unpack(endian + "I", data, position + 8)[0]
            if name < 12:
                raise ValueError("Invalid rpath offset")
            rpaths.append(string(data, position + name, position + size))
        elif base == 0x1D:
            if size != 16:
                raise ValueError("Invalid signature command")
            offset, length = unpack(endian + "II", data, position + 8)
            if length < 8 or offset < 32 + total or offset + length > len(data):
                raise ValueError("Invalid signature blob bounds")
            signed = True
        elif base == 0x32:
            if size < 24:
                raise ValueError("Truncated build-version command")
            build_platform, version = unpack(endian + "II", data, position + 8)
            if build_platform != 1:
                raise ValueError("Mach-O is for a non-macOS Apple platform")
            if minimum is not None:
                raise ValueError("Multiple minimum-OS commands require separate admission")
            minimum = [version >> 16, (version >> 8) & 255, version & 255]
        elif base == 0x24:
            if size != 16:
                raise ValueError("Invalid minimum-macOS command")
            version = unpack(endian + "I", data, position + 8)[0]
            if minimum is not None:
                raise ValueError("Multiple minimum-OS commands require separate admission")
            minimum = [version >> 16, (version >> 8) & 255, version & 255]
        elif base in {0x25, 0x2F, 0x30}:
            raise ValueError("Mach-O is for a non-macOS Apple platform")
        position += size
    if position != 32 + total:
        raise ValueError("Mach-O command count/size mismatch")
    return {"format": "Mach-O64", "architecture": architecture, "dependencies": dependencies,
            "rpaths": rpaths, "signature_blob_present": signed,
            "minimum_macos": minimum,
            "no_writable_executable_segment": True}


def inspect_native(data, target):
    if target not in TARGETS:
        raise ValueError("Unknown target")
    if any(marker in data for marker in PACKERS):
        raise ValueError("Known executable packer marker")
    if data.startswith(b"MZ"):
        info = pe64(data)
    elif data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        info = macho64(data)
    else:
        raise ValueError("Expected supported PE64 or thin Mach-O64; fat/unknown needs separate admission")
    expected = "arm64" if target.endswith("arm64") else "x86_64"
    if info["architecture"] != expected or (target.startswith("windows") != (info["format"] == "PE64")):
        raise ValueError("Native target mismatch")
    return {**info, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "known_packer_markers_absent": True, "signature_verified": False,
            "status": "STRUCTURAL_CHECKS_ONLY_RELEASE_NEED", "release_ready": False,
            "limitation": "Not a code-signature, provenance, no-packing, purity or numerical-correctness proof"}


def probe(target):
    system, architectures = TARGETS[target]
    actual = {"system": platform.system(), "machine": platform.machine(), "version": platform.version()}
    match = actual["system"] == system and actual["machine"].lower() in architectures
    names = ["codesign", "security", "xcrun", "spctl", "fs_usage", "dtrace"] if system == "Darwin" else ["powershell", "signtool", "wpr", "wevtutil", "certutil"]
    tools = {name: shutil.which(name) is not None for name in names}
    return {"schema": 1, "utc": dt.datetime.now(dt.timezone.utc).isoformat(), "target": target,
            "runner": actual, "target_matches_runner": match,
            "image": {key: os.environ.get(key) for key in ["ImageOS", "ImageVersion"]},
            "tool_available": tools, "credentials_read": False,
            "status": "BOOTSTRAP_CAPTURED_RELEASE_NEED" if match else "INCOMPLETE_WRONG_NATIVE_RUNNER",
            "release_ready": False, "native_payload": "MISSING", "OS_signature": "MISSING",
            "notarization": "MISSING" if system == "Darwin" else "NOT_APPLICABLE",
            "numerical_comparison": "MISSING", "purity": "INCOMPLETE_NATIVE_COLLECTOR_MISSING",
            "network_process_write_claim": "NONE", "raw_trace_uploaded": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inspect", type=Path)
    parser.add_argument("--pure", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.pure:
        result = {"schema": 1, "status": "INCOMPLETE_NATIVE_COLLECTOR_MISSING",
                  "target": args.target, "target_executed": False, "release_ready": False,
                  "reason": "No validated complete native collector; absence of events cannot yield PASS",
                  "command_contents_recorded": False}
        code = 3
    elif args.inspect:
        if args.inspect.stat().st_size > 512 * 1024**2:
            raise ValueError("Native input exceeds store file cap")
        result = inspect_native(args.inspect.read_bytes(), args.target)
        code = 0
    else:
        result = probe(args.target)
        code = 0 if result["target_matches_runner"] else 3
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ["status", "release_ready"] if key in result}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
