#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit signing protocol control. Never publishes or reads local owner files."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import struct
import subprocess
import tempfile
import zipfile

from desktop_bootstrap import TARGETS, inspect_native, unpack

SOURCE = r'''/* SPDX-License-Identifier: MIT */
#ifdef _WIN32
__declspec(dllexport)
#endif
int takt_signing_smoke_identity(void) { return 71; }
#ifndef TAKT_SMOKE_DLL
int main(void) { return takt_signing_smoke_identity() == 71 ? 0 : 1; }
#endif
'''
CMAKE = '''cmake_minimum_required(VERSION 3.20)
project(takt_desktop_signing_control C)
add_executable(desktop-signing-smoke signing_smoke.c)
add_library(desktop-signing-smoke-lib SHARED signing_smoke.c)
target_compile_definitions(desktop-signing-smoke-lib PRIVATE TAKT_SMOKE_DLL=1)
foreach(target desktop-signing-smoke desktop-signing-smoke-lib)
 set_target_properties(${target} PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${SUBJECTS}"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${SUBJECTS}"
  LIBRARY_OUTPUT_DIRECTORY "${SUBJECTS}"
  LIBRARY_OUTPUT_DIRECTORY_RELEASE "${SUBJECTS}")
endforeach()
'''
PRIVATE_ENV = {"APPLE_SIGNING_P12_B64", "APPLE_SIGNING_P12_PASSWORD", "APPLE_ASC_KEY_P8_B64"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(args, *, timeout=120, check=True, env=None):
    clean = {k: v for k, v in (os.environ if env is None else env).items() if k not in PRIVATE_ENV}
    result = subprocess.run([str(x) for x in args], env=clean, capture_output=True, timeout=timeout)
    if check and result.returncode:
        # Never include argv, secret values, subprocess output or client paths.
        error = RuntimeError("NATIVE_TOOL_FAILED_" + Path(args[0]).name)
        error.native_returncode = result.returncode
        raise error
    return result


def required(env, names):
    if any(not env.get(name) for name in names):
        raise ValueError("NEED_COORDINATOR_CONFIGURATION")
    return {name: env[name] for name in names}


def require_protocol(env):
    if env.get("ENABLE_SIGNING") != "true" or env.get("ENABLE_PUBLISHING", "false") != "false":
        raise ValueError("SIGNING_CONTROL_REQUIRES_SIGN_TRUE_PUBLISH_FALSE")


def require_host(target):
    system, machines = TARGETS[target]
    if platform.system() != system or platform.machine().lower() not in machines:
        raise ValueError("NEED_MATCHING_NATIVE_RUNNER")


def apple_anchor(env):
    values = required(env, ["APPLE_TEAM_ID", "APPLE_SIGNING_CERT_SHA1", "APPLE_SIGNING_CERT_SHA256"])
    team, sha1, sha256 = (values[k] for k in ["APPLE_TEAM_ID", "APPLE_SIGNING_CERT_SHA1", "APPLE_SIGNING_CERT_SHA256"])
    if not re.fullmatch(r"[A-Z0-9]{10}", team) or not re.fullmatch(r"[0-9A-Fa-f]{40}", sha1) or not re.fullmatch(r"[0-9A-Fa-f]{64}", sha256):
        raise ValueError("INVALID_PUBLIC_APPLE_TRUST_ANCHOR")
    return team, sha1, sha256


def windows_configuration(env):
    names = ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID", "AZURE_SIGNING_ENDPOINT",
             "AZURE_SIGNING_ACCOUNT", "AZURE_SIGNING_CERTIFICATE_PROFILE", "WINDOWS_PUBLISHER_NAME"]
    values = required(env, names)
    for name in names[:3]:
        if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", values[name]):
            raise ValueError("INVALID_AZURE_PUBLIC_IDENTIFIER")
    if not re.fullmatch(r"https://[a-z0-9-]+\.codesigning\.azure\.net/?", values["AZURE_SIGNING_ENDPOINT"]):
        raise ValueError("INVALID_PUBLIC_TRUST_ENDPOINT")
    for name in ["AZURE_SIGNING_ACCOUNT", "AZURE_SIGNING_CERTIFICATE_PROFILE"]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", values[name]):
            raise ValueError("INVALID_AZURE_SIGNING_PROFILE_NAME")
    if len(values["WINDOWS_PUBLISHER_NAME"]) > 256 or any(x in values["WINDOWS_PUBLISHER_NAME"] for x in "\r\n"):
        raise ValueError("INVALID_WINDOWS_PUBLISHER_NAME")
    return {"configured": True, "authentication": "GITHUB_OIDC_AZURE_CLI", "identity_validation": "EXTERNAL_COORDINATOR_REQUIRED"}


def code_data_fingerprint(data, target):
    """Additional mutation check; not a mathematical-equivalence proof."""
    info = inspect_native(data, target)
    rows = []
    if info["format"] == "PE64":
        start = unpack("<I", data, 0x3C)[0]
        count = unpack("<H", data, start + 6)[0]
        optional = start + 24
        table = optional + unpack("<H", data, start + 20)[0]
        rows.append({"entry_RVA": unpack("<I", data, optional + 16)[0],
                     "image_base": unpack("<Q", data, optional + 24)[0]})
        for i in range(count):
            pos = table + 40 * i
            virtual, rva, size, offset = unpack("<IIII", data, pos + 8)
            rows.append({"section": data[pos:pos + 8].hex(), "virtual_size": virtual,
                         "rva": rva, "flags": unpack("<I", data, pos + 36)[0],
                         "bytes": size, "sha256": digest(data[offset:offset + size])})
    else:
        endian = "<" if data[:4] == b"\xcf\xfa\xed\xfe" else ">"
        count = unpack(endian + "I", data, 16)[0]
        pos = 32
        for _ in range(count):
            cmd, size = unpack(endian + "II", data, pos)
            if cmd == 0x19:
                sections = unpack(endian + "I", data, pos + 64)[0]
                if sections > 4096 or 72 + sections * 80 > size:
                    raise ValueError("INVALID_MACHO_SECTION_ARRAY")
                for i in range(sections):
                    section = pos + 72 + i * 80
                    address, length = unpack(endian + "QQ", data, section + 32)
                    offset = unpack(endian + "I", data, section + 48)[0]
                    flags = unpack(endian + "I", data, section + 64)[0]
                    zerofill = flags & 0xFF in {1, 0xC, 0x12}
                    if not zerofill and offset + length > len(data):
                        raise ValueError("MACHO_SECTION_OUTSIDE_FILE")
                    rows.append({"names": data[section:section + 32].hex(), "address": address,
                                 "bytes": length, "flags": flags,
                                 "sha256": None if zerofill else digest(data[offset:offset + length])})
            pos += size
        if not rows:
            raise ValueError("NO_MACHO_CODE_DATA_SECTIONS")
    return digest(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())


def prepare_smoke(target, output):
    require_host(target)
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    source.mkdir()
    (source / "signing_smoke.c").write_text(SOURCE)
    (source / "CMakeLists.txt").write_text(CMAKE)
    subjects = output / "subjects"
    subjects.mkdir()
    build = output / "build"
    args = ["cmake", "-S", source, "-B", build, "-DCMAKE_BUILD_TYPE=Release", "-DSUBJECTS=" + str(subjects.resolve())]
    if target == "windows_x86_64":
        args += ["-A", "x64"]
        names = ["desktop-signing-smoke.exe", "desktop-signing-smoke-lib.dll"]
    else:
        minimum = "14.0" if target == "macos_arm64" else "13.0"
        args += ["-DCMAKE_OSX_DEPLOYMENT_TARGET=" + minimum]
        names = ["desktop-signing-smoke", "libdesktop-signing-smoke-lib.dylib"]
    command(args, timeout=300)
    command(["cmake", "--build", build, "--config", "Release", "--parallel", "2"], timeout=300)
    actual = sorted(p.name for p in subjects.iterdir())
    if actual != sorted(names) or any(p.is_symlink() or not p.is_file() for p in subjects.iterdir()):
        raise ValueError("UNEXPECTED_SIGNING_CONTROL_SUBJECT")
    pins = {}
    for name in names:
        data = (subjects / name).read_bytes()
        pins[name] = {"sha256_before": digest(data), "code_data_sha256": code_data_fingerprint(data, target)}
    result = {"schema": 1, "scope": "TINY_PUBLIC_SIGNING_PROTOCOL_CONTROL_NOT_SKU", "target": target,
              "source_sha256": digest(SOURCE.encode()), "CMake_sha256": digest(CMAKE.encode()),
              "subjects": pins, "payload_executed": False, "release_ready": False}
    (output / "SUBJECTS.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def verify_macos(path, target, env):
    require_host(target)
    team, sha1, sha256 = apple_anchor(env)
    requirement = 'anchor apple generic and certificate leaf = H"' + sha1.lower() + '" and certificate leaf[subject.OU] = "' + team + '"'
    command(["codesign", "--verify", "--strict", "--verbose=2", "-R", requirement, path])
    details = command(["codesign", "--display", "--verbose=4", path]).stderr.decode(errors="replace")
    if not re.search(r"(?m)^TeamIdentifier=" + re.escape(team) + r"$", details) or "Signature=adhoc" in details:
        raise ValueError("APPLE_TEAM_OR_ADHOC_REFUSED")
    with tempfile.TemporaryDirectory(prefix="desktop-public-certificate-") as folder:
        prefix = Path(folder) / "cert-"
        command(["codesign", "--display", "--extract-certificates=" + str(prefix), path])
        cert = Path(str(prefix) + "0").read_bytes()
    if digest(cert) != sha256.lower() or hashlib.sha1(cert).hexdigest() != sha1.lower():
        raise ValueError("APPLE_CERTIFICATE_FINGERPRINT_MISMATCH")
    return {"verified": True, "team_id": team, "certificate_sha1": sha1.lower(), "certificate_sha256": digest(cert)}


def signtool():
    if shutil.which("signtool"):
        return shutil.which("signtool")
    root = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Windows Kits/10/bin"
    tools = sorted(root.glob("*/x64/signtool.exe"))
    if not tools:
        raise ValueError("NEED_WINDOWS_SIGNTOOL")
    return str(tools[-1])


def verify_windows(path, env):
    require_host("windows_x86_64")
    expected = required(env, ["WINDOWS_PUBLISHER_NAME"])["WINDOWS_PUBLISHER_NAME"]
    command([signtool(), "verify", "/pa", "/all", "/v", path])
    script = '''$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$s=Get-AuthenticodeSignature -LiteralPath $env:TAKT_VERIFY_FILE
if($s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate -or $null -eq $s.TimeStamperCertificate){throw 'INVALID_AUTHENTICODE_OR_TIMESTAMP'}
$cert=$s.SignerCertificate
$name=$cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
if($name -cne $env:WINDOWS_PUBLISHER_NAME){throw 'PUBLISHER_MISMATCH'}
$hash=[System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)
@{verified=$true;publisher=$name;certificate_sha1=$cert.Thumbprint.ToLowerInvariant();certificate_sha256=([BitConverter]::ToString($hash)).Replace('-','').ToLowerInvariant();timestamp_present=$true}|ConvertTo-Json -Compress
'''
    child = dict(env, TAKT_VERIFY_FILE=str(path.resolve()), WINDOWS_PUBLISHER_NAME=expected)
    data = json.loads(command(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], env=child).stdout)
    if (data.get("verified") is not True or data.get("timestamp_present") is not True
            or data.get("publisher") != expected
            or not re.fullmatch(r"[0-9a-f]{40}", data.get("certificate_sha1", ""))
            or not re.fullmatch(r"[0-9a-f]{64}", data.get("certificate_sha256", ""))):
        raise ValueError("INVALID_AUTHENTICODE_RECEIPT")
    return data


def verify_native(path, target, env=None):
    return verify_windows(path, os.environ if env is None else env) if target == "windows_x86_64" else verify_macos(path, target, os.environ if env is None else env)


def subject_receipts(output, target, env):
    pins = json.loads((output / "SUBJECTS.json").read_text())
    if pins["target"] != target or pins["scope"] != "TINY_PUBLIC_SIGNING_PROTOCOL_CONTROL_NOT_SKU":
        raise ValueError("CONTROL_SUBJECT_SCOPE_MISMATCH")
    folder = output / "subjects"
    if set(p.name for p in folder.iterdir()) != set(pins["subjects"]):
        raise ValueError("CONTROL_SUBJECT_SET_CHANGED")
    records = {}
    for name, before in pins["subjects"].items():
        path = folder / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("SIGNING_SUBJECT_MUST_BE_REGULAR")
        data = path.read_bytes()
        if code_data_fingerprint(data, target) != before["code_data_sha256"]:
            raise ValueError("CODE_DATA_CHANGED_BY_SIGNING")
        records[name] = {**before, "sha256_after": digest(data), "code_data_sections_equal": True,
                         "OS_signature": verify_native(path, target, env)}
    return records


def decode_secret(value, path):
    data = base64.b64decode("".join(value.split()), validate=True)
    if not data or len(data) > 1024**2:
        raise ValueError("INVALID_PROTECTED_SECRET_SIZE")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def license_bytes():
    return (Path(__file__).resolve().parent / "resources-desktop-v1/verify/LICENSE-MIT").read_bytes()


def macos_smoke(target, output, env):
    require_protocol(env)
    require_host(target)
    values = required(env, ["APPLE_SIGNING_P12_B64", "APPLE_SIGNING_P12_PASSWORD", "APPLE_ASC_KEY_P8_B64",
                            "APPLE_ASC_KEY_ID", "APPLE_ASC_ISSUER_ID", "APPLE_TEAM_ID",
                            "APPLE_SIGNING_CERT_SHA1", "APPLE_SIGNING_CERT_SHA256"])
    apple_anchor(env)
    if not re.fullmatch(r"[A-Z0-9]{10}", values["APPLE_ASC_KEY_ID"]) or not re.fullmatch(r"[0-9a-fA-F-]{36}", values["APPLE_ASC_ISSUER_ID"]):
        raise ValueError("INVALID_APPLE_NOTARY_IDENTIFIERS")
    prepare_smoke(target, output)
    with tempfile.TemporaryDirectory(prefix="takt-desktop-signing-", dir=env.get("RUNNER_TEMP")) as private:
        private = Path(private)
        p12, p8, keychain = private / "identity.p12", private / "AuthKey.p8", private / "ephemeral.keychain-db"
        password = secrets.token_urlsafe(32)
        created = False
        original_keychains = None
        try:
            original_keychains = shlex.split(command(["security", "list-keychains", "-d", "user"]).stdout.decode())
            decode_secret(values["APPLE_SIGNING_P12_B64"], p12)
            decode_secret(values["APPLE_ASC_KEY_P8_B64"], p8)
            command(["security", "create-keychain", "-p", password, keychain]); created = True
            command(["security", "set-keychain-settings", "-lut", "3600", keychain])
            command(["security", "unlock-keychain", "-p", password, keychain])
            command(["security", "import", p12, "-k", keychain, "-P", values["APPLE_SIGNING_P12_PASSWORD"], "-T", "/usr/bin/codesign"])
            command(["security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", password, keychain])
            for path in sorted((output / "subjects").iterdir()):
                command(["codesign", "--force", "--options", "runtime", "--timestamp", "--keychain", keychain,
                         "--sign", values["APPLE_SIGNING_CERT_SHA1"], path], timeout=300)
            signed = subject_receipts(output, target, env)
            (output / "SIGNED_SUBJECTS.json").write_text(json.dumps(signed, indent=2) + "\n")
            archive = output / "notary-subjects.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as target_zip:
                for path in sorted((output / "subjects").iterdir()):
                    target_zip.write(path, path.name)
                target_zip.writestr("LICENSE-MIT.txt", license_bytes())
            notary = json.loads(command(["xcrun", "notarytool", "submit", archive, "--key", p8,
                                        "--key-id", values["APPLE_ASC_KEY_ID"], "--issuer", values["APPLE_ASC_ISSUER_ID"],
                                        "--wait", "--output-format", "json"], timeout=3600).stdout)
            safe_notary = {"status": notary.get("status") if notary.get("status") in {"Accepted", "Invalid", "In Progress"} else "UNKNOWN",
                           "id": notary.get("id") if re.fullmatch(r"[0-9a-fA-F-]{36}", str(notary.get("id", ""))) else None,
                           "archive_sha256": digest(archive.read_bytes())}
            (output / "NOTARY_RECEIPT.json").write_text(json.dumps(safe_notary, indent=2) + "\n")
            if safe_notary["status"] != "Accepted" or not safe_notary["id"]:
                raise ValueError("NEED_NOTARY_ACCEPTED_RECEIPT")
            executable = output / "subjects/desktop-signing-smoke"
            library = output / "subjects/libdesktop-signing-smoke-lib.dylib"
            assess = command(["spctl", "--assess", "--type", "execute", "--verbose=4", executable], check=False)
            library_assess = command(["spctl", "--assess", "--type", "execute", "--verbose=4", library], check=False)
            return {"status": "BOOTSTRAP_SIGNING_PASS" if assess.returncode == 0 else "NEED_GATEKEEPER_EXECUTABLE_ASSESSMENT",
                    "target": target, "subjects": signed, "notary": {"id": notary["id"], "status": "Accepted", "archive_sha256": digest(archive.read_bytes())},
                    "spctl_executable_rc": assess.returncode, "spctl_library_rc": library_assess.returncode,
                    "library_assessment_scope": "Not an application; recorded separately, not a wheel install PASS",
                    "stapler": "NOT_APPLICABLE_BARE_EXECUTABLE_DYLIB_ZIP", "wheel_boundary": "ZIP subjects accepted; no claim that a wheel was stapled or native installation validated"}
        finally:
            try:
                if created or keychain.exists():
                    command(["security", "delete-keychain", keychain])
            finally:
                if original_keychains is not None:
                    command(["security", "list-keychains", "-d", "user", "-s", *original_keychains])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["protocol-check", "preflight-windows", "prepare-smoke", "macos-smoke", "verify-windows-smoke"])
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"schema": 1, "utc": dt.datetime.now(dt.timezone.utc).isoformat(), "scope": "TINY_PUBLIC_SIGNING_PROTOCOL_CONTROL_NOT_SKU",
              "release_ready": False, "numerical_SKU_evidence": "MISSING", "native_SKU_purity": "MISSING", "payload_executed": False,
              "runner": {"system": platform.system(), "machine": platform.machine(), "version": platform.version(),
                         "ImageOS": os.environ.get("ImageOS"), "ImageVersion": os.environ.get("ImageVersion")}}
    try:
        if args.mode == "protocol-check":
            require_protocol(os.environ)
            result.update(status="SIGNING_CONTROL_CONFIGURATION_VALID")
        elif args.mode == "preflight-windows":
            require_protocol(os.environ)
            require_host("windows_x86_64")
            if args.target != "windows_x86_64":
                raise ValueError("EXPECTED_WINDOWS_TARGET")
            result.update(status="WINDOWS_OIDC_CONFIGURATION_PRESENT", configuration=windows_configuration(os.environ))
        elif args.mode == "prepare-smoke":
            require_protocol(os.environ)
            result.update(prepare_smoke(args.target, args.output), status="UNSIGNED_CONTROL_PREPARED")
        elif args.mode == "macos-smoke":
            if not args.target.startswith("macos_"):
                raise ValueError("EXPECTED_MACOS_TARGET")
            result.update(macos_smoke(args.target, args.output, os.environ))
        else:
            require_protocol(os.environ)
            if args.target != "windows_x86_64":
                raise ValueError("EXPECTED_WINDOWS_TARGET")
            result.update(status="BOOTSTRAP_SIGNING_PASS", target=args.target,
                          subjects=subject_receipts(args.output, args.target, os.environ))
        code = 0 if not result["status"].startswith("NEED_") else 3
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        safe_code = str(error) if re.fullmatch(r"[A-Za-z0-9_]{1,120}", str(error)) else "SANITIZED_NATIVE_FAILURE"
        result.update(status="NEED_SIGNING_CONTROL", failure_type=type(error).__name__, failure_code=safe_code)
        result["native_returncode"] = getattr(error, "native_returncode", None)
        code = 3
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "release_ready": False}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
