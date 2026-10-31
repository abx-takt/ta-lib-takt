#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate signed contractual metadata, never a binary runtime licence check.

One immutable shared artifact per SKU/version; only certificates vary by order.
No buyer names, contact fields, device binding, telemetry, expiry or remote switch.
"""

import argparse
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import uuid

SCHEMA = "urn:takt:entitlement:v1"
SHARED_SCHEMA = "urn:takt:shared-store-artifact:v1"
VENDOR_KEY_ID = "sha256:d2c5c31e6f032b82d744a19d1f7ddb54b407b9883dbccdc4521c7011f0b682fc"
VENDOR_PEM_SHA256 = "3bd6f39b7650597a654eb78cadcd4c4f214cf7e2af1c4d05e384b0ef6ba53c3d"


def vendor_anchor(public_key):
    data = public_key.read_bytes()
    if hashlib.sha256(data).hexdigest() != VENDOR_PEM_SHA256:
        raise ValueError("Public key differs from the independently pinned vendor entitlement anchor")
    lines = data.decode("ascii").splitlines()
    if lines[0] != "-----BEGIN PUBLIC KEY-----" or lines[-1] != "-----END PUBLIC KEY-----":
        raise ValueError("Expected public SPKI PEM")
    der = base64.b64decode("".join(lines[1:-1]), validate=True)
    if len(der) != 44 or not der.startswith(bytes.fromhex("302a300506032b6570032100")):
        raise ValueError("Expected Ed25519 SPKI")
    if "sha256:" + hashlib.sha256(der).hexdigest() != VENDOR_KEY_ID:
        raise ValueError("Vendor SPKI fingerprint mismatch")
    return {"key_id": VENDOR_KEY_ID, "public_key_sha256": VENDOR_PEM_SHA256,
            "purpose": "offline entitlement certificates; not keyless artifact signing",
            "network_requests": 0}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON property")
        result[key] = value
    return result


def read_json(path):
    if path.stat().st_size > 65536:
        raise ValueError("Metadata file exceeds schema size")
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def identifier(value):
    order = uuid.UUID(value)
    if order.int == 0 or str(order) != value:
        raise ValueError("Canonical nonzero opaque order UUID required")
    return value


def sku_version(sku, version):
    if not isinstance(sku, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,79}", sku):
        raise ValueError("Invalid SKU code")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9][A-Za-z0-9.]{0,79}", version):
        raise ValueError("Invalid version code")


def validate(document):
    expected = {"schema", "issuer", "issuer_profile", "order_ref", "sku", "version", "artifact_sha256", "seats", "term", "terms_revision"}
    if not isinstance(document, dict) or set(document) != expected:
        raise ValueError("Schema requires exact fields; buyer data/keys/URLs/unknown properties are forbidden")
    if document["schema"] != SCHEMA or document["issuer"] != "TAKT":
        raise ValueError("Unsupported entitlement schema/issuer label")
    if document["issuer_profile"] not in {"TEST_ONLY_LOCAL_KEY", "SELF_MANAGED_VENDOR_KEY"}:
        raise ValueError("Unknown issuer profile")
    identifier(document["order_ref"])
    sku_version(document["sku"], document["version"])
    if not re.fullmatch(r"[0-9a-f]{64}", document["artifact_sha256"]):
        raise ValueError("Invalid artifact SHA256")
    if type(document["seats"]) is not int or not 1 <= document["seats"] <= 2147483647:
        raise ValueError("Seats must be a positive contractual integer")
    if not isinstance(document["terms_revision"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", document["terms_revision"]):
        raise ValueError("A non-personal Terms revision code is required")
    term = document["term"]
    if not isinstance(term, dict):
        raise ValueError("Term must contain explicit contractual metadata")
    if term.get("binary_use") == "perpetual":
        expected_term = {"binary_use", "support_updates_through"}
    elif term.get("binary_use") == "fixed_interval":
        expected_term = {"binary_use", "support_updates_through", "starts_on", "ends_on"}
        for field in ("starts_on", "ends_on"):
            value = term.get(field)
            if not isinstance(value, str) or dt.date.fromisoformat(value).isoformat() != value:
                raise ValueError("Fixed contractual interval requires ISO dates")
        if term["starts_on"] > term["ends_on"]:
            raise ValueError("Contractual interval is reversed")
    else:
        raise ValueError("Unknown contractual term kind")
    if set(term) != expected_term:
        raise ValueError("Unexpected contractual term fields; no runtime expiry fields")
    if term["support_updates_through"] is not None:
        value = term["support_updates_through"]
        if not isinstance(value, str) or dt.date.fromisoformat(value).isoformat() != value:
            raise ValueError("Invalid support/updates date")
    return document


def signed(cosign, path, key, public_key, config, trusted_root):
    bundle = path.with_name(path.name + ".sigstore.json")
    if bundle.exists():
        raise FileExistsError(bundle)
    subprocess.run(["unshare", "-rn", "--", str(cosign), "sign-blob", "--yes", "--key", str(key),
                    "--signing-config", str(config), "--trusted-root", str(trusted_root),
                    "--oidc-disable-ambient-providers", "--bundle", str(bundle), str(path)], check=True)
    verify_signature(cosign, path, bundle, public_key, trusted_root)
    return bundle


def verify_signature(cosign, path, bundle, trusted_public_key, trusted_root):
    # The trusted key is an explicit external input, never taken from a certificate.
    subprocess.run(["unshare", "-rn", "--", str(cosign), "verify-blob", str(path),
                    "--key", str(trusted_public_key), "--bundle", str(bundle),
                    "--trusted-root", str(trusted_root), "--insecure-ignore-tlog"], check=True)


def private_directory(path):
    if set(path.parts) & {"dist", "public", "pypi", "store-release", "store_final", "store_final_v4", "store_final_v5", "store_final_v6", "store_final_v6_draft_clone1", "ci_payloads", "ci_payloads_v4", "ci_payloads_v5", "ci_payloads_v6"}:
        raise ValueError("Customer-specific metadata is forbidden in public/release/PyPI staging")
    if path.exists() and (not path.is_dir() or path.stat().st_mode & 0o077):
        raise ValueError("Existing private staging directory must already have mode 0700")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)


def prepare_shared(args):
    if not args.test_only:
        vendor_anchor(args.public_key)
    sku_version(args.sku, args.version)
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+\.(?:so(?:\.[0-9]+)*|whl)", args.artifact.name):
        raise ValueError("A generic library/wheel filename is required")
    root = args.private_root.resolve()
    private_directory(root)
    output = root / "shared" / args.sku / args.version
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    artifact = output / args.artifact.name
    shutil.copyfile(args.artifact, artifact)
    final_hash = digest(artifact)
    if final_hash != digest(args.artifact):
        raise ValueError("Shared artifact copy changed bytes")
    document = {"schema": SHARED_SCHEMA, "sku": args.sku, "version": args.version,
                "artifact_name": artifact.name, "artifact_sha256": final_hash, "artifact_bytes": artifact.stat().st_size,
                "issuer_profile": "TEST_ONLY_LOCAL_KEY" if args.test_only else "SELF_MANAGED_VENDOR_KEY",
                "public_key_trust": "must be pinned independently; no embedded-key trust",
                "binary_changes": 0, "licence_file_consumed_by_binary": False}
    manifest = output / "SHARED_ARTIFACT.json"
    manifest.write_bytes(canonical(document))
    signed(args.cosign, artifact, args.key, args.public_key, args.signing_config, args.trusted_root)
    signed(args.cosign, manifest, args.key, args.public_key, args.signing_config, args.trusted_root)
    (output / "VIRUSTOTAL.json").write_text(json.dumps({"sha256": final_hash,
        "url": "https://www.virustotal.com/gui/file/" + final_hash, "uploads": 0,
        "status": "HASH_LINK_ONLY_NOT_SCANNER_REPORT", "scope": "one shared artifact per SKU/version; no order-specific subjects"}, indent=2) + "\n")
    return {"shared_manifest": str(manifest), "artifact_sha256": final_hash, "binary_changes": 0,
            "issuer_profile": document["issuer_profile"]}


def issue(args):
    shared = read_json(args.shared_manifest)
    if shared.get("issuer_profile") == "SELF_MANAGED_VENDOR_KEY":
        vendor_anchor(args.public_key)
    verify_signature(args.cosign, args.shared_manifest, args.shared_manifest.with_name(args.shared_manifest.name + ".sigstore.json"), args.public_key, args.trusted_root)
    if shared.get("schema") != SHARED_SCHEMA:
        raise ValueError("Expected authenticated shared-artifact manifest")
    order = identifier(args.order_ref)
    root = args.private_root.resolve()
    private_directory(root)
    output = root / "entitlements" / order
    term = {"binary_use": args.binary_use, "support_updates_through": args.support_updates_through}
    if args.binary_use == "fixed_interval":
        if not args.accepted_fixed_term_order or not args.starts_on or not args.ends_on:
            raise ValueError("Explicit accepted fixed-term order and both interval dates are required")
        term.update(starts_on=args.starts_on, ends_on=args.ends_on)
    elif args.starts_on or args.ends_on or args.accepted_fixed_term_order:
        raise ValueError("Perpetual certificates must not contain fixed-interval options")
    document = {"schema": SCHEMA, "issuer": "TAKT", "issuer_profile": shared["issuer_profile"],
                "order_ref": order, "sku": shared["sku"], "version": shared["version"],
                "artifact_sha256": shared["artifact_sha256"], "seats": args.seats,
                "term": term,
                "terms_revision": args.terms_revision}
    validate(document)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    certificate = output / "ENTITLEMENT.json"
    certificate.write_bytes(canonical(document))
    signature = signed(args.cosign, certificate, args.key, args.public_key, args.signing_config, args.trusted_root)
    result = {"order_ref": order, "certificate": str(certificate), "signature": str(signature),
              "shared_artifact_sha256": shared["artifact_sha256"], "shared_binary_writes": 0,
              "scope": "contractual metadata only; binary never consumes this certificate"}
    (output / "DELIVERY_RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def verify(args):
    document = validate(read_json(args.certificate))
    if document["issuer_profile"] == "SELF_MANAGED_VENDOR_KEY":
        vendor_anchor(args.trusted_public_key)
    verify_signature(args.cosign, args.certificate, args.bundle, args.trusted_public_key, args.trusted_root)
    if document["artifact_sha256"] != digest(args.artifact):
        raise ValueError("Certificate is for different artifact bytes")
    if document["sku"] != args.sku or document["version"] != args.version:
        raise ValueError("Certificate SKU/version differs from the explicitly expected product")
    if args.require_production and document["issuer_profile"] != "SELF_MANAGED_VENDOR_KEY":
        raise ValueError("A local test key is not a production issuer")
    return {"status": "SIGNATURE_SCHEMA_AND_ARTIFACT_BINDING_VERIFIED", "issuer_profile": document["issuer_profile"],
            "order_ref": document["order_ref"], "sku": document["sku"], "version": document["version"],
            "artifact_sha256": document["artifact_sha256"], "seats_contractual": document["seats"],
            "term_contractual": document["term"], "runtime_authorization_or_expiry": False,
            "trust_source": "pinned vendor anchor for production; explicit test key otherwise; never certificate-embedded",
            "vendor_key_id": VENDOR_KEY_ID if document["issuer_profile"] == "SELF_MANAGED_VENDOR_KEY" else None}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    anchor = sub.add_parser("verify-anchor", help="Verify the independent public vendor key pin; no signing/network")
    anchor.add_argument("--public-key", type=Path, required=True)
    for action in ("prepare-shared", "issue"):
        a = sub.add_parser(action)
        a.add_argument("--private-root", type=Path, required=True)
        a.add_argument("--cosign", type=Path, required=True)
        a.add_argument("--key", type=Path, required=True)
        a.add_argument("--public-key", type=Path, required=True)
        a.add_argument("--signing-config", type=Path, required=True)
        a.add_argument("--trusted-root", type=Path, required=True)
        if action == "prepare-shared":
            a.add_argument("--artifact", type=Path, required=True)
            a.add_argument("--sku", required=True)
            a.add_argument("--version", required=True)
            a.add_argument("--test-only", action="store_true")
        else:
            a.add_argument("--shared-manifest", type=Path, required=True)
            a.add_argument("--order-ref", required=True)
            a.add_argument("--seats", type=int, required=True)
            a.add_argument("--support-updates-through")
            a.add_argument("--binary-use", choices=("perpetual", "fixed_interval"), default="perpetual")
            a.add_argument("--starts-on")
            a.add_argument("--ends-on")
            a.add_argument("--accepted-fixed-term-order", action="store_true",
                           help="Record an already accepted fixed-term order; does not create or enforce Terms")
            a.add_argument("--terms-revision", required=True)
    a = sub.add_parser("verify")
    a.add_argument("--certificate", type=Path, required=True)
    a.add_argument("--bundle", type=Path, required=True)
    a.add_argument("--trusted-public-key", type=Path, required=True)
    a.add_argument("--trusted-root", type=Path, required=True)
    a.add_argument("--cosign", type=Path, required=True)
    a.add_argument("--artifact", type=Path, required=True)
    a.add_argument("--sku", required=True)
    a.add_argument("--version", required=True)
    a.add_argument("--require-production", action="store_true")
    return p


if __name__ == "__main__":
    args = parser().parse_args()
    functions = {"prepare-shared": prepare_shared, "issue": issue, "verify": verify,
                 "verify-anchor": lambda a: vendor_anchor(a.public_key)}
    print(json.dumps(functions[args.action](args)))
