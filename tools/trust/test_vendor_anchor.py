# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import entitlement as e

PUBLIC_PEM = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAi5xq18J2y85JdcybqtCXrUOHjQQkJoxunV6Ji16rvog=\n-----END PUBLIC KEY-----\n'


class VendorAnchorTests(unittest.TestCase):
    def test_public_anchor_matches_schema_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory) / "public.pem"
            public.write_text(PUBLIC_PEM)
            result = e.vendor_anchor(public)
            schema = json.loads(Path(e.__file__).with_name("ENTITLEMENT_SCHEMA.json").read_text())
            self.assertEqual(result["key_id"], schema["x-vendor-trust-anchor"]["key_id"])
            self.assertEqual(result["public_key_sha256"], schema["x-vendor-trust-anchor"]["public_key_sha256"])
            self.assertEqual(result["network_requests"], 0)

    def test_unrelated_public_key_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory) / "wrong.pem"
            public.write_text(PUBLIC_PEM.replace("i5xq", "j5xq"))
            with self.assertRaises(ValueError):
                e.vendor_anchor(public)

    def test_production_verification_checks_pin_before_signature_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "public.pem"
            public.write_text("not the vendor public key")
            artifact = root / "fixture.whl"
            artifact.write_bytes(b"fixture only")
            certificate = root / "certificate.json"
            certificate.write_text(json.dumps({"schema":e.SCHEMA,"issuer":"TAKT",
                "issuer_profile":"SELF_MANAGED_VENDOR_KEY","order_ref":"00000000-0000-0000-0000-000000000001",
                "sku":"fixture","version":"1.0","artifact_sha256":e.digest(artifact),"seats":1,
                "term":{"binary_use":"perpetual","support_updates_through":None},"terms_revision":"fixture"}))
            args = SimpleNamespace(certificate=certificate, trusted_public_key=public, artifact=artifact,
                sku="fixture",version="1.0",require_production=True,cosign=root/"unused",bundle=root/"unused",
                trusted_root=root/"unused")
            with patch.object(e,"verify_signature") as signature:
                with self.assertRaises(ValueError):e.verify(args)
                signature.assert_not_called()
                public.write_text(PUBLIC_PEM)
                result=e.verify(args)
                signature.assert_called_once()
                self.assertEqual(result["vendor_key_id"],e.VENDOR_KEY_ID)


if __name__ == "__main__":
    unittest.main()
