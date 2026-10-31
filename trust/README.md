# Vendor entitlement public trust anchor

The owner-authorized v1 Ed25519 public anchor is committed here.
Key ID (SHA256 SPKI DER): `sha256:d2c5c31e6f032b82d744a19d1f7ddb54b407b9883dbccdc4521c7011f0b682fc`.
PEM SHA256: `3bd6f39b7650597a654eb78cadcd4c4f214cf7e2af1c4d05e384b0ef6ba53c3d`.
Files: vendor-entitlement-v1.pub.pem and vendor-entitlement-v1.json; web copies
are prepared at https://taktcycles.com/trust/. Verify the fingerprint independently.
No private key, age identity, encrypted private key or customer certificate belongs
in this repository or CI. Test keys are not production anchors.

The key authenticates separate contractual certificates. Binaries do not read
certificates, call a licence server or enforce terms. Keyless artifact signing and
GitHub attestations use their separate OIDC/provenance trust, not this key.
See docs/STORE_RELEASE.md and the schema's x-vendor-trust-anchor metadata.

VirusTotal links remain dated observations. Manual mode does not verify report
contents or justify a clean badge. The Public API is forbidden for this commercial
workflow; a licensed commercial API path is separate.
