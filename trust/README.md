# Vendor entitlement public trust anchor

The production Ed25519 key has not been generated. No test key is a production
trust anchor. The owner runs `tools/trust/generate_vendor_key_offline.py` on an
offline Linux machine, supplying the owner's trusted X25519 age recipient.
Only `vendor-entitlement-v1.pub.pem` and `vendor-entitlement-v1.json` belong here
and at https://taktcycles.com/trust/. No private key, age identity, encrypted
private key or customer certificate belongs in this repository or CI.

The key authenticates separate contractual certificates. Package binaries do
not read certificates, contact a licence server or enforce their term.
