# Store release inputs and owner setup

This workflow runs only by workflow_dispatch on main. Signing/attestation and
PyPI publication default to false. No private build inputs are stored here.

The reviewed descriptor in `.store/inputs/<package>/<version>.json` names an
exact SHA256-pinned ZIP release asset in **abx-takt/store-build-inputs**, a
separate **private** repository. Its source wheel/native files are also pinned
individually and must match the assembly manifest. These are precompiled inputs;
no private source, packer, customer data or entitlement key is needed in CI.
The resulting provenance describes assembly, not reproduction of the closed
native kernel from public source.

Before the first manual run the owner must:

1. Create/confirm the private input repository, create the tag named by the
   descriptor and upload the exact local ZIP supplied in the handoff. Do not
   upload these ZIPs to this public repository, a public release, VT or logs.
2. Set repository secret `STORE_INPUTS_READ_TOKEN` to a fine-grained token with
   Contents:read for only that private repository (or the equivalent short-lived
   GitHub App token). The public repo GITHUB_TOKEN cannot read another private
   repo. Only the trusted main assemble step receives this credential; no PR
   workflow is added. Rotation/expiry remains the owner's responsibility.
3. Confirm the pypi/store-signing environments and desired approval/branch rules.
   They exist but protection rules are not claimed. Configure the exact PyPI
   Trusted Publisher: owner abx-takt, this repository, store-release.yml, pypi.
4. Provide `VT_API_KEY` and existing fresh reports for each final hash before
   requesting signing. The workflow never uploads or rescans files on VT.

Assembly and native checks have no OIDC permission. ClamAV uses a fresh database
directory and requires freshclam to succeed; clamscan refuses databases older
than two days, limits exceeded and scanner errors. Scan logs identify the
scanner/database version and update outcome; no clean claim exists until a real
CI run succeeds. The actual final bytes are scanned before protected signing.
PEP740 publication is a separate protected top-level job, after checks/scans/sign.

The input ZIP stays local to the assemble runner. Reference public wheels and
final review artifacts are separated from the sign/publish allowlists. Raw pure
traces, model/input data, private source and certificates are never uploaded.
No dispatch, signing, publishing or secret configuration is performed by this PR.

## Owner-only entitlement key ceremony

Run `tools/trust/generate_vendor_key_offline.py` yourself on an offline Linux
machine with OpenSSL, age and unshare installed. Supply a trusted **public**
X25519 age recipient file; never provide an age identity/private key to an agent.
For example (choose your real local paths, no production key is generated here):

```sh
python3 tools/trust/generate_vendor_key_offline.py \
  --recipient-file /owner/trusted-age-recipient.txt \
  --private-directory /owner/offline/vendor-entitlement-v1 \
  --public-directory /owner/repos/ta-lib-takt/trust \
  --public-directory /owner/repos/quantlib-takt/trust \
  --public-directory /owner/repos/lightgbm-takt/trust \
  --public-directory /owner/site/trust
```

Each crypto tool runs in an unshared network namespace. Ed25519 PKCS8 private
bytes are only in process memory/pipes; only their age ciphertext is written,
mode0600 in a new0700 private directory. Python does not promise memory erasure;
use an owner-controlled machine and appropriate swap/storage policy. Existing
keys/anchors are refused. Stdout contains only public metadata. Do not run with
shell xtrace, capture process memory, or upload the private directory.

Commit/deploy **only** `vendor-entitlement-v1.pub.pem` and its JSON fingerprint
from each public directory. Publish identical public bytes at
https://taktcycles.com/trust/. Until the owner runs this ceremony and distributes
the public fingerprint independently, production entitlement trust is pending.
The script is not executed by CI or by the assistant. The PKCS8 key must be
imported into the existing Cosign issuer by the owner offline when issuing;
keep any decrypted/imported key and password solely in owner RAM/private storage.
The certificate authenticates agreed rights; the binary does not read it or
implement licence checks, expiry enforcement or telemetry.
