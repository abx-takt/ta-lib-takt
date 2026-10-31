# Store release inputs and owner setup

This workflow runs only by workflow_dispatch on main. Signing/attestation and
PyPI publication default to false. No private build inputs are stored here.

The reviewed descriptor in `.store/inputs/<package>/<version>.json` names an
exact SHA256-pinned ZIP in **abx-takt/store-build-inputs**, a separate **private**
repository. Default `input_transport=auto` prefers `STORE_INPUTS_DEPLOY_KEY`
(read-only SSH deploy key); otherwise it uses `STORE_INPUTS_READ_TOKEN` (release
PAT). Explicit `ssh`/`pat` choices are available. A failed SSH fetch is refused;
it does not silently retry via another credential.

SSH clones tag `inputs-git-2026-10-31-v6` without checking out or running files,
requires commit `7f34571aee38da77a376fb28c5fea086a0c0b59e`, and reads the exact
`inputs/<asset>` and `inputs/SHA256SUMS` regular blobs. ZIP/member SHA and size
checks are identical for both transports. PAT uses the separate `release_tag`
field (`store-inputs-2026-10-31-v6`), with the original private-repo API check.
The SSH mode relies on the reviewed repository allowlist, fixed commit and the
owner's private repository configuration; it does not need a cross-repo API token. Its source wheel/native files are also pinned
individually and must match the assembly manifest. These are precompiled inputs;
no private source, packer, customer data or entitlement key is needed in CI.
The resulting provenance describes assembly, not reproduction of the closed
native kernel from public source.

Before the first manual run the owner must:

1. Create/confirm the private input repository, create the tag named by the
   descriptor and upload the exact local ZIP supplied in the handoff. Do not
   upload these ZIPs to this public repository, a public release, VT or logs.
2. Configure `STORE_INPUTS_DEPLOY_KEY` as the read-only deploy key secret for
   only that input repository (already provisioned by the coordinator), or the
   optional `STORE_INPUTS_READ_TOKEN` with Contents:read for the PAT alternative.
   The public repo GITHUB_TOKEN cannot read another private repo. Only the trusted
   main assemble fetch step receives these credentials; no PR workflow is added.
   SSH writes its IdentityFile in a temporary0700 directory with mode0600,
   disables agents/passwords, requires strict host-key verification against the
   checked-in GitHub Ed25519 pin and cleans up on exit. Key bytes never appear in
   arguments/reports, and the key/token environment is removed from git/ssh child
   processes. No key is committed or uploaded in artifacts. Rotation/revocation
   remains the owner's responsibility.
3. Confirm the pypi/store-signing environments and desired approval/branch rules.
   They exist but protection rules are not claimed. Configure the exact PyPI
   Trusted Publisher: owner abx-takt, this repository, store-release.yml, pypi.
4. Choose one VirusTotal mode before requesting signing. **No key:** manually
   upload the intended public final files using the VT website yourself, then
   supply `vt_report_urls` (whitespace-separated exact
   `https://www.virustotal.com/gui/file/<sha256>` URLs) and `vt_observed_at`
   (ISO8601 with timezone). Cover every unique final wheel/member hash in the
   generated manifest. The helper verifies the actual final wheel and all member
   digests, rejects foreign or incomplete links, and makes **no API/HTTP calls**.
   **With `VT_API_KEY`:** use only an API licence authorizing this commercial
   workflow and explicitly set `vt_commercial_api_authorized=true`. A key alone
   is insufficient. The Public API is forbidden here, including GET-only lookups.
   The workflow never uploads or rescans files on VT.

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

## VirusTotal observation manifest and trust/card links

`store-scanner-summary-*` contains `VIRUSTOTAL.json` (the dated observation
manifest) and `VIRUSTOTAL_LINKS.md`; the latter also appears in the run summary.
Reuse its exact SHA256 links on the card and /trust/. Final wheel bytes and the
signed STORE_MANIFEST are unchanged by scanner metadata. Links remain external
observations, separate from signatures/provenance and from the local ClamAV gate.

Manual status is `OWNER_LINKS_COMPLETE_CONTENT_UNVERIFIED`: coverage and owner
observation date (at most 30 days old) are recorded; the helper does not verify
that a report exists, its contents, scanner verdict or actual analysis date.
Do not display a clean/no-detections badge based on this status. API observations
retain their analysis date/stats and flagged/missing/stale refusal behavior.
Signing requires complete observations in the chosen mode. Unsigned preparation
can emit NEED_REPORTS for the owner to complete; it is not release clearance.
The owner checks the applicable web-service terms before manual upload; this mode
avoids the Public API and makes no claim about separate website permissions.

Public API restrictions: https://docs.virustotal.com/reference/public-vs-premium-api
Local helper controls (no API requests):
`python3 -m unittest discover -s tools/trust -p 'test_*.py' -v`

## SSH host pin

GitHub Ed25519 host fingerprint:
`SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU`, pinned in
fetch_private_inputs.py and verified by an offline test. No ssh-keyscan, TOFU or
StrictHostKeyChecking=no. Source:
https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
A host-key rotation requires a reviewed source update, not automatic trust.

## Scanner configuration preflight

The scanner uses a new workspace-local `clamav-runtime` directory, independent
of RUNNER_TEMP. prepare_clamav.py creates exact LF-separated DatabaseMirror,
DatabaseDirectory and DatabaseOwner directives, mode0600, and a new0700 DB directory;
checks their actual bytes/accessibility; and emits CLAMAV_CONFIG.json. A pre-existing
workspace is refused. The installed freshclam first parses that exact file via
`--config-file=... --version` (no update/download), then performs the mandatory
fresh update; either failure fails the scan gate. Config/version preflight and
update stdout+stderr are retained in scanner-summary. No stale-definition or
scanner-error bypass is introduced. Signing/publishing still default to false.
