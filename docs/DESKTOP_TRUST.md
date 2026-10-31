# Desktop verification bootstrap v1

The desktop_bootstrap inventory component is unsigned; it is not a native release or a purity certificate.
The existing Linux `resources-v6` verifier and final wheels are unchanged.

`desktop_bootstrap.py --target TARGET --output RESULT.json` records native runner
and tool availability without reading signing credentials. It always records
`release_ready=false`. A wrong OS/architecture returns exit 3.

`--inspect FILE` checks a bounded PE64 x86-64 or thin Mach-O64 x86-64/arm64 file:
architecture, structural bounds, declared imports/dependencies, writable executable
sections/segments and known packer markers. It does not validate the OS signature,
prove provenance, exclude arbitrary packing/anti-debugging, or compare results.
Fat/universal2 and specialized subtypes need a separate admission profile.

`pure.ps1 -Output result.json -- COMMAND` (Windows) or
`./pure.sh --output result.json -- COMMAND` (macOS) currently returns exit 3,
`INCOMPLETE_NATIVE_COLLECTOR_MISSING`, and does not execute COMMAND. It neither
approves a command from absent events nor records client command arguments.
A validated complete native collector and positive/negative controls are required
before a PASS mode can be added. Do not transplant Linux strace/unshare claims.
Do not disable SIP, Defender or OS policy for this bootstrap.

`store-release.yml` adds an opt-in desktop_bootstrap input (default false) with
Windows x64, macOS Intel and macOS arm64 inventory jobs. These jobs do not fetch
private inputs, use signing environments, run payloads, sign, notarize or publish.
They do not create desktop wheels. No workflow dispatch is implied by this patch.

OS-signature/notarization and concrete native numerical/purity evidence remain
MISSING until the owner has provisioned the protected signing route and platform
payloads and an explicit unsigned trial is authorised. Sigstore/PEP740 does not
replace Authenticode or Developer ID/notarization. Native signing must happen
before final wheel RECORD/hashes/external attestations, with no later mutation.

## Protected signing protocol control

`desktop_signing_smoke=true` is a separate opt-in control. It requires
`sign_and_attest=true`, `publish=false`, trusted main and the protected
`store-signing` environment. Both desktop modes bypass the existing Linux assemble/check/
scanner/release path, so it is not another Linux ClamAV trial. Normal release
behaviour retains the existing default when this option is false.

The control compiles a fixed public MIT C executable/library, records the exact
unsigned subjects, and signs only those files. It does not execute a SKU or the
control payload. Actual native signing is performed only by a reviewed dispatch
with coordinator-provisioned credentials; this source patch is not such a run.

Mac: private P12/P8 go only into a restricted temporary directory; a separate
keychain is imported/unlocked and removed in finally, and the original user
keychain list is restored. `codesign --options runtime --timestamp` is verified
against public Team ID and exact certificate fingerprints. `notarytool submit
--wait` must return Accepted. ZIP contains only the public signed subjects and
MIT notice, never credentials. Bare executable/dylib ZIP is not stapleable;
spctl executable and library assessments are reported with distinct scope.
No claim of wheel notarization/stapling or minimum-OS runtime testing follows.

Windows: pinned Azure login + Artifact Signing actions use GitHub OIDC and a
Public Trust profile. All other DefaultAzureCredential routes are excluded;
only the Azure CLI identity from the OIDC login is used. The exact executable
and DLL paths are allowlisted. SignTool /pa /all, expected publisher and timestamp
are checked. Actual leaf certificate fingerprints are captured per build because
managed leaves can rotate; they are not permanently pinned to a SKU.

Public variables required:

- Apple: APPLE_TEAM_ID, APPLE_SIGNING_CERT_SHA1, APPLE_SIGNING_CERT_SHA256.
- Windows: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID,
  AZURE_SIGNING_ENDPOINT, AZURE_SIGNING_ACCOUNT,
  AZURE_SIGNING_CERTIFICATE_PROFILE, WINDOWS_PUBLISHER_NAME.
- Optional runners: STORE_MACOS_ARM_RUNNER, STORE_MACOS_INTEL_RUNNER,
  STORE_WINDOWS_RUNNER. Defaults are supported macos-15, macos-15-intel,
  windows-latest; macos-13 is retired and macos-14 retires 2026-11-02.

Protected Apple secrets: APPLE_SIGNING_P12_B64, APPLE_SIGNING_P12_PASSWORD,
APPLE_ASC_KEY_P8_B64, APPLE_ASC_KEY_ID, APPLE_ASC_ISSUER_ID. The owner/coordinator
sets these directly. Do not send keys through an AI conversation or repository.
The existing vendor entitlement key is unrelated to OS signing.

## Final desktop wheel route (source tool, no automatic publication)

`desktop_wheel.py prepare` requires the exact unsigned wheel SHA and a declared
unpacked store profile/target. It rejects duplicate/traversal/symlink members,
undeclared native files, wrong architectures/platforms and unsuitable minimum-OS
tags. It stages exact native subjects for a native signing job.

`desktop_wheel.py finish` verifies actual OS signatures, checks loadable code/data
sections stayed identical, repacks signed bytes, and recalculates/verifies every
RECORD entry. This is an additional mutation check, not a numerical proof. The
result remains `FINAL_WHEEL_OS_SIGNED_RELEASE_BLOCKED`, release_ready=false,
until full native numerical and complete purity evidence exists. Scanners and
external signatures/attestations must use these final repacked bytes. No desktop
wheel is automatically added to the current Linux-only publisher by this patch.

The tiny signing fixture, mock unit certificates and synthetic binary structures
are protocol controls, not a product PASS. Real native runs, protected signing,
notary receipts and native purity remain MISSING until separately executed.
