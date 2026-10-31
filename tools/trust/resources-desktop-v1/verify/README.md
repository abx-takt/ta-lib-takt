# Desktop verification bootstrap v1

This is an unsigned bootstrap, not a native release or a purity certificate.
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
