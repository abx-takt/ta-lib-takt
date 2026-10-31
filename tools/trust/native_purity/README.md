# Native desktop purity diagnostics

These are public MIT controls and real tracing adapters, **not a purity certificate**.
They cannot sign, publish or mark a SKU release ready. The packaged `verify/pure`
bootstrap still refuses to certify native calls. No SKU is executed here.

The separate manually dispatched workflow is intended to obtain the first actual
native receipts after review and merge. Source compilation and mock trace tests on
Linux do not replace that run. It has no signing environment, private inputs, OIDC
or publishing permissions. It changes neither SIP nor Defender. No dispatch has
been performed by the author of this block.

## Controls and boundary

Build the fixed public `control.c` with CMake. The six modes are a clean arithmetic
control, file write, child creation, a UDP packet to **127.0.0.1 only**, writable
open without a write, and a shared writable mapping. The driver creates and deletes
the disposable 4096-byte test file outside each observed target interval. It traces
only these public controls. It checks whether file/process/network violations are
actually seen. The clean control remains `INCOMPLETE`, never a silence-based PASS.
Import and call of every real SKU are separate **MISSING** boundaries.

macOS: an unprivileged trusted launcher closes extra descriptors and stops itself
before executing the target. A separate inherited read-only gate pipe also blocks
exec, even if an attaching debugger resumes SIGSTOP. The driver attaches `sudo -n
dtrace`, requires its BEGIN record for the exact PID, then sends the one-byte gate
token and resumes that PID; the gate is closed before exec. The target retains the caller
UID. It inherits neither the tracer pipe nor a trace output file. Both `syscall`
and `mach_trap` providers are required; no `-Z` missing-probe suppression is used.
Numeric arguments and names are parsed without capturing paths or client bytes.
Unknown syscalls, undecoded Mach traps, malformed/truncated records, tracer
diagnostics (including drops), missing boundaries and nonzero return codes retain
`INCOMPLETE`. Mach IPC and the complete syscall argument policy are not yet closed.
SIP is recorded and remains enabled. A missing provider or attach privilege is a
specific NEED, not a reason to disable system protection. Apple documents protected
process restrictions and distinguishes development inspection of one's own apps.
[Apple runtime protections](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/RuntimeProtections/RuntimeProtections.html),
[Apple provider source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/dev/dtrace/systrace.c).

Windows: the pinned Microsoft TraceEvent ETW consumer starts a new uniquely named
kernel file session **before** creating the control, records the target and its
children, then stops and decodes it. File/network/process and registry mutation
events give positive detections. Both live-session and ETL loss counters are
recorded. Unresolved PID and unhandled target events are counted. The local ETL can
contain unrelated runner paths; it is deleted in `finally` and is never uploaded.
The summary exports no paths, command lines, names or packet payloads.
The fixed public target currently uses the native CI runner's token; this is **not**
a general elevated runner for arbitrary SKU/client code. That admission boundary
would need a split privileged observer and an unchanged client token.

The classic Windows FileIo_Create schema does not include `DesiredAccess`, and
SysCallEnter exposes a function address rather than syscall arguments. Denied
attempts, writable-open semantics, mapped I/O and IPC are therefore not proven
absent. The code always emits `purity_pass=false`, including a clean trace with
zero reported losses. A positive violation may be valid evidence while full
coverage is still incomplete.
[FileIo_Create schema](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-create),
[SysCallEnter schema](https://learn.microsoft.com/en-us/windows/win32/etw/syscallenter),
[ETW loss conditions](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing),
[Microsoft TraceEvent source](https://github.com/microsoft/perfview/tree/main/src/TraceEvent).

## Run after review (no signatures or secrets)

Dispatch `desktop-purity-controls.yml` on reviewed main with
`confirm_public_controls_only=true`. Its supported hosts are macos-15 ARM,
macos-15-intel and windows-latest; actual hosts are recorded. The two macOS minimum
build targets are 14 ARM and 13 Intel; those are **not** claims of tested runtime
compatibility on 13/14. A failed native tracer or missed negative control is NEED.
Even a green diagnostic workflow is **not a native SKU purity PASS**.

The .NET dependency and all transitive packages are locked by version/content hash
in `windows/packages.lock.json`; its Microsoft component is MIT. This consumer is a
CI tool, not a wheel payload. Raw traces, SDKs and local build trees are not shipped.
