// SPDX-License-Identifier: MIT. Real ETW diagnostics, explicitly NOT a purity proof.
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

if (args.Length < 4 || args[2] != "--") return 64;
string output = Path.GetFullPath(args[0]), etl = Path.GetFullPath(args[1]);
if (File.Exists(etl) || File.Exists(output)) return 64;
var result = new Dictionary<string, object?> {
    ["schema"] = "takt-native-purity-etw-diagnostic-v1", ["purity_pass"] = false,
    ["release_ready"] = false, ["scope"] = "cold-process-including-image-start",
    ["status"] = "INCOMPLETE", ["platform"] = RuntimeInformation.OSDescription,
    ["coverage_gaps"] = new [] { "DesiredAccess absent from classic FileIo_Create", "syscall arguments absent", "denied I/O attempts not fully decoded", "mapped I/O and IPC not fully decoded" }
};
int exitCode = 3;
try {
    if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
    Directory.CreateDirectory(Path.GetDirectoryName(output)!);
    Directory.CreateDirectory(Path.GetDirectoryName(etl)!);
    string sessionName = "TAKT-Purity-" + Guid.NewGuid().ToString("N");
    int targetPid, targetRc; bool timeout;
    using (var session = new TraceEventSession(sessionName, etl)) {
        session.StopOnDispose = true;
        session.BufferSizeMB = 64;
        // Never attach/restart somebody else's ETW session.
        session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process |
            KernelTraceEventParser.Keywords.Thread | KernelTraceEventParser.Keywords.FileIO |
            KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.NetworkTCPIP |
            KernelTraceEventParser.Keywords.Registry | KernelTraceEventParser.Keywords.VirtualAlloc |
            KernelTraceEventParser.Keywords.VAMap | KernelTraceEventParser.Keywords.SystemCall);
        var info = new ProcessStartInfo(Path.GetFullPath(args[3])) { UseShellExecute = false };
        foreach (var arg in args.Skip(4)) info.ArgumentList.Add(arg);
        using var target = Process.Start(info) ?? throw new InvalidOperationException("No target");
        targetPid = target.Id;
        timeout = !target.WaitForExit(30000);
        if (timeout) { target.Kill(true); target.WaitForExit(); }
        targetRc = target.ExitCode;
        session.Flush();
        result["events_lost_before_stop"] = session.EventsLost;
        session.Stop();
    }
    var pids = new HashSet<int> { targetPid };
    var counts = new SortedDictionary<string, int>();
    var violations = new SortedSet<string>();
    int starts = 0, stops = 0, unresolved = 0, unknown = 0, total = 0;
    using (var source = new ETWTraceEventSource(etl)) {
        // No path, command line, packet payload or other-process identity is exported.
        source.Kernel.ProcessStart += data => {
            if (data.ProcessID == targetPid) starts++;
            if (pids.Contains(data.ParentID)) { pids.Add(data.ProcessID); violations.Add("PROCESS_CREATION"); }
        };
        source.Kernel.ProcessStop += data => { if (data.ProcessID == targetPid) stops++; };
        source.Kernel.All += data => {
            if (data.ProcessID < 0) unresolved++;
            if (!pids.Contains(data.ProcessID)) return;
            total++;
            string name = data.EventName;
            counts[name] = counts.GetValueOrDefault(name) + 1;
            if (name.StartsWith("TcpIp/") || name.StartsWith("UdpIp/")) violations.Add("NETWORK_ACTIVITY");
            if (name is "FileIO/Write" or "FileIO/Delete" or "FileIO/Rename" or "FileIO/SetInfo") violations.Add("FILE_MUTATION");
            if (name is "Registry/SetValue" or "Registry/DeleteValue" or "Registry/Delete" or "Registry/Create") violations.Add("REGISTRY_MUTATION");
            if (data is FileIOCreateTraceData create && (int)create.CreateDisposition != 1) violations.Add("MUTATING_CREATE_DISPOSITION");
        };
        source.UnhandledEvents += data => { if (pids.Contains(data.ProcessID)) unknown++; };
        source.Process();
        result["events_lost_etl"] = source.EventsLost;
    }
    result["target_pid"] = targetPid; result["target_rc"] = targetRc;
    result["complete_trace"] = false;
    result["timeout"] = timeout; result["process_starts"] = starts; result["process_stops"] = stops;
    result["unresolved_pid_events"] = unresolved; result["unknown_target_events"] = unknown;
    result["target_events"] = total; result["event_counts"] = counts; result["violations"] = violations;
    // A real violation is useful evidence even with incomplete coverage. Never PASS on silence.
    if (violations.Count > 0) { result["status"] = "VIOLATION_OBSERVED"; exitCode = 1; }
    else result["reason"] = "ETW_COVERAGE_INCOMPLETE_NOT_A_PURITY_PASS";
} catch (Exception error) {
    result["reason"] = "NATIVE_COLLECTOR_UNAVAILABLE_OR_FAILED";
    result["exception_type"] = error.GetType().Name;
    result["hresult"] = error.HResult;
} finally {
    // Raw kernel trace may contain unrelated runner paths: local only, never uploaded.
    if (File.Exists(etl)) File.Delete(etl);
    Directory.CreateDirectory(Path.GetDirectoryName(output)!);
    File.WriteAllText(output, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }) + "\n");
}
return exitCode;
