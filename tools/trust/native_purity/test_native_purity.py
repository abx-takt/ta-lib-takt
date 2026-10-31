# SPDX-License-Identifier: MIT
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
import signal

spec = importlib.util.spec_from_file_location("macos_collect", Path(__file__).with_name("macos_collect.py"))
mac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mac)


class NativeTraceTests(unittest.TestCase):
    def event(self, name, args=None, provider="S"):
        return "|".join([provider, "50", name, *[f"{n:x}" for n in (args or [0] * 6)]])

    def parse(self, *events, stderr="", rc=0):
        return mac.parse_trace("\n".join(["B|123", *events, "T|0", "E"]), stderr, 123, rc)

    def test_clean_is_never_a_purity_pass(self):
        result = self.parse(self.event("getpid"))
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertFalse(result["purity_pass"])

    def test_network_attempt(self):
        self.assertIn("NETWORK_ATTEMPT", self.parse(self.event("connect"))["violations"])

    def test_process_attempt(self):
        self.assertIn("PROCESS_CREATION_OR_UNADMITTED_EXEC", self.parse(self.event("posix_spawn"))["violations"])

    def test_file_write(self):
        self.assertIn("FILE_WRITE_ATTEMPT", self.parse(self.event("write", [5, 0, 1, 0, 0, 0]))["violations"])

    def test_stdio_not_assumed_to_be_pipe(self):
        result = self.parse(self.event("write", [1, 0, 1, 0, 0, 0]))
        self.assertEqual(result["status"], "INCOMPLETE")

    def test_read_open_incomplete(self):
        self.assertEqual(self.parse(self.event("open", [999, 0, 0, 0, 0, 0]))["status"], "INCOMPLETE")

    def test_write_open_flag_location(self):
        self.assertIn("WRITABLE_OPEN_ATTEMPT", self.parse(self.event("open", [999, 2, 0, 0, 0, 0]))["violations"])
        self.assertIn("WRITABLE_OPEN_ATTEMPT", self.parse(self.event("openat", [999, 999, 2, 0, 0, 0]))["violations"])

    def test_private_mapping_not_reported_as_shared_write(self):
        result = self.parse(self.event("mmap", [0, 4096, 3, 2, 5, 0]))
        self.assertNotIn("SHARED_WRITABLE_MAPPING_ATTEMPT", result["violations"])
        self.assertFalse(result["purity_pass"])

    def test_shared_mapping_detected(self):
        self.assertIn("SHARED_WRITABLE_MAPPING_ATTEMPT", self.parse(self.event("mmap", [0, 4096, 3, 1, 5, 0]))["violations"])

    def test_mach_traps_not_silently_allowed(self):
        result = self.parse(self.event("mach_msg_trap", provider="M"))
        self.assertIn("MACH_TRAP_ARGUMENTS_UNDECODED", result["coverage_gaps"])

    def test_drop_and_unknown_diagnostic(self):
        for stderr in ["dtrace: 12 drops", "SIP is on", "unexpected warning"]:
            self.assertIn("TRACER_DIAGNOSTIC_OR_DROP", self.parse(self.event("getpid"), stderr=stderr)["coverage_gaps"])

    def test_truncation_and_unrecognized_records(self):
        for raw in ["B|123\nS|50|write|5", "B|999\nT|0\nE", "", "B|123\nT|0", "B|123\nB|123\nT|0\nE"]:
            result = mac.parse_trace(raw, "", 123, 0)
            self.assertFalse(result["purity_pass"])
            self.assertEqual(result["status"], "INCOMPLETE")

    def test_unknown_syscall_and_malformed_arguments(self):
        result = self.parse(self.event("new_future_syscall"), "S|50|write|fffffffffffffffff|0|0|0|0|0")
        self.assertTrue(any(x.startswith("SYSCALL_ARGUMENT_POLICY_UNPROVEN") for x in result["coverage_gaps"]))
        self.assertIn("MALFORMED_ARGUMENT", result["coverage_gaps"])

    def test_privilege_and_provider_failure_are_different(self):
        self.assertEqual(mac.diagnostic_code("operation not permitted"), "TRACER_PRIVILEGE_OR_SIP_UNAVAILABLE")
        self.assertEqual(mac.diagnostic_code("probe description does not match any probes"), "REQUIRED_PROVIDER_UNAVAILABLE")

    def test_second_exec_is_not_hidden_by_start_boundary(self):
        result = self.parse(self.event("execve"), self.event("execve"))
        self.assertIn("PROCESS_REPLACEMENT_AFTER_INITIAL_EXEC", result["violations"])

    def test_coalesced_begin_keeps_suffix(self):
        raw = ("B|123\n" + self.event("write", [5, 0, 1, 0, 0, 0]) + "\nT|0\nE\n").encode()
        self.assertTrue(mac.begin_matches(raw, 123))
        self.assertIn("FILE_WRITE_ATTEMPT", mac.parse_trace(raw.decode(), "", 123, 0)["violations"])
        self.assertFalse(mac.begin_matches(raw, 999))
        self.assertFalse(mac.begin_matches(b"B|123", 123))

    def test_cleanup_eperm_uses_only_own_observer_group(self):
        tracer = mock.Mock(pid=12345)
        tracer.poll.return_value = None
        tracer.wait.return_value = 0
        with mock.patch.object(mac.os, "killpg", side_effect=PermissionError()), mock.patch.object(mac.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            mac.cleanup_tracer(tracer)
        self.assertEqual(run.call_args.args[0], ["sudo", "-n", "/bin/kill", "-INT", "-12345"])
        tracer.wait.assert_called_once_with(timeout=5)

    def test_cleanup_missing_privilege_is_not_silently_successful(self):
        tracer = mock.Mock(pid=12345)
        tracer.poll.return_value = None
        with mock.patch.object(mac.os, "killpg", side_effect=PermissionError()), mock.patch.object(mac.subprocess, "run", return_value=mock.Mock(returncode=1)):
            with self.assertRaisesRegex(RuntimeError, "OBSERVER_CLEANUP_PRIVILEGE_UNAVAILABLE"):
                mac.cleanup_tracer(tracer)


if __name__ == "__main__": unittest.main()
