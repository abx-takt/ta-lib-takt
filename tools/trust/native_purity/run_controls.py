#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native public-control diagnostics only; never execute a SKU or publish PASS."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

MODES = ("clean", "write", "process", "network", "openwrite", "mapwrite")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ns = ap.parse_args()
    if ns.out.exists(): ap.error("New output directory required")
    if platform.system() not in {"Darwin", "Windows"}: ap.error("Native Mac/Windows required")
    root = Path(__file__).resolve().parent
    ns.out.mkdir(parents=True)
    is_win = platform.system() == "Windows"
    control = ns.build.resolve() / ("Release/takt-purity-control.exe" if is_win else "takt-purity-control")
    cases = {}
    for mode in MODES:
        payload = ns.out / (mode + ".fixture.bin")
        payload.write_bytes(b"0" * 4096)
        out = ns.out / (mode + ".json")
        command = [str(control), mode, str(payload.resolve())]
        if is_win:
            collector = ns.build.resolve() / "etw/Collector.dll"
            collector_args = ["dotnet", str(collector), str(out), str(ns.out / (mode + ".local-only.etl")), "--", *command]
        else:
            collector_args = [sys.executable, str(root / "macos_collect.py"), "--launcher", str(ns.build.resolve() / "takt-purity-launcher"), "--out", str(out), "--", *command]
        try:
            run = subprocess.run(collector_args, timeout=90, check=False, stdin=subprocess.DEVNULL)
            data = json.loads(out.read_text()) if out.exists() else {"status": "INCOMPLETE", "reason": "COLLECTOR_RECEIPT_MISSING"}
            data["collector_exit"] = run.returncode
        except (OSError, subprocess.TimeoutExpired, ValueError):
            data = {"status": "INCOMPLETE", "reason": "COLLECTOR_FAILED_OR_TIMED_OUT"}
        data["control_effect"] = {"first_byte_changed": payload.read_bytes()[:1] != b"0"}
        payload.unlink()
        cases[mode] = data
    expected = {"write": "FILE", "process": "PROCESS", "network": "NETWORK"}
    negatives_observed = {mode: any(prefix in item for item in cases[mode].get("violations", [])) for mode, prefix in expected.items()}
    receipt = {"schema": "takt-native-purity-control-suite-v1", "scope": "public diagnostic controls only; no SKU", "platform": platform.platform(), "control_sha256": hashlib.sha256(control.read_bytes()).hexdigest(), "cases": cases,
               "required_negative_controls_observed": negatives_observed, "native_diagnostic_controls_complete": all(negatives_observed.values()),
               "status": "INCOMPLETE_NATIVE_PURITY", "purity_pass": False, "release_ready": False,
               "import_boundary": "MISSING_SKU_IMPORT_CONTROL", "call_boundary": "MISSING_SKU_CALL_CONTROL"}
    (ns.out / "RESULT.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0 if all(negatives_observed.values()) else 3


if __name__ == "__main__": raise SystemExit(main())
