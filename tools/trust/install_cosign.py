#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Install the exact independently checksum-pinned official Cosign executable."""

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    pin = json.loads((Path(__file__).parent / "COSIGN_PIN.json").read_text())
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(pin["url"], timeout=30) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != pin["sha256"]:
        raise ValueError("Cosign download SHA mismatch")
    with a.output.open("xb") as stream:
        stream.write(data)
    a.output.chmod(0o755)
