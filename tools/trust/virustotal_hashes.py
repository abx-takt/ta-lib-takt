#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create per-file VirusTotal hash links or query existing reports. GET only.

No binary upload, rescan request, URL submission or automatic unknown->clean.
VT_API_KEY is read from the environment and never written to the report.
"""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def classify(sha256, data, now, max_age_days):
    if data.get("data", {}).get("id") != sha256:
        return {"status": "ERROR_HASH_ID_MISMATCH"}
    attributes = data["data"].get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    date = attributes.get("last_analysis_date")
    completed = sum(stats.get(name, 0) for name in ("harmless", "undetected", "malicious", "suspicious"))
    if not stats or not date or not completed or not {"malicious", "suspicious"}.issubset(stats):
        return {"status": "INCOMPLETE_NO_ANALYSIS"}
    analysis_date = dt.datetime.fromtimestamp(date, dt.timezone.utc)
    result = {"analysis_utc": analysis_date.isoformat(), "analysis_stats": stats,
              "signal": "dated scanner observation; not a safety certificate"}
    if analysis_date > now + dt.timedelta(minutes=5):
        result["status"] = "ERROR_FUTURE_ANALYSIS_DATE"
    elif stats.get("malicious", 0) or stats.get("suspicious", 0):
        result["status"] = "FLAGGED"
    elif (now - analysis_date).total_seconds() > max_age_days * 86400:
        result["status"] = "STALE_REPORT"
    else:
        result["status"] = "OBSERVED_NO_DETECTIONS"
    return result


def query(sha256, key, max_age_days):
    request = urllib.request.Request("https://www.virustotal.com/api/v3/files/" + sha256,
                                     headers={"x-apikey": key}, method="GET")
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            data = json.load(response)
        return classify(sha256, data, dt.datetime.now(dt.timezone.utc), max_age_days)
    except urllib.error.HTTPError as error:
        return {"status": {404: "UNKNOWN_NOT_SCANNED", 401: "NEED_VALID_API_KEY",
                           403: "NEED_API_ACCESS", 429: "RATE_LIMITED"}.get(error.code, "HTTP_ERROR"),
                "http_status": error.code}
    except (OSError, ValueError) as error:
        return {"status": "QUERY_ERROR", "error_type": type(error).__name__}


def generate(manifests, do_query, require_complete, max_age_days, interval_s):
    files = []
    for path in manifests:
        manifest = json.loads(path.read_text())
        files.append({"name": manifest["wheel"], "sha256": manifest["wheel_sha256"], "kind": "wheel"})
        files.extend({"name": manifest["wheel"] + "::" + name, "sha256": item["sha256"], "kind": "wheel_member"}
                     for name, item in manifest["files"].items())
    unique = sorted({item["sha256"] for item in files})
    reports = {}
    key = os.environ.get("VT_API_KEY", "")
    for index, digest in enumerate(unique):
        if not do_query:
            result = {"status": "LINK_ONLY_NOT_SCANNER_REPORT"}
        elif not key:
            result = {"status": "NEED_VT_API_KEY"}
        else:
            if index:
                time.sleep(interval_s)
            result = query(digest, key, max_age_days)
        reports[digest] = {"sha256": digest, "url": "https://www.virustotal.com/gui/file/" + digest, **result}
    eligible = all(item["status"] == "OBSERVED_NO_DETECTIONS" for item in reports.values())
    flagged = any(item["status"] == "FLAGGED" for item in reports.values())
    result = {"generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "files": files,
              "hash_reports": reports, "file_count": len(files), "unique_hash_count": len(unique),
              "uploads": 0, "rescans": 0, "requests": "GET /api/v3/files/{sha256} only",
              "release_gate": "FLAGGED" if flagged else "REPORTS_AVAILABLE_NO_DETECTIONS" if eligible else "NEED_REPORTS",
              "not_a_safety_certificate": True}
    return result, 1 if flagged else 3 if require_complete and not eligible else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--query", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--max-age-days", type=int, default=30)
    parser.add_argument("--interval-s", type=float, default=16.0,
                        help="Respect the rate limit of the configured API plan")
    args = parser.parse_args()
    result, code = generate(args.manifest, args.query, args.require_complete, args.max_age_days, args.interval_s)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("file_count", "unique_hash_count", "release_gate", "uploads")}))
    raise SystemExit(code)
