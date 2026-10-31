#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create per-file VirusTotal hash links or query existing reports. GET only.

No binary upload, rescan request, URL submission or automatic unknown->clean.
VT_API_KEY is read from the environment and never written to the report.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request
import zipfile


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


def collect_files(manifests):
    files = []
    for path in manifests:
        manifest = json.loads(path.read_text())
        wheel = path.parent / manifest["wheel"]
        if wheel.name != manifest["wheel"] or not wheel.is_file():
            raise ValueError("Missing final wheel or invalid wheel filename")
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != manifest["wheel_sha256"]:
            raise ValueError("Final wheel digest differs from manifest")
        with zipfile.ZipFile(wheel) as archive:
            if len(archive.namelist()) != len(set(archive.namelist())) or set(archive.namelist()) != set(manifest["files"]):
                raise ValueError("Final wheel membership differs from manifest")
            for name, item in manifest["files"].items():
                if hashlib.sha256(archive.read(name)).hexdigest() != item["sha256"]:
                    raise ValueError("Final wheel member digest differs from manifest")
        files.append({"name": manifest["wheel"], "sha256": manifest["wheel_sha256"], "kind": "wheel"})
        files.extend({"name": manifest["wheel"] + "::" + name, "sha256": item["sha256"], "kind": "wheel_member"}
                     for name, item in manifest["files"].items())
    if not files or any(not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) for item in files):
        raise ValueError("Invalid final subject digest")
    return files


def manual_links(text, observed_at, expected, now):
    urls = {}
    for url in text.split():
        match = re.fullmatch(r"https://www\.virustotal\.com/gui/file/([0-9a-fA-F]{64})", url)
        if not match:
            raise ValueError("Expected an exact HTTPS VirusTotal SHA256 report URL")
        digest = match[1].lower()
        if digest not in expected:
            raise ValueError("Report URL digest is not a final artifact digest")
        urls[digest] = "https://www.virustotal.com/gui/file/" + digest
    if observed_at:
        observed = dt.datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        if observed.tzinfo is None or observed > now + dt.timedelta(minutes=5):
            raise ValueError("Owner observation needs a non-future timezone-aware timestamp")
        observed_at = observed.astimezone(dt.timezone.utc).isoformat()
    return urls, observed_at


def generate(manifests, do_query, require_complete, max_age_days, interval_s,
             manual_report_urls="", observed_at="", commercial_api_authorized=False):
    files = collect_files(manifests)
    unique = sorted({item["sha256"] for item in files})
    reports = {}
    key = os.environ.get("VT_API_KEY", "")
    now = dt.datetime.now(dt.timezone.utc)
    api_mode = bool(do_query and key)
    urls, observed_at = manual_links(manual_report_urls, observed_at, set(unique), now)
    for index, digest in enumerate(unique):
        if not api_mode and digest in urls and observed_at:
            age = (now - dt.datetime.fromisoformat(observed_at)).total_seconds()
            result = {"status": "OWNER_LINK_RECORDED" if age <= max_age_days * 86400 else "STALE_OWNER_OBSERVATION",
                      "owner_observed_utc": observed_at, "date_source": "owner assertion",
                      "report_content_verified": False, "detections_verified": False}
        elif not api_mode and (manual_report_urls or observed_at):
            result = {"status": "NEED_OWNER_REPORT_URL_AND_DATE"}
        elif not do_query:
            result = {"status": "LINK_ONLY_NOT_SCANNER_REPORT"}
        elif not key:
            result = {"status": "NEED_OWNER_REPORT_URL_AND_DATE"}
        elif not commercial_api_authorized:
            result = {"status": "NEED_COMMERCIAL_API_AUTHORIZATION"}
        else:
            if index:
                time.sleep(interval_s)
            result = query(digest, key, max_age_days)
        reports[digest] = {"sha256": digest, "url": "https://www.virustotal.com/gui/file/" + digest, **result}
    eligible = all(item["status"] == "OBSERVED_NO_DETECTIONS" for item in reports.values())
    manual_complete = all(item["status"] == "OWNER_LINK_RECORDED" for item in reports.values())
    flagged = any(item["status"] == "FLAGGED" for item in reports.values())
    result = {"generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "files": files,
              "hash_reports": reports, "file_count": len(files), "unique_hash_count": len(unique),
              "uploads": 0, "rescans": 0,
              "mode": "licensed_api" if api_mode else "owner_manual_links",
              "requests": "GET /api/v3/files/{sha256} only" if api_mode and commercial_api_authorized else "NONE",
              "release_gate": "FLAGGED" if flagged else "REPORTS_AVAILABLE_NO_DETECTIONS" if eligible else
                              "OWNER_LINKS_COMPLETE_CONTENT_UNVERIFIED" if manual_complete else "NEED_REPORTS",
              "not_a_safety_certificate": True}
    return result, 1 if flagged else 3 if require_complete and not (eligible or manual_complete) else 0


def markdown(result):
    lines = ["## VirusTotal dated observations", "", "Status: " + result["release_gate"], "",
             "Links identify final SHA256 bytes. Manual mode does not fetch or verify report contents, dates or detections.",
             "This is not a safety certificate. Owner dates are assertions, not API-verified analysis dates.", ""]
    for digest, report in sorted(result["hash_reports"].items()):
        date = report.get("owner_observed_utc", report.get("analysis_utc", "not supplied"))
        lines.append("- [" + digest + "](" + report["url"] + ") — " + report["status"] + "; " + date)
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--query", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--manual-report-urls", default="", help="Whitespace-separated exact SHA256 GUI report URLs")
    parser.add_argument("--observed-at", default="", help="Owner observation ISO8601 timestamp, including timezone")
    parser.add_argument("--commercial-api-authorized", action="store_true",
                        help="Owner confirms API licence permits this commercial workflow; Public API is forbidden")
    parser.add_argument("--markdown-output", type=Path)
    parser.add_argument("--max-age-days", type=int, default=30)
    parser.add_argument("--interval-s", type=float, default=16.0,
                        help="Respect the rate limit of the configured API plan")
    args = parser.parse_args()
    try:
        result, code = generate(args.manifest, args.query, args.require_complete, args.max_age_days, args.interval_s,
                                args.manual_report_urls, args.observed_at, args.commercial_api_authorized)
    except ValueError as error:
        parser.exit(2, str(error) + "\n")
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    if args.markdown_output:
        args.markdown_output.write_text(markdown(result))
    print(json.dumps({key: result[key] for key in ("file_count", "unique_hash_count", "release_gate", "uploads")}))
    raise SystemExit(code)
