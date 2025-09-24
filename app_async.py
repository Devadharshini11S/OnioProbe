# app_async.py
import os
import uuid
import json
import time
import logging
import shutil
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import requests

from scanner import run_scan  # uses your scanner.py

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("onioprobe_api")

# Config
REPORT_DIR = os.getenv("REPORT_DIR", "reports")
os.makedirs(REPORT_DIR, exist_ok=True)
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "2"))
QUICK_CRAWL_MAX = int(os.getenv("QUICK_CRAWL_MAX", "15"))  # max links for quick summary
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "8"))
TOR_SOCKS = os.getenv("TOR_SOCKS", "socks5h://127.0.0.1:9050")
ONION_RE = re.compile(r"[a-z2-7]{16,56}\.onion", re.I)

app = Flask(__name__)
CORS(app)

executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
jobs: Dict[str, Dict[str, Any]] = {}  # job_id -> metadata


# Utility: quick header checks
def check_security_headers(headers: Dict[str, str]) -> List[str]:
    missing = []
    # common security headers
    required = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Strict-Transport-Security",
        "Permissions-Policy",
    ]
    for h in required:
        if h not in headers:
            missing.append(h)
    return missing


# Quick (fast) crawl: fetch the target page, extract same-domain links up to a limited number
def quick_crawl_and_checks(url: str, use_tor: bool = False) -> Dict[str, Any]:
    session = requests.Session()
    if use_tor:
        session.proxies.update({"http": TOR_SOCKS, "https": TOR_SOCKS})
    result = {"urls": [], "onion_links": [], "missing_headers": {}, "status_code": None}
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        result["status_code"] = r.status_code
        headers = {k: v for k, v in r.headers.items()}
        missing = check_security_headers(headers)
        result["missing_headers"][url] = missing
        # find links
        links = set(re.findall(r'href=[\'"]?([^\'" >]+)', r.text))
        parsed = urlparse(url)
        same_domain_links = []
        for l in links:
            # build absolute url
            try:
                full = urljoin(url, l)
                p = urlparse(full)
                if p.netloc and parsed.netloc in p.netloc:
                    same_domain_links.append(full)
            except Exception:
                continue
            if len(same_domain_links) >= QUICK_CRAWL_MAX:
                break
        result["urls"] = same_domain_links
        # detect onion inline
        onions = ONION_RE.findall(r.text or "")
        result["onion_links"] = list(set([o.lower() for o in onions]))
    except Exception as e:
        logger.warning("Quick crawl failed for %s: %s", url, e)
    return result


def background_scan(job_id: str, target: str, active: bool, use_tor: bool):
    """Background worker that runs the full scanner and updates the job metadata."""
    logger.info("Job %s: background scan started (active=%s, tor=%s)", job_id, active, use_tor)
    jobs[job_id]["status"] = "scanning"
    jobs[job_id]["progress"] = 10
    jobs[job_id]["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    try:
        # run the heavy scan (scanner.run_scan returns (result, filename))
        result, fname = run_scan(target, deep_scan=active, fetch_with_tor=use_tor)
        # move report into REPORT_DIR (scanner already writes into REPORT_DIR by default)
        basename = os.path.basename(fname)
        dest = os.path.join(REPORT_DIR, basename)
        try:
            shutil.move(fname, dest)
        except Exception:
            # if already in place or move failed, ignore
            dest = fname if os.path.exists(fname) else dest

        jobs[job_id]["progress"] = 95
        jobs[job_id]["status"] = "finalizing"
        jobs[job_id]["result_file"] = basename
        jobs[job_id]["report"] = result
        jobs[job_id]["progress"] = 100
        jobs[job_id]["status"] = "done"
        jobs[job_id]["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        logger.info("Job %s: done. Report %s", job_id, dest)
    except Exception as e:
        logger.exception("Job %s: error during background scan: %s", job_id, e)
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(e)
        jobs[job_id]["progress"] = 100


@app.route("/scan", methods=["POST"])
def scan():
    """
    POST /scan
    JSON body: { "url": "...", "active": false, "use_tor": false }
    Returns immediately with a job_id and a quick summary.
    """
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url")
    if not url:
        return jsonify({"error": "missing url"}), 400
    active = bool(data.get("active", False))
    use_tor = bool(data.get("use_tor", False))

    # quick summary (fast, non-ZAP)
    quick = quick_crawl_and_checks(url, use_tor=use_tor)
    quick_summary = {
        "urls_found_quick": len(quick.get("urls", [])),
        "onion_links_quick": quick.get("onion_links", []),
        "missing_headers_quick": quick.get("missing_headers", {}),
        "status_code": quick.get("status_code"),
    }

    # create job
    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "id": job_id,
        "target": url,
        "active": active,
        "use_tor": use_tor,
        "status": "queued",
        "progress": 0,
        "quick_summary": quick_summary,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # submit background scan
    executor.submit(background_scan, job_id, url, active, use_tor)

    return jsonify({"job_id": job_id, "quick_summary": quick_summary}), 202


@app.route("/status/<job_id>", methods=["GET"])
def status(job_id):
    j = jobs.get(job_id)
    if not j:
        return jsonify({"error": "job not found"}), 404
    # return minimal info
    return jsonify({
        "job_id": job_id,
        "status": j.get("status"),
        "progress": j.get("progress", 0),
        "quick_summary": j.get("quick_summary", {}),
        "result_file": j.get("result_file")
    })


@app.route("/result/<job_id>", methods=["GET"])
def result(job_id):
    j = jobs.get(job_id)
    if not j:
        return jsonify({"error": "job not found"}), 404
    if j.get("status") != "done":
        return jsonify({"error": "result not ready", "status": j.get("status")}), 202
    # return full report
    return jsonify(j.get("report", {}))


@app.route("/download/<filename>", methods=["GET"])
def download(filename):
    path = os.path.join(REPORT_DIR, filename)
    if not os.path.exists(path):
        return jsonify({"error": "file not found"}), 404
    return send_file(path, as_attachment=True)


@app.route("/jobs", methods=["GET"])
def list_jobs():
    # debug endpoint to see all jobs
    return jsonify({"jobs": list(jobs.values())})


if __name__ == "__main__":
    port = int(os.getenv("API_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "False").lower() in ("1", "true", "yes")
    logger.info("Starting OnioProbe async API on 0.0.0.0:%s (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
