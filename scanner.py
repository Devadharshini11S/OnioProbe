# scanner.py
"""
Improved scanner wrapper for OnioProbe.
- Reads ZAP host/port/api key from env
- Optional Tor fetch for onion detection
- Keeps the same JSON report output
"""

import os
import time
import re
import json
import logging
import shutil
from typing import Tuple, Dict, Any, List, Optional

import requests
from zapv2 import ZAPv2

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("onio_probe_scanner")

# Config (use env; keep sensible defaults)
API_KEY = os.getenv("ZAP_API_KEY", "")       # **Set this in env** for production
ZAP_HOST = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.getenv("ZAP_PORT", os.getenv("PORT_ZAP", "8080")))
ZAP_PROXY = f"http://{ZAP_HOST}:{ZAP_PORT}"
REPORT_DIR = os.getenv("REPORT_DIR", "reports")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "15"))
TOR_SOCKS = os.getenv("TOR_SOCKS", "socks5h://127.0.0.1:9050")  # default Tor socks

os.makedirs(REPORT_DIR, exist_ok=True)

# Onion regex (keeps your original idea; matches onion host anywhere)
ONION_RE = re.compile(r"[a-z2-7]{16,56}\.onion", re.I)

# OWASP mapping (kept your mapping)
OWASP_TOP10 = {
    "SQL Injection": "A03: Injection",
    "Cross Site Scripting": "A07: XSS",
    "Path Traversal": "A05: Security Misconfiguration",
    "Remote OS Command Injection": "A03: Injection",
    "Cross-Domain JavaScript Source File Inclusion": "A08: Software Integrity Failures",
    "Server Side Include": "A03: Injection",
    "Insecure JSF ViewState": "A02: Cryptographic Failures"
}


def connect_zap() -> ZAPv2:
    """Connect to local ZAP instance and validate connection."""
    zap = ZAPv2(apikey=API_KEY, proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})
    try:
        version = zap.core.version
        logger.info("Connected to ZAP API version: %s (proxy=%s)", version, ZAP_PROXY)
    except Exception as e:
        logger.exception("Cannot reach ZAP API at %s: %s", ZAP_PROXY, e)
        raise ConnectionError(f"Cannot reach ZAP API: {e}")
    return zap


def fetch_via_requests(url: str, use_tor: bool = False, timeout: int = REQUEST_TIMEOUT) -> str:
    """Fetch page text; use Tor if requested (for .onion discovery)."""
    s = requests.Session()
    if use_tor:
        s.proxies.update({"http": TOR_SOCKS, "https": TOR_SOCKS})
    r = s.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text


def detect_onion_from_urls(urls: List[str]) -> List[str]:
    found = set()
    for u in urls:
        for m in ONION_RE.findall(u or ""):
            found.add(m.lower())
    return sorted(found)


def make_unique_report_name(prefix: str = "onioprobe_result") -> str:
    ts = int(time.time())
    return os.path.join(REPORT_DIR, f"{prefix}_{ts}.json")


def run_scan(target_url: str, deep_scan: bool = False, fetch_with_tor: bool = False) -> Tuple[Dict[str, Any], str]:
    """
    Run a scan and write a JSON report.
    Returns (result_dict, report_filename_path)
    """
    zap = connect_zap()

    # New session in ZAP to isolate results
    session_name = f"onioprobe-{int(time.time())}"
    try:
        zap.core.new_session(name=session_name, overwrite=True)
    except Exception:
        # Not fatal; continue
        logger.debug("Could not create new ZAP session; continuing.")

    logger.info("Starting scan for %s (deep=%s, tor_fetch=%s)", target_url, deep_scan, fetch_with_tor)

    try:
        # Seed ZAP with the target URL (this will populate the site tree)
        zap.urlopen(target_url)
    except Exception as e:
        logger.warning("zap.urlopen failed (proceeding): %s", e)

    # Spider
    try:
        spider_id = zap.spider.scan(target_url)
        while int(zap.spider.status(spider_id)) < 100:
            logger.debug("Spider progress: %s%%", zap.spider.status(spider_id))
            time.sleep(1)
        logger.info("Spider completed.")
    except Exception as e:
        logger.warning("Spider failed or timed out: %s", e)

    # Active scan (optional)
    if deep_scan:
        try:
            ascan_id = zap.ascan.scan(target_url)
            while int(zap.ascan.status(ascan_id)) < 100:
                logger.debug("Active scan progress: %s%%", zap.ascan.status(ascan_id))
                time.sleep(2)
            logger.info("Active scan completed.")
        except Exception as e:
            logger.warning("Active scan failed or timed out: %s", e)

    # Gather URLs & alerts
    try:
        urls = list(set(zap.core.urls() or []))
    except Exception as e:
        logger.warning("Failed to fetch urls from ZAP: %s", e)
        urls = []

    try:
        alerts = zap.core.alerts(baseurl=target_url) or []
    except Exception as e:
        logger.warning("Failed to fetch alerts from ZAP: %s", e)
        alerts = []

    # Filter out informational alerts
    findings = []
    for alert in alerts:
        risk = alert.get("risk")
        if risk and risk.lower() != "informational":
            findings.append({
                "alert": alert.get("alert"),
                "risk": risk,
                "url": alert.get("url"),
                "param": alert.get("param"),
                "solution": alert.get("solution"),
                "owasp": OWASP_TOP10.get(alert.get("alert"), "Other")
            })

    # Onion links detected in discovered URLs
    onion_links = detect_onion_from_urls(urls)

    # Also attempt to fetch page directly (optional) to detect inline onion links if requested
    inline_onions = []
    if fetch_with_tor:
        try:
            text = fetch_via_requests(target_url, use_tor=True)
            inline_onions = list(set([m.lower() for m in ONION_RE.findall(text or "")]))
        except Exception as e:
            logger.warning("Direct fetch via Tor failed (non-fatal): %s", e)
    else:
        # Try a normal fetch (non-Tor); may reveal links
        try:
            text = fetch_via_requests(target_url, use_tor=False)
            inline_onions = list(set([m.lower() for m in ONION_RE.findall(text or "")]))
        except Exception:
            # ignore
            pass

    # Merge onion lists
    onion_links = sorted(set(onion_links) | set(inline_onions))

    result = {
        "target": target_url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "urls_discovered": len(urls),
        "onion_links": onion_links,
        "findings": findings,
        "vulnerabilities_count": len(findings)
    }

    # Save JSON report (unique filename). Use shutil.move if replacing/moving later.
    fname = make_unique_report_name()
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    logger.info("Scan finished. Report written to %s", fname)
    return result, fname
