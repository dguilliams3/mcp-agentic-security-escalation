#!/usr/bin/env python3
"""
cve_tools.py

1) Prep step: download NVD feed (2025), filter to relevant vendors, write subset.
2) Prep step: download CISA KEV feed.
3) Runtime functions: search_cves_by_software, lookup_cve, enrich_with_kev.
"""

import json
import zipfile
import requests
import os
import time
from pathlib import Path
from typing import List, Dict, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --------------- Configuration ---------------

DATA_DIR = Path("data")
NVD_ZIP = DATA_DIR / "nvdcve-1.1-2025.json.zip"
NVD_RAW_JSON = DATA_DIR / "nvdcve-1.1-2025.json"
NVD_SUBSET = DATA_DIR / "nvd_subset.json"
KEV_JSON = DATA_DIR / "kev.json"
INCIDENTS_PATH = DATA_DIR / "incidents.json"
# Rate limiting configuration
RATE_LIMIT_WITH_KEY = 50 / 60  # 50 requests per minute
RATE_LIMIT_WITHOUT_KEY = 10 / 60  # 10 requests per minute
last_request_time = 0

# API key configuration
NIST_API_KEY = os.getenv("NIST_API_KEY", "")

# --------------- Request Handling ---------------


def create_session_with_retries() -> requests.Session:
    """Create a session with retry strategy."""
    session = requests.Session()
    retries = Retry(
        total=5,  # number of retries
        backoff_factor=1,  # will sleep for [1s, 2s, 4s, 8s, 16s]
        status_forcelist=[429, 500, 502, 503, 504],
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session


def rate_limited_request(url: str, **kwargs) -> requests.Response:
    """Make a rate-limited request with exponential backoff."""
    global last_request_time

    # Determine rate limit based on API key presence
    rate_limit = RATE_LIMIT_WITH_KEY if NIST_API_KEY else RATE_LIMIT_WITHOUT_KEY

    # Calculate time to wait
    now = time.time()
    time_since_last = now - last_request_time
    if time_since_last < 1 / rate_limit:
        sleep_time = 1 / rate_limit - time_since_last
        time.sleep(sleep_time)

    # Add API key to headers if available
    headers = kwargs.get("headers", {})
    if NIST_API_KEY:
        headers["apiKey"] = NIST_API_KEY
    kwargs["headers"] = headers

    # Make request with session
    session = create_session_with_retries()
    response = session.get(url, **kwargs)
    last_request_time = time.time()

    return response


# --------------- Vendor Filter Extraction ---------------
def extract_vendor_filters() -> list[str]:
    """Read all installed_software names from incidents and return lowercase tokens."""
    incidents = json.loads(INCIDENTS_PATH.read_text())
    filters = set()
    for inc in incidents:
        for asset in inc.get("affected_assets", []):
            for sw in asset.get("installed_software", []):
                # Option 1: take the full name
                filters.add(sw["name"].lower())
                # Option 2: split vendor and product
                vendor = sw["name"].split()[0].lower()
                filters.add(vendor)
    return sorted(filters)


VENDOR_FILTERS = extract_vendor_filters()
print("Using vendor filters:", VENDOR_FILTERS)

# NVD feed URL for 2025
NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2025.json.zip"
# CISA KEV (Known-Exploited Vulnerabilities) JSON feed
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# --------------- Prep Functions ---------------


def download_nvd_feed() -> None:
    """Download the 2025 NVD CVE feed ZIP if not already present."""
    DATA_DIR.mkdir(exist_ok=True)
    if not NVD_ZIP.exists():
        print("Downloading NVD feed...")
        resp = rate_limited_request(NVD_FEED_URL)
        resp.raise_for_status()
        NVD_ZIP.write_bytes(resp.content)
        print("Downloaded NVD feed.")
    else:
        print("NVD ZIP already present.")


def extract_nvd_json() -> None:
    """Extract the JSON file from the downloaded ZIP."""
    if not NVD_RAW_JSON.exists():
        print("Extracting NVD JSON from ZIP...")
        with zipfile.ZipFile(NVD_ZIP, "r") as z:
            # assume the JSON is the first entry
            name = next(n for n in z.namelist() if n.endswith(".json"))
            with z.open(name) as src, open(NVD_RAW_JSON, "wb") as dst:
                dst.write(src.read())
        print("Extraction complete.")
    else:
        print("Raw NVD JSON already present.")


def filter_nvd_subset() -> None:
    """
    Filter the raw NVD JSON to only CVEs whose description or CPE configs
    mention any of the VENDOR_FILTERS. Write to NVD_SUBSET.
    """
    print("Loading raw NVD JSON...")
    with open(NVD_RAW_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)
    items = data.get("CVE_Items", [])
    print(f"Total CVE items: {len(items)}")

    subset: Dict[str, dict] = {}
    for item in items:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        desc = item["cve"]["description"]["description_data"][0]["value"].lower()
        combined = desc + " " + " ".join(VENDOR_FILTERS)
        if any(v in desc for v in VENDOR_FILTERS):
            subset[cve_id] = item

    print(f"Filtered down to {len(subset)} CVEs. Saving subset...")
    with open(NVD_SUBSET, "w", encoding="utf-8") as f:
        json.dump(subset, f, indent=2)
    print(f"Wrote subset to {NVD_SUBSET}")


def download_kev_feed() -> None:
    """Download the CISA KEV JSON feed."""
    print("Downloading KEV feed...")
    resp = rate_limited_request(KEV_FEED_URL)
    resp.raise_for_status()
    DATA_DIR.mkdir(exist_ok=True)
    KEV_JSON.write_bytes(resp.content)
    print(f"Wrote KEV data to {KEV_JSON}")


# --------------- Runtime Utility Functions ---------------

# Lazy-load caches
_NVD_INDEX: Optional[Dict[str, dict]] = None
_KEV_INDEX: Optional[Dict[str, str]] = None


def _load_nvd_index() -> Dict[str, dict]:
    global _NVD_INDEX
    if _NVD_INDEX is None:
        print("Loading NVD subset into memory...")
        with open(NVD_SUBSET, "r", encoding="utf-8") as f:
            _NVD_INDEX = json.load(f)
    return _NVD_INDEX


def _load_kev_index() -> Dict[str, str]:
    global _KEV_INDEX
    if _KEV_INDEX is None:
        print("Loading KEV list into memory...")
        kev_data = json.load(open(KEV_JSON, "r", encoding="utf-8"))
        # KEV feed may be list of entries with "cveID" and "dateAdded"
        _KEV_INDEX = {entry["cveID"]: entry.get("dateAdded", "") for entry in kev_data}
    return _KEV_INDEX


def search_cves_by_software(vendor: str, product: str, version: Optional[str] = None) -> List[str]:
    """
    Return CVE IDs matching the given software fingerprints.
    Simple substring match in description. Caps result to 25.
    """
    idx = _load_nvd_index()
    key = f"{vendor.lower()} {product.lower()}"
    results = []
    for cve_id, rec in idx.items():
        desc = rec["cve"]["description"]["description_data"][0]["value"].lower()
        if key in desc and (version is None or version.lower() in desc):
            results.append(cve_id)
            if len(results) >= 25:
                break
    return results


def lookup_cve(cve_id: str) -> dict:
    """
    Return the full CVE record dict for a CVE ID, or an error dict.
    """
    idx = _load_nvd_index()
    return idx.get(cve_id, {"id": cve_id, "error": "not found in subset"})


def enrich_with_kev(cve_id: str) -> dict:
    """
    Return whether the CVE is on CISA's Known-Exploited Vulnerabilities list,
    plus the date it was added.
    """
    kev = _load_kev_index()
    return {"kev_listed": cve_id in kev, "date_added": kev.get(cve_id, None)}


# --------------- Main CLI ---------------

if __name__ == "__main__":
    # Simple CLI: run all prep steps
    download_nvd_feed()
    extract_nvd_json()
    filter_nvd_subset()
    download_kev_feed()
    print("Prep complete. You can now import search_cves_by_software, lookup_cve, enrich_with_kev.")
