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
from pathlib import Path
from typing import List, Dict, Optional

# --------------- Configuration ---------------

DATA_DIR = Path("data")
NVD_ZIP = DATA_DIR / "nvdcve-1.1-2025.json.zip"
NVD_RAW_JSON = DATA_DIR / "nvdcve-1.1-2025.json"
NVD_SUBSET = DATA_DIR / "nvd_subset.json"
KEV_JSON = DATA_DIR / "kev.json"

# Filter for these vendors/products
VENDOR_FILTERS = ["cisco", "microsoft", "adobe", "oracle", "tomcat", "mysql"]

# NVD feed URL for 2025
NVD_FEED_URL = (
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2025.json.zip"
)
# CISA KEV (Known-Exploited Vulnerabilities) JSON feed
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# --------------- Prep Functions ---------------

def download_nvd_feed() -> None:
    """Download the 2025 NVD CVE feed ZIP if not already present."""
    DATA_DIR.mkdir(exist_ok=True)
    if not NVD_ZIP.exists():
        print("Downloading NVD feed...")
        resp = requests.get(NVD_FEED_URL)
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
    resp = requests.get(KEV_FEED_URL)
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
        _KEV_INDEX = {
            entry["cveID"]: entry.get("dateAdded", "")
            for entry in kev_data
        }
    return _KEV_INDEX

def search_cves_by_software(vendor: str, product: str, version: Optional[str]=None) -> List[str]:
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
    return {
        "kev_listed": cve_id in kev,
        "date_added": kev.get(cve_id, None)
    }

# --------------- Main CLI ---------------

if __name__ == "__main__":
    # Simple CLI: run all prep steps
    download_nvd_feed()
    extract_nvd_json()
    filter_nvd_subset()
    download_kev_feed()
    print("Prep complete. You can now import search_cves_by_software, lookup_cve, enrich_with_kev.")
