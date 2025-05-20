"""Setup utilities for the MCP CVE Analysis system.

This package provides setup and initialization utilities for the MCP CVE Analysis system,
including data download, processing, and vector index creation.

The package is organized into several modules:
- download_cve_data: CVE data download and processing utilities
- build_faiss_KEV_and_NVD_indexes: Vector index creation for KEV and NVD data
- build_historical_incident_index: Vector index creation for historical incidents

Example:
    Basic usage of the package::

        from setup import download_cve_data, build_faiss_KEV_and_NVD_indexes

        # Download and process CVE data
        download_cve_data.download_nvd_feed()
        download_cve_data.download_kev_feed()

        # Build vector indexes
        build_faiss_KEV_and_NVD_indexes.build_indexes()
"""

from .download_cve_data import (
    download_nvd_feed,
    extract_nvd_json,
    filter_nvd_subset,
    download_kev_feed,
    search_cves_by_software,
    lookup_cve,
    enrich_with_kev,
    create_session_with_retries,
    rate_limited_request,
)

from .build_faiss_KEV_and_NVD_indexes import build_kev_index, build_nvd_index, index_is_fresh

from .build_historical_incident_index import build_historical_index

# Public API documentation
__all__ = [
    # Data Download and Processing
    "download_nvd_feed",  # Download NVD CVE feed
    "extract_nvd_json",  # Extract NVD JSON from ZIP
    "filter_nvd_subset",  # Filter NVD data to relevant subset
    "download_kev_feed",  # Download CISA KEV feed
    "search_cves_by_software",  # Search CVEs by software fingerprint
    "lookup_cve",  # Look up full CVE record
    "enrich_with_kev",  # Enrich CVE with KEV information
    # Request Handling
    "create_session_with_retries",  # Create requests session with retry strategy
    "rate_limited_request",  # Make rate-limited HTTP requests
    # Index Building
    "build_kev_index",  # Build FAISS index for KEV data
    "build_nvd_index",  # Build FAISS index for NVD data
    "build_historical_index",  # Build FAISS index for historical incidents
    "index_is_fresh",  # Check if index needs rebuilding
]

# Type hints for better IDE support
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Dict, List, Optional
    from requests import Session, Response
