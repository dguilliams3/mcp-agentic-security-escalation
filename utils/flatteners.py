"""
utils/flatteners.py
-------------------
Helpers to convert KEV & NVD JSON entries into
(langchain) Document objects ready for embedding.
"""

from pathlib import Path
from typing import List, Dict, Any
from langchain_core.documents import Document


# ----- KEV ---------------------------------------------------
def flatten_kev(entry: Dict[str, Any]) -> Document:
    """
    Turn one KEV vulnerability entry into a single text chunk
    with metadata preserved.
    """
    text_parts = [
        f"CVE {entry.get('cveID', '')}",
        entry.get("vendorProject", ""),
        entry.get("product", ""),
        entry.get("vulnerabilityName", ""),
        entry.get("shortDescription", ""),
        entry.get("notes", ""),
    ]
    page_content = "\n".join(filter(None, text_parts))

    metadata = {
        "source": "kev",
        "cve_id": entry.get("cveID"),
        "vendor": entry.get("vendorProject"),
        "product": entry.get("product"),
        "date_added": entry.get("dateAdded"),
        "ransomware_use": entry.get("knownRansomwareCampaignUse"),
        "cwes": entry.get("cwes", []),
    }
    return Document(page_content=page_content, metadata=metadata)


# ----- NVD ---------------------------------------------------
def flatten_nvd(item: Dict[str, Any]) -> Document:
    """
    Reduce one NVD CVE item to a readable text blob.
    """
    cve = item.get("cve", {})
    cve_id = cve.get("CVE_data_meta", {}).get("ID", "UNKNOWN")

    # safest-access for nested description
    desc_list = (
        cve.get("description", {})
        .get("description_data", [{}])
    )
    description = desc_list[0].get("value", "")

    references = " | ".join(
        ref.get("url", "")
        for ref in cve.get("references", {})
        .get("reference_data", [])
    )

    text_parts = [
        f"CVE {cve_id}",
        description,
        references,
    ]
    page_content = "\n".join(filter(None, text_parts))

    metadata = {
        "source": "nvd",
        "cve_id": cve_id,
        "published": item.get("publishedDate"),
        "last_modified": item.get("lastModifiedDate"),
    }
    return Document(page_content=page_content, metadata=metadata)
