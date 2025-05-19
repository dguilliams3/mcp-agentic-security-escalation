"""
utils/flatteners.py
-------------------
Helpers to convert KEV & NVD JSON entries into
(langchain) Document objects ready for embedding.
"""

from pathlib import Path
from typing import Dict, Any
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

def flatten_incident(incident: dict) -> str:
    """
    Convert one incident JSON object into a single text blob
    suitable for embedding.
    """
    lines = [
        incident.get("title", ""),
        incident.get("description", ""),
        incident.get("initial_findings", ""),
    ]

    # pull installed software
    for asset in incident.get("affected_assets", []):
        sw_parts = [
            f"{sw['name']} {sw.get('version','')}".strip()
            for sw in asset.get("installed_software", [])
        ]
        if sw_parts:
            lines.append("Software: " + ", ".join(sw_parts))

    # TTPs
    ttp_parts = [t["name"] for t in incident.get("observed_ttps", [])]
    if ttp_parts:
        lines.append("TTPs: " + ", ".join(ttp_parts))

    lines.append("TTP IDs: " + ", ".join(t["id"] for t in incident["observed_ttps"]))
    lines.append("OS: " + ", ".join(a["os"] for a in incident["affected_assets"]))
    for ioc in incident["indicators_of_compromise"]:
        if ioc["type"] in {"file_path","process_name","file_extension",
                        "library_name","container_id"}:
            lines.append(f"IOC: {ioc['value']}")

    return "\n".join(filter(None, lines))
