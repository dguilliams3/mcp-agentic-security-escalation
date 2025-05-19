import sys
import traceback
from typing import Dict, Any, List, Optional
from fastmcp import FastMCP
import json
from pathlib import Path
from utils.decorators import timing_metric, cache_result
from dotenv import load_dotenv
from utils.retrieval_utils import (
    initialize_embeddings,
    initialize_indexes,
    match_incident_to_cves,
    semantic_match_incident,
    semantic_search_cves,
    list_incident_ids,
    get_incident
)

from utils.logging_utils import setup_logger
# Load environment variables
load_dotenv()
logger = setup_logger()

from pathlib import Path
BASE_DIR = Path(__file__).parent               # absolute directory of this file
DATA_DIR = BASE_DIR / "data"

KEV_ENTRIES = json.loads((DATA_DIR / "kev.json").read_text())["vulnerabilities"]
NVD_INDEX   = json.loads((DATA_DIR / "nvd_subset.json").read_text())

KEV_FAISS = None
NVD_FAISS = None
embeddings = None

initialize_embeddings()
initialize_indexes()

mcp = FastMCP("cve")

########################################################
############## CVE MANAGEMENT TOOLS ####################
########################################################


@mcp.tool(annotations={
    "title": "Match Incident to CVEs using semantic search",
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False
})
@timing_metric
@cache_result(ttl_seconds=30)   # cache identical incident queries for 30s
def match_incident_to_cves_tool(incident_id: str, k: int = 5, use_mmr: bool = True) -> dict:
    return match_incident_to_cves(incident_id, k, use_mmr)

def semantic_match_incident_tool(incident_id: str, k: int = 5, use_mmr: bool = True) -> dict:
    return semantic_match_incident(incident_id, k, use_mmr)

@mcp.tool(
  annotations={
    "title": "Semantic Free-Form CVE Search",
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False
  }
)
@timing_metric
@cache_result(ttl_seconds=30)   # cache identical free-form queries
def semantic_search_cves_tool(    query: str,
    sources: List[str] = ["kev", "nvd", "historical"],
    k: int = 5,
    use_mmr: bool = False,
    lambda_mult: float = 0.7
) -> Dict[str, Any]:
    return semantic_search_cves(query, sources, k, use_mmr, lambda_mult)

@mcp.tool(annotations={
    "title": "Search NVD Entries (often to find the CVE ID and related information) for a specific match for ALL words in the query",
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False
}   )
@timing_metric
@cache_result(ttl_seconds=30)   # cache identical free-form queries
def search_nvd(query: str, limit: int = 10) -> list[dict]:
    """
    Return up to `limit` full CVE records whose fields match ALL words in `query`.
    Case-insensitive substring match over CVE ID, description, and any reference URLs.
    """
    qwords = query.lower().split()
    matches = []
    for cve_id, rec in NVD_INDEX.items():
        # flatten searchable text
        desc = rec.get("cve", {}) \
                  .get("description", {}) \
                  .get("description_data", [{}])[0] \
                  .get("value", "")
        refs = " ".join([r.get("url","") for r in rec.get("cve",{}) \
                                          .get("references",{}) \
                                          .get("reference_data",[])])
        text = f"{cve_id} {desc} {refs}".lower()
        if all(w in text for w in qwords):
            # return the full record so the agent can inspect any fields
            matches.append(rec)
            if len(matches) >= limit:
                break
    return matches


@mcp.tool(
    annotations={
        "title": "Search KEV Entries (Return up to `limit` KEV entries whose fields match ALL words in `query`)",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
@timing_metric
@cache_result(ttl_seconds=30)   # cache identical free-form queries
def search_kevs(query: str, limit: int = 10) -> list[dict]:
    """
    Return up to `limit` KEV entries whose fields match ALL words in `query`.
    Case-insensitive substring match over cveID, vendorProject, product,
    vulnerabilityName, and shortDescription.
    """
    qwords = query.lower().split()
    matches = []
    for entry in KEV_ENTRIES:
        combined = " ".join([
            entry.get("cveID", ""),
            entry.get("vendorProject", ""),
            entry.get("product", ""),
            entry.get("vulnerabilityName", ""),
            entry.get("shortDescription", "")
        ]).lower()
        if all(w in combined for w in qwords):
            matches.append(entry)
            if len(matches) >= limit:
                break
    return matches

@mcp.tool(annotations={
    "title": "Lookup KEV Entry by CVE ID",
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False
}   )
@timing_metric
def lookup_kev_by_cve_id(cve_id: str) -> dict:
    """
    Return the entire KEV entry for the given CVE ID.
    """
    for entry in KEV_ENTRIES:
        if entry.get("cveID") == cve_id:
            return entry
    return None

########################################################
############## GENERAL TOOLS ###########################
########################################################
@mcp.tool(
    annotations={
        "title": "Test Server Connection",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
@timing_metric
def test_server() -> str:
    """Test if the server is running and responsive.

    Returns:
        str: A message indicating the server is running
    """
    return "Server is running"

@mcp.tool(
    annotations={
        "title": "Get Server Time",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
@timing_metric
async def get_current_time() -> str:
    """Get the current server time in ISO 8601 format.

    Returns:
        str: Current timestamp in ISO 8601 format (e.g., "2023-08-15T10:30:00.000Z")
    """
    from datetime import datetime
    return datetime.now().isoformat()

@mcp.tool(
    annotations={
        "title": "Get System Information",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
@timing_metric
@cache_result(ttl_seconds=300)  # Cache system info for 5 minutes
async def get_system_info() -> Dict[str, Any]:
    """Get basic system information about the server environment.

    Returns:
        Dict[str, Any]: Dictionary containing:
            - system: Operating system name
            - version: OS version
            - machine: Machine architecture
            - python_version: Python runtime version
    """
    import platform
    return {
        "system": platform.system(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python_version": platform.python_version()
    }


########################################################
############## INCIDENT MANAGEMENT TOOLS ###############
########################################################


@mcp.tool(
    annotations={
        "title": "List Incident IDs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
@timing_metric
@cache_result(ttl_seconds=300)  # Cache incident list for 5 minutes
def list_incident_ids_tool(limit: Optional[int] = None, start_index: Optional[int] = 0) -> Dict[str, Any]:
    return list_incident_ids(limit, start_index)

@mcp.tool(
    annotations={
        "title": "Get Incident Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
@timing_metric
@cache_result(ttl_seconds=60)  # Cache incident details for 1 minute
def get_incident_tool(incident_id: str) -> Dict[str, Any]:
    return get_incident(incident_id)

@mcp.tool(
    annotations={
        "title": "Get Incident Schema",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
@timing_metric
@cache_result(ttl_seconds=300)  # Cache schema for 5 minutes
def get_incident_schema() -> Dict[str, Any]:
    """Get the schema definition for incident data.

    Returns:
        Dict[str, Any]: Static schema definition of the incident data structure
    """
    return {
        "type": "object",
        "properties": {
            "incident_id": {"type": "string", "description": "Unique identifier for the incident"},
            "timestamp": {"type": "string", "format": "date-time", "description": "When the incident occurred"},
            "title": {"type": "string", "description": "Brief title of the incident"},
            "description": {"type": "string", "description": "Detailed description of the incident"},
            "affected_assets": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "hostname": {"type": "string"},
                        "ip_address": {"type": "string"},
                        "os": {"type": "string"},
                        "installed_software": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "version": {"type": "string"}
                                }
                            }
                        },
                        "role": {"type": "string"}
                    }
                }
            },
            "observed_ttps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "framework": {"type": "string"},
                        "id": {"type": "string"},
                        "name": {"type": "string"}
                    }
                }
            },
            "indicators_of_compromise": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string"},
                        "value": {"type": "string"},
                        "context": {"type": "string"}
                    }
                }
            },
            "initial_findings": {"type": "string", "description": "Initial analysis and findings"}
        },
        "required": ["incident_id", "timestamp", "title", "description"]
    }

@mcp.tool(
    annotations={
        "title": "Get NVD Schema",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
@timing_metric
@cache_result(ttl_seconds=300)
def get_nvd_schema() -> Dict[str, Any]:
    """Return the nested schema for entries in the NVD (National Vulnerability Database) JSON file."""
    return {
        "type": "object",
        "properties": {
            "cve": {
                "type": "object",
                "properties": {
                    "data_type": {"type": "string"},
                    "data_format": {"type": "string"},
                    "data_version": {"type": "string"},
                    "CVE_data_meta": {
                        "type": "object",
                        "properties": {
                            "ID": {"type": "string"},
                            "ASSIGNER": {"type": "string"}
                        }
                    },
                    "problemtype": {
                        "type": "object",
                        "properties": {
                            "problemtype_data": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "description": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "lang": {"type": "string"},
                                                    "value": {"type": "string"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "references": {
                        "type": "object",
                        "properties": {
                            "reference_data": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "url": {"type": "string"},
                                        "name": {"type": "string"},
                                        "refsource": {"type": "string"},
                                        "tags": {
                                            "type": "array",
                                            "items": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "description": {
                        "type": "object",
                        "properties": {
                            "description_data": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "lang": {"type": "string"},
                                        "value": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "configurations": {
                "type": "object",
                "properties": {
                    "CVE_data_version": {"type": "string"},
                    "nodes": {"type": "array"}
                }
            },
            "impact": {"type": "object"},
            "publishedDate": {"type": "string"},
            "lastModifiedDate": {"type": "string"}
        }
    }

@mcp.tool(
    annotations={
        "title": "Get KEV Schema",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False
    }
)
@timing_metric
@cache_result(ttl_seconds=300)
def get_kev_schema() -> Dict[str, Any]:
    """Return the nested schema for entries in the KEV (Known Exploited Vulnerabilities) JSON file."""
    return {
        "type": "object",
        "properties": {
            "cveID": {"type": "string"},
            "vendorProject": {"type": "string"},
            "product": {"type": "string"},
            "vulnerabilityName": {"type": "string"},
            "dateAdded": {"type": "string"},
            "shortDescription": {"type": "string"},
            "requiredAction": {"type": "string"},
            "dueDate": {"type": "string"},
            "knownRansomwareCampaignUse": {"type": "string"},
            "notes": {"type": "string"},
            "cwes": {
                "type": "array",
                "items": {"type": "string"}
            }
        }
    }


########################################################
############## MAIN #####################################
########################################################
if __name__ == "__main__":
    mcp.run(transport="stdio")          # ← KEY CHANGE