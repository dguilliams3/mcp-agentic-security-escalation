import sys
import traceback
from typing import Dict, Any, List, Optional
from fastmcp import FastMCP
import json
from pathlib import Path
from utils.decorators import timing_metric, cache_result
from dotenv import load_dotenv
from utils.retriever import semantic_match_incident, search_text, initialize_embeddings, initialize_indexes

# Load environment variables
load_dotenv()

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
def match_incident_to_cves(incident_id: str, k: int = 5, use_mmr: bool = True) -> dict:
    """
    Given an incident_id, return top-k KEV and NVD candidate CVEs.
    """
    incident_resp = get_incident(incident_id)
    if not incident_resp.get("found"):
        return {"error": "incident not found", "incident_id": incident_id}

    inc = incident_resp["incident_data"]
    result = semantic_match_incident(
        inc,
        k_kev=k,
        k_nvd=k,
        use_mmr=use_mmr,      # pass through flag
    )
    # result already looks like {"kev_candidates":[{…}], "nvd_candidates":[{…}]}

    return {"incident_id": incident_id, **result}

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
def semantic_search_cves(
    query: str,
    sources: List[str] = ["kev", "nvd"],
    k: int = 5,
    use_mmr: bool = False,
    lambda_mult: float = 0.7
) -> Dict[str, Any]:
    """
    Agent-callable tool: run semantic similarity search over  
    KEV and/or NVD FAISS indexes using search_text().
    """
    out: Dict[str, Any] = {"query": query}
    if "kev" in sources:
        out["kev_candidates"] = search_text(
            query, KEV_FAISS, k=k, use_mmr=use_mmr, lambda_mult=lambda_mult
        )
    if "nvd" in sources:
        out["nvd_candidates"] = search_text(
            query, NVD_FAISS, k=k, use_mmr=use_mmr, lambda_mult=lambda_mult
        )
    return out

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
        "title": "Search KEV Entries (often to find the CVE ID and related information)",
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
    Return the entireKEV entry for the given CVE ID.
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
@cache_result(ttl_seconds=60)  # Cache incident list for 1 minute
def list_incident_ids(limit: Optional[int] = None) -> Dict[str, Any]:
    """Get a list of incident IDs, optionally limited to a specific count.
    Returns most recent first.
    
    Args:
        limit (Optional[int]): Maximum number of IDs to return
        
    Returns:
        Dict[str, Any]: Dictionary containing:
            - success: bool indicating if operation succeeded
            - incident_ids: List of incident IDs if successful
            - debug_info: Dictionary with diagnostic information
    """
    try:
        data_file = Path("data/incidents.json")
        debug_info = {
            "attempted_path": str(data_file.absolute()),
            "file_exists": data_file.exists(),
            "current_working_dir": str(Path.cwd())
        }
        
        with open(data_file, 'r') as f:
            incidents = json.load(f)
            
        incident_ids = [incident["incident_id"] for incident in incidents]
        incident_ids.sort(reverse=True)
        
        if limit and limit > 0:
            incident_ids = incident_ids[:limit]
            
        return {
            "success": True,
            "incident_ids": incident_ids,
            "debug_info": {
                **debug_info,
                "num_incidents_loaded": len(incidents)
            }
        }
    except FileNotFoundError:
        return {
            "success": False,
            "incident_ids": [],
            "debug_info": {
                **debug_info,
                "error": "File not found"
            }
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "incident_ids": [],
            "debug_info": {
                **debug_info,
                "error": f"JSON decode error\n{e}"
            }
        }
    except Exception as e:
        return {
            "success": False,
            "incident_ids": [],
            "debug_info": {
                **debug_info,
                "error": str(e)
            }
        }

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
def get_incident(incident_id: str) -> Dict[str, Any]:
    """Get full details of a specific incident.
    
    Args:
        incident_id (str): The ID of the incident to retrieve
        
    Returns:
        Dict[str, Any]: Incident data with metadata, or error information if not found
    """
    try:
        data_file = Path("data/incidents.json")
        with open(data_file, 'r') as f:
            incidents = json.load(f)
        
        # Find the specific incident
        incident = next((inc for inc in incidents if inc["incident_id"] == incident_id), None)
        
        if incident:
            return {
                "found": True,
                "incident_data": incident,
                "metadata": {
                    "timestamp": incident.get("timestamp"),
                    "num_affected_assets": len(incident.get("affected_assets", [])),
                    "num_ttps": len(incident.get("observed_ttps", [])),
                    "num_iocs": len(incident.get("indicators_of_compromise", []))
                }
            }
        else:
            return {
                "found": False,
                "error": "Incident not found",
                "incident_id": incident_id
            }
    except FileNotFoundError:
        return {
            "found": False,
            "error": "Incident database not found",
            "incident_id": incident_id
        }
    except Exception as e:
        return {
            "found": False,
            "error": str(e),
            "incident_id": incident_id
        }

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