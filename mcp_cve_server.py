import requests
from typing import Dict, Any, List, Optional
from pandas import DataFrame
from fastmcp import FastMCP
import json
from pathlib import Path
from mcp.server.lowlevel import NotificationOptions

mcp = FastMCP("cve")

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
############## SECURITY TOOLS ##########################
########################################################
@mcp.tool(
    annotations={
        "title": "Fetch CVE Data",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True
    }
)
def fetch_cve_data(cve_id: str) -> Dict[str, Any]:
    """Fetch CVE data from the National Vulnerability Database (NVD) API.
    
    Args:
        cve_id (str): The CVE identifier to fetch (e.g., "CVE-2023-1234")
    
    Returns:
        Dict[str, Any]: Dictionary containing:
            - success: bool indicating if the fetch was successful
            - data: CVE data if successful, including:
                - id: CVE ID
                - description: CVE description
                - severity: CVSS severity scores
                - references: Related references
                - published: Publication date
                - last_modified: Last modification date
            - error: Error message if not successful
    """
    try:
        # First try to load from our local NVD cache
        nvd_file = Path("data/nvd_subset.json")
        if nvd_file.exists():
            with open(nvd_file, 'r') as f:
                nvd_data = json.load(f)
                if cve_id in nvd_data:
                    cve = nvd_data[cve_id]
                    return {
                        "success": True,
                        "data": {
                            "id": cve_id,
                            "description": cve.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "No description available"),
                            "severity": {
                                "v3": cve.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}),
                                "v2": cve.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {})
                            },
                            "references": cve.get("cve", {}).get("references", {}).get("reference_data", []),
                            "published": cve.get("publishedDate"),
                            "last_modified": cve.get("lastModifiedDate")
                        }
                    }
        
        # If not found in NVD cache, try the KEV database
        kev_file = Path("data/kev.json")
        if kev_file.exists():
            with open(kev_file, 'r') as f:
                kev_data = json.load(f)
                for vuln in kev_data.get("vulnerabilities", []):
                    if vuln.get("cveID") == cve_id:
                        return {
                            "success": True,
                            "data": {
                                "id": vuln.get("cveID"),
                                "description": vuln.get("shortDescription"),
                                "severity": "HIGH - Known Exploited Vulnerability",
                                "vendor_info": vuln.get("vendorProject"),
                                "product": vuln.get("product"),
                                "vulnerability_name": vuln.get("vulnerabilityName"),
                                "date_added": vuln.get("dateAdded"),
                                "due_date": vuln.get("dueDate"),
                                "known_ransomware_use": vuln.get("knownRansomwareCampaignUse"),
                                "cwes": vuln.get("cwes", [])
                            }
                        }
        
        return {
            "success": False,
            "error": f"CVE {cve_id} not found in local database",
            "note": "To fetch from NVD API directly, an API key is required"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Error fetching CVE data: {str(e)}"
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
        "title": "Search Incidents",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False
    }
)
def search_incidents(query: str, limit: Optional[int] = None) -> Dict[str, Any]:
    """Search incidents by any field.
    Performs a case-insensitive search across all text fields in the incidents.
    
    Args:
        query (str): Search query string
        limit (Optional[int]): Maximum number of results to return
        
    Returns:
        Dict[str, Any]: Search results with metadata
    """
    try:
        data_file = Path("data/incidents.json")
        with open(data_file, 'r') as f:
            incidents = json.load(f)
        
        query = query.lower()
        matches = []
        
        for incident in incidents:
            # Search in title and description
            if query in incident.get("title", "").lower() or \
               query in incident.get("description", "").lower():
                matches.append(incident)
                continue
            
            # Search in affected assets
            for asset in incident.get("affected_assets", []):
                if query in str(asset).lower():
                    matches.append(incident)
                    break
            
            # Search in TTPs
            for ttp in incident.get("observed_ttps", []):
                if query in str(ttp).lower():
                    matches.append(incident)
                    break
            
            # Search in IOCs
            for ioc in incident.get("indicators_of_compromise", []):
                if query in str(ioc).lower():
                    matches.append(incident)
                    break
        
        # Apply limit if specified
        if limit and limit > 0:
            matches = matches[:limit]
        
        return {
            "metadata": {
                "query": query,
                "total_matches": len(matches),
                "limit_applied": limit if limit else None
            },
            "results": matches
        }
        
    except FileNotFoundError:
        return {
            "metadata": {
                "query": query,
                "error": "Incident database not found"
            },
            "results": []
        }
    except Exception as e:
        return {
            "metadata": {
                "query": query,
                "error": str(e)
            },
            "results": []
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
def get_incident_schema() -> Dict[str, Any]:
    """Get the schema definition for incident data.
    
    Returns:
        Dict[str, Any]: Static schema definition of the incident data structure
    """
    # Original dynamic schema implementation
    # try:
    #     data_file = Path("data/Synthetic incident dataset.json")
    #     with open(data_file, 'r') as f:
    #         incidents = json.load(f)
    #         
    #     if not incidents:
    #         return {
    #             "error": "No incidents found in dataset",
    #             "schema": None
    #         }
    #         
    #     def get_type(value: Any) -> str:
    #         if isinstance(value, str):
    #             return "string"
    #         elif isinstance(value, bool):
    #             return "boolean"
    #         elif isinstance(value, int):
    #             return "integer"
    #         elif isinstance(value, float):
    #             return "number"
    #         elif isinstance(value, list):
    #             return "array"
    #         elif isinstance(value, dict):
    #             return "object"
    #         else:
    #             return "unknown"
    #     
    #     def analyze_object(obj: Dict) -> Dict[str, Any]:
    #         schema = {"type": "object", "properties": {}}
    #         for key, value in obj.items():
    #             if isinstance(value, dict):
    #                 schema["properties"][key] = analyze_object(value)
    #             elif isinstance(value, list) and value:
    #                 if isinstance(value[0], dict):
    #                     schema["properties"][key] = {
    #                         "type": "array",
    #                         "items": analyze_object(value[0])
    #                     }
    #                 else:
    #                     schema["properties"][key] = {
    #                         "type": "array",
    #                         "items": {"type": get_type(value[0])}
    #                     }
    #             else:
    #                 schema["properties"][key] = {"type": get_type(value)}
    #         return schema
    #     
    #     return analyze_object(incidents[0])
    # except Exception as e:
    #     return {"error": str(e), "schema": None}

    # Static schema implementation
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

########################################################
############## MAIN #####################################
########################################################
if __name__ == "__main__":
    print("Starting CVE MCP Server...")
    mcp.run()