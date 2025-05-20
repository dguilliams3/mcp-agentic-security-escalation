# utils/retrieval_utils.py  (patched)
import json
import logging, os
from pathlib import Path
from typing import Any, Dict, List, Optional
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from utils.datastore_utils import get_incident_analyses_from_database
from utils.decorators import cache_result, timing_metric
from utils.flatteners import flatten_incident
from utils.logging_utils import setup_logger
from langchain.schema import Document
from typing import Any, Dict, List
import asyncio
from datetime import datetime, UTC
import msvcrt  # Windows-specific file locking

BASE_DIR = Path(__file__).parent.parent        # utils/ ➜ project root
DATA_DIR = BASE_DIR / "data" / "vectorstore"
KEV_FAISS = None
NVD_FAISS = None
INCIDENT_HISTORY_FAISS = None
embeddings = None
faiss_write_lock = asyncio.Lock()
file_locks = {}  # Dictionary to store file locks

logger = setup_logger("retrieval_utils")
# =========================================================================
# INITIALIZATION AND EMBEDDING FUNCTIONS
# =========================================================================
# These functions handle the initialization of embeddings and vector indexes
# for semantic search across vulnerability databases

@timing_metric
def initialize_openai_embeddings():
    """
    Initialize the global OpenAI embeddings object for vector representations.

    This function creates a global embeddings instance using OpenAIEmbeddings,
    which will be used for converting text to vector representations across
    the semantic search functionality.

    The function is decorated with @timing_metric to track potential initialization cost.

    Note:
        - This function sets a global 'embeddings' variable
        - It suppresses verbose logging from the OpenAI embeddings initialization
        - Should be called before any embedding or search operations
        - Uses OpenAI's embedding model for vector representations

    Raises:
        Any exceptions that might occur during OpenAI embeddings initialization
    """
    logging.getLogger("openai").setLevel(logging.ERROR)  # suppress verbose init
    global embeddings
    logger.info("Initializing OpenAI embeddings...")
    embeddings = OpenAIEmbeddings()
    logger.info("OpenAI embeddings initialized!")

@timing_metric
def initialize_faiss_indexes():
    """
    Initialize global FAISS vector indexes for different vulnerability databases.

    This function loads local FAISS vector stores for:
    - KEV (Known Exploited Vulnerabilities)
    - NVD (National Vulnerability Database)
    - Incident Analysis History

    The function ensures that:
    - OpenAI embeddings are initialized if not already done
    - FAISS indexes are loaded from local storage
    - Dangerous deserialization is allowed for loading pre-built indexes

    Note:
        - Sets global variables: KEV_FAISS, NVD_FAISS, INCIDENT_HISTORY_FAISS
        - Requires OpenAI embeddings to be initialized first
        - Uses local vector store files in the 'data/vectorstore' directory
        - Uses FAISS for efficient similarity search

    Raises:
        Various exceptions if FAISS index loading fails
    """
    global KEV_FAISS, NVD_FAISS, INCIDENT_HISTORY_FAISS
    if embeddings is None:
        initialize_openai_embeddings()

    logger.info("Loading KEV FAISS index...")
    KEV_FAISS = FAISS.load_local(DATA_DIR / "kev", embeddings,
                              allow_dangerous_deserialization=True)
    logger.info("KEV FAISS index loaded!")
    logger.info("Loading NVD FAISS index...")
    NVD_FAISS = FAISS.load_local(DATA_DIR / "nvd", embeddings,
                              allow_dangerous_deserialization=True)
    logger.info("NVD FAISS index loaded!")
    logger.info("Loading Incident Analysis History FAISS index...")
    INCIDENT_HISTORY_FAISS = FAISS.load_local(DATA_DIR / "incident_analysis_history", embeddings,
                               allow_dangerous_deserialization=True)
    logger.info("Incident Analysis History FAISS index loaded!")
# =========================================================================
# CORE SEARCH UTILITY FUNCTIONS
# =========================================================================
# Provide low-level search capabilities using FAISS vector stores

@timing_metric
def _search(
    store: FAISS,
    query: str,
    k: int = 5,
    use_mmr: bool = True,
    lambda_mult: float = 0.7,
    fetch_k: int = None
) -> List[Dict]:
    """
    Perform a semantic search on a given FAISS vector store.

    This is a core search method that supports both standard similarity
    search and Maximal Marginal Relevance (MMR) search strategies.

    Args:
        store (FAISS): The FAISS vector store to search
        query (str): The search query string
        k (int, optional): Number of top results to return. Defaults to 5.
        use_mmr (bool, optional): Use Maximal Marginal Relevance for
            more diverse results. Defaults to True.
        lambda_mult (float, optional): Diversity control for MMR search.
            Higher values prioritize relevance, lower values prioritize diversity.
            Defaults to 0.7.
        fetch_k (int, optional): Number of documents to fetch before filtering
            for MMR. If None, defaults to 2*k. Defaults to None.

    Returns:
        List[Dict]: A list of search results, each containing:
            - Metadata from the original document
            - Similarity score
            - Preview of the document content

    Note:
        - Ensures embeddings are initialized
        - Supports both vector-based and text-based similarity search
        - Handles Maximal Marginal Relevance search for result diversity

    Raises:
        Various exceptions related to embedding or search operations
    """
    if embeddings is None:
        initialize_openai_embeddings()

    if use_mmr:
        # embed the query once
        vec = embeddings.embed_query(query)
        # if fetch_k not provided, default to 2*k
        fk = fetch_k or (2 * k)
        # call the vector-based MMR-with-scores method
        pairs = store.max_marginal_relevance_search_with_score_by_vector(
            vec,
            k=k,
            fetch_k=fk,
            lambda_mult=lambda_mult,
        )
    else:
        # direct text-based similarity search (score included)
        pairs = store.similarity_search_with_score(query, k=k)

    out: List[Dict] = []
    for doc, score in pairs:
        meta = doc.metadata.copy()
        meta["variance"] = float(score)
        # Remove newlines, replace multiple spaces with single space, and truncate
        meta["preview"] = ' '.join(doc.page_content.replace('\n', ' ').split())[:120]
        out.append(meta)

    return out

def search_text(
    text: str,
    store: FAISS,
    k: int = 5,
    use_mmr: bool = False,
    lambda_mult: float = 0.7,
) -> List[Dict]:
    """
    Perform a semantic text search on a given FAISS vector store.

    This function provides a simplified interface for searching a FAISS
    vector store using a text query, with optional Maximal Marginal
    Relevance (MMR) search.

    Args:
        text (str): The search query text
        store (FAISS): The FAISS vector store to search
        k (int, optional): Number of top results to return. Defaults to 5.
        use_mmr (bool, optional): Use Maximal Marginal Relevance for
            more diverse results. Defaults to False.
        lambda_mult (float, optional): Diversity control for MMR search.
            Higher values prioritize relevance, lower values prioritize diversity.
            Defaults to 0.7.

    Returns:
        List[Dict]: A list of search results, each containing:
            - Metadata from the matched documents
            - Similarity scores

    Note:
        - Wraps the internal _search method
        - Provides a more generic search interface
        - Useful for searching across different FAISS indexes

    Example:
        results = search_text("security vulnerability", KEV_FAISS)
    """
    # embed the query
    if embeddings is None:
        initialize_openai_embeddings()
    query_vec = embeddings.embed_query(text)

    if use_mmr:
        # MMR path: pull doc+score
        hits = store.max_marginal_relevance_search_with_score_by_vector(
            query_vec,
            k=k,
            fetch_k=2*k,
            lambda_mult=lambda_mult,
        )
    else:
        # regular similarity
        hits = store.similarity_search_with_score(text, k=k)

    out = []
    for doc, score in hits:
        m = doc.metadata.copy()
        m["variance"] = score
        out.append(m)
    return out

# =========================================================================
# INCIDENT RETRIEVAL AND MANAGEMENT FUNCTIONS
# =========================================================================
# Handle retrieving and listing incident data

def list_incident_ids(limit: Optional[int] = None, start_index: Optional[int] = 0) -> Dict[str, Any]:
    """Get a list of incident IDs, optionally limited to a specific count and starting index.
    Returns most recent first.

    Args:
        limit (Optional[int]): Maximum number of IDs to return
        start_index (Optional[int]): Starting index for the returned incidents (default 0)

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

        # Handle start_index bounds
        start_index = max(0, min(start_index, len(incident_ids)))

        # If limit specified, return that many incidents from start_index
        if limit and limit > 0:
            incident_ids = incident_ids[start_index:start_index + limit]
        else:
            # Otherwise return all incidents from start_index
            incident_ids = incident_ids[start_index:]

        return {
            "success": True,
            "incident_ids": incident_ids,
            "debug_info": {
                **debug_info,
                "num_incidents_loaded": len(incidents),
                "start_index": start_index,
                "num_incidents_returned": len(incident_ids)
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

# =========================================================================
# SEMANTIC MATCHING FUNCTIONS
# =========================================================================
# Perform semantic matching of incidents against vulnerability databases

@timing_metric
def semantic_match_incident(
    incident: dict,
    k_kev: int = 5,
    k_nvd: int = 5,
    kev_threshold: float = 0.3,
    use_mmr: bool = False,
    lambda_mult: float = 0.7,
) -> dict:
    """
    Comprehensive semantic matching of an incident across KEV and NVD databases.

    This function performs a two-stage semantic search:
    1. Search the Known Exploited Vulnerabilities (KEV) database
    2. Conditionally search the National Vulnerability Database (NVD)

    The NVD search is only performed if the KEV match score is above a specified threshold.

    Args:
        incident (dict): The incident data to match against vulnerability databases
        k_kev (int, optional): Number of top KEV matches to return. Defaults to 5.
        k_nvd (int, optional): Number of top NVD matches to return. Defaults to 5.
        kev_threshold (float, optional): Minimum similarity score to trigger NVD search.
            Defaults to 0.3.
        use_mmr (bool, optional): Use Maximal Marginal Relevance for
            more diverse results. Defaults to False.
        lambda_mult (float, optional): Diversity control for MMR search.
            Higher values prioritize relevance, lower values prioritize diversity.
            Defaults to 0.7.

    Returns:
        dict: A dictionary containing:
            - 'kev_candidates': Top matches from KEV database
            - 'nvd_candidates': Top matches from NVD database (if KEV threshold met)

    Note:
        - Logs detailed information about the matching process
        - Supports conditional NVD searching based on KEV match quality
        - Uses separate search functions for KEV and NVD databases

    Example:
        matches = semantic_match_incident(incident_data, k_kev=3, k_nvd=3)
    """
    logger.info(f"Matching incident against KEV/NVD databases. KEV k={k_kev}, NVD k={k_nvd}")
    logger.debug(f"Incident details: {incident}")

    # First search KEV database
    kev_hits = semantic_match_incident_kev(incident, k_kev, use_mmr, lambda_mult)
    lowest_kev_variance = kev_hits[0]["variance"] if kev_hits else 1.0

    logger.info(f"Lowest KEV variance: {lowest_kev_variance:.3f}")

    # Only search NVD if KEV results aren't strong enough
    if lowest_kev_variance < kev_threshold:
        logger.info(f"KEV variance {lowest_kev_variance:.3f} below threshold {kev_threshold}, skipping NVD search")
        nvd_hits = [f"Kev varaince of {lowest_kev_variance} is satisfactory enough to skip searching NVD"]
    else:
        logger.info("KEV score above threshold, searching NVD database")
        nvd_hits = semantic_match_incident_nvd(incident, k_nvd, use_mmr, lambda_mult)

    return {"kev_candidates": kev_hits, "nvd_candidates": nvd_hits}

@timing_metric
def semantic_match_incident_kev(
    incident: dict,
    k: int = 5,
    use_mmr: bool = False,
    lambda_mult: float = 0.7,
) -> List[Dict]:
    """
    Perform semantic matching of an incident against the Known Exploited
    Vulnerabilities (KEV) database.

    This function converts an incident into a searchable text representation
    and finds the most semantically similar entries in the KEV database.

    Args:
        incident (dict): The incident data to match against KEV database
        k (int, optional): Number of top matches to return. Defaults to 5.
        use_mmr (bool, optional): Use Maximal Marginal Relevance for
            more diverse results. Defaults to False.
        lambda_mult (float, optional): Diversity control for MMR search.
            Higher values prioritize relevance, lower values prioritize diversity.
            Defaults to 0.7.

    Returns:
        List[Dict]: A list of top KEV matches, each containing:
            - Metadata about the matched vulnerability
            - Similarity score
            - Preview of the matched content

    Note:
        - Initializes KEV index if not already done
        - Uses flatten_incident() to convert incident to searchable text
        - Supports both standard similarity and MMR search strategies

    Example:
        kev_matches = semantic_match_incident_kev(incident_data)
    """
    logger.debug(f"Flattening incident text for KEV search")
    query_text = flatten_incident(incident)

    # Initialize indexes if needed
    if KEV_FAISS is None:
        logger.info("KEV index not initialized, initializing now")
        initialize_faiss_indexes()

    logger.debug(f"Searching KEV index with k={k}, MMR={use_mmr}")
    kev_hits = _search(KEV_FAISS, query_text, k, use_mmr, lambda_mult)
    logger.info(f"Found {len(kev_hits)} KEV matches")

    return kev_hits

@timing_metric
def semantic_match_incident_nvd(
    incident: dict,
    k: int = 5,
    use_mmr: bool = False,
    lambda_mult: float = 0.7,
) -> List[Dict]:
    """
    Perform semantic matching of an incident against the National
    Vulnerability Database (NVD).

    This function converts an incident into a searchable text representation
    and finds the most semantically similar entries in the NVD database.

    Args:
        incident (dict): The incident data to match against NVD database
        k (int, optional): Number of top matches to return. Defaults to 5.
        use_mmr (bool, optional): Use Maximal Marginal Relevance for
            more diverse results. Defaults to False.
        lambda_mult (float, optional): Diversity control for MMR search.
            Higher values prioritize relevance, lower values prioritize diversity.
            Defaults to 0.7.

    Returns:
        List[Dict]: A list of top NVD matches, each containing:
            - Metadata about the matched vulnerability
            - Similarity score
            - Preview of the matched content

    Note:
        - Initializes NVD index if not already done
        - Uses flatten_incident() to convert incident to searchable text
        - Supports both standard similarity and MMR search strategies

    Example:
        nvd_matches = semantic_match_incident_nvd(incident_data)
    """
    logger.debug(f"Flattening incident text for NVD search")
    query_text = flatten_incident(incident)

    # Initialize indexes if needed
    if NVD_FAISS is None:
        logger.info("NVD index not initialized, initializing now")
        initialize_faiss_indexes()

    logger.debug(f"Searching NVD index with k={k}, MMR={use_mmr}")
    nvd_hits = _search(NVD_FAISS, query_text, k, use_mmr, lambda_mult)
    logger.info(f"Found {len(nvd_hits)} NVD matches")

    return nvd_hits

# =========================================================================
# BATCH PROCESSING AND ANALYSIS FUNCTIONS
# =========================================================================
# Handle batch processing of incidents for CVE matching

@timing_metric
def batch_match_incident_to_cves(batch_size: int = 5, start_index: int = 0, top_k: int = 3) -> Dict[str, Any]:
    """
    Batch process incidents to find related CVEs using semantic matching.

    This function retrieves a batch of incident IDs and performs CVE matching
    for each incident. It provides a comprehensive overview of potential
    vulnerability correlations across a set of incidents.

    Args:
        batch_size (int, optional): Number of incidents to process.
            Defaults to 5.
        start_index (int, optional): Starting index for incident retrieval.
            Useful for pagination. Defaults to 0.
        top_k (int, optional): Number of top CVE matches to return per incident.
            Defaults to 3.

    Returns:
        Dict[str, Any]: A comprehensive mapping of incidents to their CVE matches:
            - 'success': Boolean indicating if the operation was successful
            - 'results': Dictionary of incident IDs to their CVE matches
            - 'metadata': Information about the batch processing
                * 'batch_size': Number of incidents processed
                * 'start_index': Starting index of the batch
                * 'incidents_processed': Actual number of incidents processed

    Raises:
        Various exceptions if incident retrieval or CVE matching fails

    Example:
        cve_matches = batch_match_incident_to_cves(batch_size=10, top_k=3)
        for incident_id, match_data in cve_matches['results'].items():
            print(f"Incident {incident_id} CVE Matches: {match_data}")
    """
    # Get list of incident IDs
    incident_list = list_incident_ids(limit=batch_size, start_index=start_index)
    if not incident_list.get("success", False):
        return {
            "error": "Failed to retrieve incident list",
            "debug_info": incident_list.get("debug_info", {})
        }

    incident_id_to_cve_map = []

    # Process each incident ID
    for incident_id in incident_list["incident_ids"]:
        # Get CVE matches for this incident
        matches = match_incident_to_cves(
            incident_id=incident_id,
            k=top_k,  # Get top_k (default of 3) matches from each source
            use_mmr=True  # Use maximal marginal relevance to avoid near-duplicates
        )

        if "error" not in matches:
            incident_id_to_cve_map.append({
                "incident_id": incident_id,
                "matches": matches
            })
        else:
            incident_id_to_cve_map.append({
                "incident_id": incident_id,
                "error": matches["error"]
            })

    return {
        "success": True,
        "results": incident_id_to_cve_map,
        "metadata": {
            "batch_size": batch_size,
            "start_index": start_index,
            "incidents_processed": len(incident_id_to_cve_map)
        }
    }

@timing_metric
def match_incident_to_cves(incident_id: str, k: int = 5, use_mmr: bool = True) -> dict:
    """
    Find top CVE candidates for a specific incident using semantic matching.

    This function takes an incident ID and returns the most relevant CVEs
    from both KEV and NVD databases, using semantic similarity search.

    Args:
        incident_id (str): Unique identifier of the incident to match
        k (int, optional): Number of top CVE candidates to return per database.
            Defaults to 5.
        use_mmr (bool, optional): Whether to use Maximal Marginal Relevance
            for more diverse CVE results. Defaults to True.

    Returns:
        dict: A dictionary containing:
            - 'incident_id': The original incident ID
            - 'kev_candidates': Top CVE matches from Known Exploited Vulnerabilities
            - 'nvd_candidates': Top CVE matches from National Vulnerability Database
            - 'error' (optional): Error message if incident not found

    Example:
        cve_matches = match_incident_to_cves("INC-2023-001")
        print(f"KEV Matches: {cve_matches['kev_candidates']}")
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
    # result looks like {"kev_candidates":[{…}], "nvd_candidates":[{…}]}

    return {"incident_id": incident_id, **result}

@timing_metric
def batch_get_historical_context(incident_ids: List[str], top_k: int = 3) -> Dict[str, Any]:
    """
    Get historical context and similar analyses for a specific list of incidents.

    This function takes a list of incident IDs and finds similar historical
    incidents and their analyses for each one. It provides a comprehensive view
    of historical context for the specified incidents.

    Args:
        incident_ids (List[str]): List of incident IDs to get historical context for
        top_k (int, optional): Number of top similar incidents to return per incident.
            Defaults to 3.

    Returns:
        Dict[str, Any]: A comprehensive mapping of incidents to their historical context:
            - 'success': Boolean indicating if the operation was successful
            - 'results': Dictionary of incident IDs to their historical context
            - 'metadata': Information about the processing
                * 'incidents_processed': Actual number of incidents processed
                * 'top_k': Number of similar incidents retrieved per incident
    """
    # Initialize indexes if needed
    if INCIDENT_HISTORY_FAISS is None:
        logger.info("Historical incident index not initialized, initializing now")
        initialize_faiss_indexes()

    incident_id_to_context_map = []

    # Process each incident ID
    for incident_id in incident_ids:
        # Get incident data
        incident_data = get_incident(incident_id)

        if incident_data.get("found"):
            # Get historical context for this incident
            historical_context = get_similar_incidents_with_analyses(
                incident=incident_data["incident_data"],
                k=top_k,
                use_mmr=True,
                incident_fields=["incident_id", "similarity"],
                analysis_fields=["incident_risk_level", "incident_summary", "cve_ids", "incident_risk_level_explanation"]
            )

            # Get the actual analyses from the database for the similar incidents
            similar_incident_ids = [inc["incident_id"] for inc in historical_context["similar_incidents"]]
            analyses = get_incident_analyses_from_database(similar_incident_ids)
            logger.info(f"Retrieved {len(analyses)} analyses")
            
            # Format the analyses properly
            formatted_analyses = {}
            for analysis in analyses:
                incident_id = analysis['incident_id']
                filtered_analysis = {
                    'incident_risk_level': analysis.get('incident_risk_level'),
                    'incident_summary': analysis.get('incident_summary'),
                    'cve_ids': analysis.get('cve_ids'),
                    'incident_risk_level_explanation': analysis.get('incident_risk_level_explanation')
                }
                if any(filtered_analysis.values()):  # Only add if we found some data
                    formatted_analyses[incident_id] = filtered_analysis

            # Update the historical context with the actual analyses
            historical_context['analyses'] = formatted_analyses

            incident_id_to_context_map.append({
                "incident_id": incident_id,
                "historical_context": historical_context
            })
        else:
            incident_id_to_context_map.append({
                "incident_id": incident_id,
                "error": "Incident not found"
            })

    return {
        "success": True,
        "results": incident_id_to_context_map,
        "metadata": {
            "incidents_processed": len(incident_id_to_context_map),
            "top_k": top_k
        }
    }

# =========================================================================
# INCIDENT ANALYSIS HISTORY FUNCTIONS
# =========================================================================
# Search and retrieve historical incident analysis data

@cache_result(ttl_seconds=3600)
def search_incident_analysis_history(
    query: str,
    k: int = 5,
    use_mmr: bool = True,
    lambda_mult: float = 0.7
) -> List[Dict]:
    """
    Search the incident analysis history using semantic search.

    This function allows searching through previously analyzed incident documents
    using semantic similarity. It supports both standard similarity search and
    Maximal Marginal Relevance (MMR) search for more diverse results.

    Args:
        query (str): Natural language query to search the incident analysis history
        k (int, optional): Number of top results to return. Defaults to 5.
        use_mmr (bool, optional): Whether to use Maximal Marginal Relevance for search.
                                  Helps get more diverse results. Defaults to True.
        lambda_mult (float, optional): Diversity control for MMR search.
                                       Higher values prioritize relevance,
                                       lower values prioritize diversity.
                                       Defaults to 0.7.

    Returns:
        List[Dict]: A list of matching incident analysis documents, each containing:
            - incident_id: ID of the similar incident
            - incident_summary: Summary of the incident
            - incident_risk_level: Risk level assigned to the incident
            - cve_ids: Associated CVEs and their details
            - similarity: Similarity score of the match

    Example:
        results = search_incident_analysis_history("ransomware attack")
        # Returns top 5 most semantically similar incident analyses
    """
    logger.info(f"Searching incident analysis history with query: {query}")

    # Initialize indexes if needed
    if INCIDENT_HISTORY_FAISS is None:
        logger.info("Historical incident index not initialized, initializing now")
        initialize_faiss_indexes()

    # Perform the search
    if use_mmr:
        # MMR path: pull doc+score
        hits = INCIDENT_HISTORY_FAISS.max_marginal_relevance_search_with_score_by_vector(
            embeddings.embed_query(query),
            k=k,
            fetch_k=2*k,
            lambda_mult=lambda_mult,
        )
    else:
        # regular similarity
        hits = INCIDENT_HISTORY_FAISS.similarity_search_with_score(query, k=k)

    # Format the results
    out = []
    for doc, score in hits:
        m = doc.metadata.copy()
        m["variance"] = float(score)
        out.append(m)

    logger.info(f"Found {len(out)} similar incidents")
    return out

# =========================================================================
# CVE SEARCH FUNCTIONS
# =========================================================================
# Perform semantic searches across CVE databases

def semantic_search_cves(
    query: str,
    sources: List[str] = ["kev", "nvd", "historical"],
    k: int = 5,
    use_mmr: bool = False,
    lambda_mult: float = 0.7
) -> Dict[str, Any]:
    """
    Perform a semantic search across CVE databases (KEV and/or NVD).

    This function allows flexible searching of vulnerability databases using
    semantic similarity. It can search KEV (Known Exploited Vulnerabilities),
    NVD (National Vulnerability Database), or both.

    Args:
        query (str): Natural language query to search CVE databases
        sources (List[str], optional): Databases to search.
            Defaults to ["kev", "nvd"].
            Allowed values are "kev" and "nvd".
        k (int, optional): Number of top results to return per source.
            Defaults to 5.
        use_mmr (bool, optional): Whether to use Maximal Marginal Relevance
            for more diverse results. Defaults to False.
        lambda_mult (float, optional): Diversity control for MMR search.
            Higher values prioritize relevance, lower values prioritize diversity.
            Defaults to 0.7.

    Returns:
        Dict[str, Any]: A dictionary containing:
            - 'query': The original search query
            - 'kev_candidates' (optional): Top CVE matches from KEV database
            - 'nvd_candidates' (optional): Top CVE matches from NVD database

    Example:
        results = semantic_search_cves("remote code execution",
                                       sources=["kev"],
                                       k=3)
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
    if "historical" in sources:
        out["historical_candidates"] = search_incident_analysis_history(
            query, k=k, use_mmr=use_mmr, lambda_mult=lambda_mult
        )
    return out

# =========================================================================
# DUMMY INCIDENT ANALYSES FUNCTIONS
# =========================================================================
# Search and retrieve similar incidents from dummy analyses

@timing_metric
@cache_result(ttl_seconds=3600)
def search_similar_incidents(
    incident: dict,
    k: int = 5,
    use_mmr: bool = True,
    lambda_mult: float = 0.7
) -> List[Dict]:
    """
    Search for similar incidents in the historical incident analyses index.

    This function takes an incident, finds similar ones in the historical incident analyses index,
    and returns their metadata including risk levels and CVE associations.

    Args:
        incident (dict): The incident to find similar ones for
        k (int, optional): Number of top matches to return. Defaults to 5.
        use_mmr (bool, optional): Whether to use Maximal Marginal Relevance
            for more diverse results. Defaults to True.
        lambda_mult (float, optional): Diversity control for MMR search.
            Higher values prioritize relevance, lower values prioritize diversity.
            Defaults to 0.7.

    Returns:
        List[Dict]: A list of similar incidents, each containing:
            - incident_id: ID of the similar incident
            - incident_summary: Summary of the incident
            - incident_risk_level: Risk level assigned to the incident
            - cve_ids: Associated CVEs and their details
            - similarity: Similarity score with the query incident

    Example:
        similar = search_similar_incidents(incident_data)
        for match in similar:
            print(f"Similar incident {match['incident_id']} with risk level {match['incident_risk_level']}")
    """
    logger.info(f"Searching for similar incidents with k={k}, MMR={use_mmr}")

    # Initialize indexes if needed
    if INCIDENT_HISTORY_FAISS is None:
        logger.debug("Historical analyses index not initialized, initializing now")
        initialize_faiss_indexes()

    # Flatten the incident for searching
    query_text = flatten_incident(incident)

    # Perform the search
    if use_mmr:
        # MMR path: pull doc+score
        hits = INCIDENT_HISTORY_FAISS.max_marginal_relevance_search_with_score_by_vector(
            embeddings.embed_query(query_text),
            k=k,
            fetch_k=2*k,
            lambda_mult=lambda_mult,
        )
    else:
        # regular similarity
        hits = INCIDENT_HISTORY_FAISS.similarity_search_with_score(query_text, k=k)

    # Format the results
    out = []
    for doc, score in hits:
        m = doc.metadata.copy()
        m["variance"] = float(score)
        out.append(m)

    logger.info(f"Found {len(out)} similar incidents")
    return out

@timing_metric
@cache_result(ttl_seconds=3600)
def get_dummy_incident_analyses(incident_ids: List[str]) -> Dict[str, Dict]:
    """
    Retrieve full analyses for a list of incident IDs from the dummy analyses database.

    Args:
        incident_ids (List[str]): List of incident IDs to retrieve analyses for

    Returns:
        Dict[str, Dict]: Dictionary mapping incident IDs to their full analyses
            - Keys are incident IDs
            - Values are the complete analysis objects including:
                * incident_summary
                * cve_ids and their details
                * incident_risk_level
                * incident_risk_level_explanation

    Example:
        analyses = get_dummy_incident_analyses(["INC-2024-05-12-005", "INC-2024-07-01-007"])
        for incident_id, analysis in analyses.items():
            print(f"Analysis for {incident_id}: {analysis['incident_risk_level']}")
    """
    try:
        data_file = Path("data/dummy_agent_incident_analyses.json")
        with open(data_file, 'r') as f:
            all_analyses = json.load(f)

        # Create a lookup dictionary for faster access
        analyses_lookup = {analysis["incident_id"]: analysis for analysis in all_analyses}

        # Retrieve requested analyses
        requested_analyses = {}
        for incident_id in incident_ids:
            if incident_id in analyses_lookup:
                requested_analyses[incident_id] = analyses_lookup[incident_id]
            else:
                logger.warning(f"Analysis not found for incident {incident_id}")
                requested_analyses[incident_id] = {
                    "error": "Analysis not found",
                    "incident_id": incident_id
                }

        return requested_analyses

    except FileNotFoundError:
        logger.error("Dummy analyses database not found")
        return {incident_id: {"error": "Database not found"} for incident_id in incident_ids}
    except Exception as e:
        logger.error(f"Error retrieving analyses: {str(e)}")
        return {incident_id: {"error": str(e)} for incident_id in incident_ids}

@timing_metric
def get_similar_incidents_with_analyses(
    incident: dict,
    k: int = 5,
    use_mmr: bool = True,
    lambda_mult: float = 0.7,
    incident_fields: List[str] = ["incident_id", "variance"],
    analysis_fields: List[str] = ["incident_risk_level", "incident_summary", "cve_ids", "incident_risk_level_explanation"]
) -> Dict[str, Any]:
    """
    Find similar incidents and retrieve their full analyses.

    This function combines semantic search with analysis retrieval to provide
    a complete view of similar incidents and their historical analyses.

    Args:
        incident (dict): The incident to find similar ones for
        k (int, optional): Number of top matches to return. Defaults to 5.
        use_mmr (bool, optional): Whether to use Maximal Marginal Relevance
            for more diverse results. Defaults to True.
        lambda_mult (float, optional): Diversity control for MMR search.
            Higher values prioritize relevance, lower values prioritize diversity.
            Defaults to 0.7.
        incident_fields (List[str], optional): Fields to include from similar incidents.
            Defaults to ["incident_id", "variance"].
            Available fields: incident_id, similarity, incident_summary, incident_risk_level
        analysis_fields (List[str], optional): Fields to include from analyses.
            Defaults to ["incident_risk_level", "incident_summary", "cve_ids", "incident_risk_level_explanation"].
            Available fields: incident_summary, cve_ids, incident_risk_level,
            incident_risk_level_explanation

    Returns:
        Dict[str, Any]: A dictionary containing:
            - 'similar_incidents': List of similar incidents with selected fields
            - 'analyses': Dictionary mapping incident IDs to their selected analysis fields
            - 'metadata': Information about the search results
    """
    # First find similar incidents
    similar_incidents = search_similar_incidents(
        incident=incident,
        k=k,
        use_mmr=use_mmr,
        lambda_mult=lambda_mult
    )

    # Filter similar incidents to requested fields
    filtered_incidents = []
    filtered_analyses = {}
    
    for inc in similar_incidents:
        # Filter incident fields
        filtered_inc = {field: inc.get(field) for field in incident_fields if field in inc}
        filtered_incidents.append(filtered_inc)
        
        # Extract analysis fields directly from the search results
        incident_id = inc["incident_id"]
        filtered_analysis = {field: inc.get(field) 
                           for field in analysis_fields 
                           if field in inc}
        if filtered_analysis:  # Only add if we found some analysis fields
            filtered_analyses[incident_id] = filtered_analysis

    # If we didn't get all analyses from search results, try getting from database
    if not filtered_analyses:
        incident_ids = [inc["incident_id"] for inc in filtered_incidents]
        logger.info(f"Retrieving analyses from database for {len(incident_ids)} incidents...")
        full_analyses = get_incident_analyses_from_database(incident_ids)
        logger.info(f"Retrieved {len(full_analyses)} analyses")
        
        for analysis in full_analyses:
            incident_id = analysis['incident_id']
            filtered_analysis = {field: analysis.get(field) 
                               for field in analysis_fields 
                               if field in analysis}
            if filtered_analysis:  # Only add if we found some analysis fields
                filtered_analyses[incident_id] = filtered_analysis

    return {
        "similar_incidents": filtered_incidents,
        "analyses": filtered_analyses,
        "metadata": {
            "num_incidents_found": len(filtered_incidents),
            "num_analyses_retrieved": len(filtered_analyses),
            "search_params": {
                "k": k,
                "use_mmr": use_mmr,
                "lambda_mult": lambda_mult
            },
            "fields_retrieved": {
                "incident_fields": incident_fields,
                "analysis_fields": analysis_fields
            }
        }
    }

async def write_documents_to_faiss_index(documents: list[Document], index: FAISS=INCIDENT_HISTORY_FAISS, index_location: str="data/vectorstore/historical_incidents"):
    """
    Write a list of documents to a FAISS index and save it to disk.

    This function handles the asynchronous writing of documents to a FAISS index
    and ensures the index is properly saved to disk. It uses a lock to prevent
    concurrent writes to the same index.

    Args:
        documents (list[Document]): List of Document objects to write to the index
        index (FAISS, optional): The FAISS index to write to. Defaults to INCIDENT_HISTORY_FAISS.
        index_location (str, optional): Path where the index should be saved. 
            Defaults to "data/vectorstore/historical_incidents".

    Note:
        - Uses an async lock to prevent concurrent writes
        - Saves the index to disk after writing
        - Updates the global index reference
    """
    async with faiss_write_lock:
        index.add_documents(documents)
        index.save_local(index_location)
        global INCIDENT_HISTORY_FAISS
        INCIDENT_HISTORY_FAISS = index

@timing_metric
async def add_incident_to_faiss_history_index(incident: dict, analysis: dict):
    """
    Add an incident and its analysis to the FAISS history index.

    This function takes an incident and its analysis, creates a Document object,
    and adds it to the FAISS history index for future semantic search.

    Args:
        incident (dict): The incident data to add
        analysis (dict): The analysis data associated with the incident

    Note:
        - Creates a Document object from the incident and analysis
        - Uses write_documents_to_faiss_index to safely add to the index
        - Updates the global INCIDENT_HISTORY_FAISS reference
    """
    # Create a Document object from the incident and analysis
    doc = Document(
        page_content=str(incident),
        metadata={
            "incident_id": incident.get("incident_id", "unknown"),
            "analysis": analysis
        }
    )

    # Write to FAISS using async lock to handle potential concurrency issues
    await write_documents_to_faiss_index(
        index=INCIDENT_HISTORY_FAISS,
        index_location="data/vectorstore/historical_incidents",
        documents=[doc]
    )

@timing_metric
async def save_incident_analysis_backup_json(incident_id: str, llm_response: Any, request_id: str = None):
    """
    Parse and save the LLM's analysis response to a local JSON backup file.
    Accepts either a JSON string or a Python dict.
    
    This function creates a backup of the analysis in data/backups/incident_analyses/
    using the current date to group analyses together.
    """
    try:
        # Normalize into a dict
        logger.debug(f"Normalizing LLM response into a dict for incident_id: {incident_id}...")
        if isinstance(llm_response, str):
            analysis = json.loads(llm_response)
        elif isinstance(llm_response, dict):
            analysis = llm_response
        else:
            raise TypeError(f"Unexpected type for llm_response: {type(llm_response)}")

        # Validate required fields
        logger.debug(f"Validating required fields for incident_id: {incident_id}...")
        for field in (
            "incident_id",
            "incident_summary",
            "cve_ids",
            "incident_risk_level",
            "incident_risk_level_explanation",
        ):
            if field not in analysis:
                raise ValueError(f"Missing required field: {field}")

        # Save to backup directory
        backup_dir = Path("data/backups/incident_analyses")
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Use current date for filename
        current_date = datetime.now(UTC).strftime("%Y%m%d")
        backup_file = backup_dir / f"incidents_{current_date}.json"
        
        # Load existing analyses if file exists
        if backup_file.exists():
            with open(backup_file, 'r') as f:
                try:
                    existing_analyses = json.load(f)
                except json.JSONDecodeError:
                    existing_analyses = {"incidents": []}
        else:
            existing_analyses = {"incidents": []}
        
        # Add new analysis to the list
        existing_analyses["incidents"].append(analysis)
        
        # Save updated analyses
        logger.debug(f"Saving JSON backup to {backup_file}...")
        with open(backup_file, 'w') as f:
            json.dump(existing_analyses, f, indent=2)
                
        logger.info(f"Saved JSON backup analysis for incident {incident_id} to {backup_file}")

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM response as JSON: {e}")
        raise
    except Exception:
        logger.exception("Error saving incident analysis JSON backup")
        raise

# =========================================================================
# MAIN EXECUTION BLOCK
# =========================================================================
if __name__ == "__main__":
    initialize_faiss_indexes()
    initialize_openai_embeddings()
    test_search_text = "My browser history was deleted"
    results = search_text(test_search_text, KEV_FAISS)
    print(results)
