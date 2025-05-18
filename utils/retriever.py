# utils/retriever.py  (patched)
import json
import logging, os
from pathlib import Path
from typing import Any, Dict, List, Optional
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from utils.decorators import cache_result, timing_metric
from utils.flatteners import flatten_incident
from utils.logging_utils import setup_logger

BASE_DIR = Path(__file__).parent.parent        # utils/ ➜ project root
DATA_DIR = BASE_DIR / "data" / "vectorstore"
logger = setup_logger("retriever")
# =========================================================================
# INITIALIZATION AND EMBEDDING FUNCTIONS
# =========================================================================
# These functions handle the initialization of embeddings and vector indexes
# for semantic search across vulnerability databases

from typing import Any, Dict, List


@timing_metric
def initialize_embeddings():
    """
    Initialize the global embeddings object using OpenAI's embedding model.

    This function creates a global embeddings instance using OpenAIEmbeddings, 
    which will be used for converting text to vector representations across 
    the semantic search functionality.

    The function is decorated with @timing_metric to track potential initialization cost.

    Note:
        - This function sets a global 'embeddings' variable
        - It suppresses verbose logging from the OpenAI embeddings initialization
        - Should be called before any embedding or search operations

    Raises:
        Any exceptions that might occur during embeddings initialization
    """
    logging.getLogger("openai").setLevel(logging.ERROR)  # suppress verbose init
    global embeddings
    embeddings = OpenAIEmbeddings()

@timing_metric
def initialize_indexes():
    """
    Initialize global FAISS indexes for different vulnerability databases.

    This function loads local FAISS vector stores for:
    - KEV (Known Exploited Vulnerabilities)
    - NVD (National Vulnerability Database)
    - Incident Analysis History

    The function ensures that:
    - Embeddings are initialized if not already done
    - FAISS indexes are loaded from local storage
    - Dangerous deserialization is allowed for loading pre-built indexes

    Note:
        - Sets global variables: KEV_FAISS, NVD_FAISS, INCIDENT_ANALYSIS_HISTORY_FAISS
        - Requires OpenAI embeddings to be initialized first
        - Uses local vector store files in the 'data/vectorstore' directory

    Raises:
        Various exceptions if index loading fails
    """
    global KEV_FAISS, NVD_FAISS, INCIDENT_ANALYSIS_HISTORY_FAISS
    if embeddings is None:
        initialize_embeddings()

    KEV_FAISS = FAISS.load_local(DATA_DIR / "kev", embeddings,
                              allow_dangerous_deserialization=True)
    NVD_FAISS = FAISS.load_local(DATA_DIR / "nvd", embeddings,
                              allow_dangerous_deserialization=True)
    INCIDENT_ANALYSIS_HISTORY_FAISS = FAISS.load_local(DATA_DIR / "incident_analysis_history", embeddings,
                               allow_dangerous_deserialization=True)

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
        initialize_embeddings()
    
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
        meta["similarity"] = float(score)
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
        initialize_embeddings()
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
        m["similarity"] = score
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
    best_kev_score = kev_hits[0]["similarity"] if kev_hits else 1.0
    
    logger.info(f"Best KEV match score: {best_kev_score:.3f}")
    
    # Only search NVD if KEV results aren't strong enough
    if best_kev_score < kev_threshold:
        logger.info(f"KEV score {best_kev_score:.3f} below threshold {kev_threshold}, skipping NVD search")
        nvd_hits = [f"Kev score of {best_kev_score} is satisfactory enough to skip searching NVD"]
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
        initialize_indexes()
    
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
        initialize_indexes()
    
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

# =========================================================================
# INCIDENT ANALYSIS HISTORY FUNCTIONS
# =========================================================================
# Search and retrieve historical incident analysis data

@timing_metric
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
            - metadata from the original document
            - 'similarity' score of the match
            - 'preview' of the document content
    
    Example:
        results = search_incident_analysis_history("ransomware attack")
        # Returns top 5 most semantically similar incident analyses
    """
    logger.info(f"Searching incident analysis history with query: {query}")
    
    # Embed the query
    query_vec = embeddings.embed_query(query)
    if INCIDENT_ANALYSIS_HISTORY_FAISS is None:
        logger.info("Batch history index not initialized, initializing now")
        initialize_indexes()

    if use_mmr:
        # MMR path: pull doc+score
        hits = INCIDENT_ANALYSIS_HISTORY_FAISS.max_marginal_relevance_search_with_score_by_vector(
            query_vec,
            k=k,
            fetch_k=2*k,
            lambda_mult=lambda_mult,
        )
    else:
        # regular similarity
        hits = INCIDENT_ANALYSIS_HISTORY_FAISS.similarity_search_with_score(query, k=k)

    out = []
    for doc, score in hits:
        m = doc.metadata.copy()
        m["similarity"] = score
        m["preview"] = doc.page_content
        out.append(m)
    
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
# MAIN EXECUTION BLOCK
# =========================================================================
if __name__ == "__main__":
    initialize_indexes()
    initialize_embeddings()
    test_search_text = "My browser history was deleted"
    results = search_text(test_search_text, KEV_FAISS)
    print(results)
