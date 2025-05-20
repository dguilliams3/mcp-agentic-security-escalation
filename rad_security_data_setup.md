# 4. Data Ingestion & Preprocessing

In this section, we'll explore the input data and prepare it for analysis. We need to:

1. Load and inspect incident data
2. Retrieve and prepare CVE data (KEV and NVD)
3. Create flattened text representations for vector embedding

**Why we do this:** Proper data preparation is critical for effective semantic search. By flattening complex JSON structures into searchable text, we enable the embedding model to capture semantic relationships between incidents and vulnerabilities.

```python
import json
from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Ensure we have an OpenAI API key
if not os.getenv("OPENAI_API_KEY"):
    raise ValueError(
        "Please set the OPENAI_API_KEY environment variable in your .env file"
    )

# Load incidents data
data_dir = Path('data')
with open(data_dir / 'incidents.json') as f:
    incidents = json.load(f)

# Display overview statistics
print(f"Total incidents: {len(incidents)}")
print("Fields in first incident:", list(incidents[0].keys()))

# Display first incident in pretty format
print("\nSample incident details:")
print(json.dumps(incidents[0], indent=2))
```

```python
# Load KEV (Known Exploited Vulnerabilities) data
with open(data_dir / 'kev.json') as f:
    kev_data = json.load(f)
    
print(f"KEV entries: {len(kev_data.get('vulnerabilities', []))}")
print("\nSample KEV entry:")
print(json.dumps(kev_data.get('vulnerabilities', [])[0], indent=2))
```

```python
# Load NVD (National Vulnerability Database) data
with open(data_dir / 'nvd_subset.json') as f:
    nvd_data = json.load(f)
    
print(f"NVD entries: {len(nvd_data)}")

# Display a sample NVD entry
sample_cve_id = list(nvd_data.keys())[0]
print(f"\nSample NVD entry ({sample_cve_id}):")
# Just show the description part to keep it manageable
desc = nvd_data[sample_cve_id].get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "")
print(desc)
```

## 5. Text Flattening for Vector Embedding

Before building our vector indexes, we need to convert the structured data into a flattened text format suitable for embedding. Let's examine our flattening strategies:

**Why we do this:** Embeddings work on raw text, but our data is in complex JSON structures. Flattening transforms these structures into searchable text while preserving the semantic meaning of the data.

```python
from utils.flatteners import flatten_kev, flatten_nvd, flatten_incident
from langchain.docstore.document import Document

# Example KEV entry flattening
sample_kev = kev_data.get('vulnerabilities', [])[0]
doc_kev = flatten_kev(sample_kev)
print("Flattened KEV document:")
print(doc_kev.page_content[:200], "...")

# Example NVD entry flattening
sample_nvd = list(nvd_data.values())[0]
doc_nvd = flatten_nvd(sample_nvd)
print("\nFlattened NVD document:")
print(doc_nvd.page_content[:200], "...")

# Example Incident flattening
doc_inc = Document(
    page_content=flatten_incident(incidents[0]), 
    metadata={"incident_id": incidents[0]["incident_id"]}
)
print("\nFlattened Incident document:")
print(doc_inc.page_content[:200], "...")
```

Let's examine the flattening functions to understand how they work:

```python
# utils/flatteners.py example implementation
def flatten_incident(incident: dict) -> str:
    """
    Flatten an incident into a text representation for embedding.
    
    Args:
        incident: The incident dict to flatten
        
    Returns:
        A string representation of the incident
    """
    # Start with the title and description
    text = f"{incident.get('title', '')}\n{incident.get('description', '')}\n"
    
    # Add initial findings
    text += f"{incident.get('initial_findings', '')}\n"
    
    # Add affected assets
    for asset in incident.get("affected_assets", []):
        text += f"Asset: {asset.get('hostname', '')} ({asset.get('ip_address', '')})\n"
        text += f"OS: {asset.get('os', '')}\n"
        text += f"Role: {asset.get('role', '')}\n"
        
        # Add installed software
        for sw in asset.get("installed_software", []):
            text += f"Software: {sw.get('name', '')} {sw.get('version', '')}\n"
    
    # Add TTPs (Tactics, Techniques, and Procedures)
    for ttp in incident.get("observed_ttps", []):
        text += f"TTP: {ttp.get('name', '')} ({ttp.get('id', '')})\n"
    
    # Add indicators of compromise
    for ioc in incident.get("indicators_of_compromise", []):
        text += f"IoC: {ioc.get('type', '')}: {ioc.get('value', '')} - {ioc.get('context', '')}\n"
    
    return text
```

## 6. Building Vector Indexes

Now we'll build FAISS vector indexes for efficient semantic search across our data sources. This process involves:

1. Initializing the OpenAI embeddings model
2. Creating FAISS indexes for KEV, NVD, and historical incident data
3. Setting up utilities for semantic search

**Why we do this:** Vector indexes enable fast similarity search over large datasets. By precomputing embeddings and storing them in FAISS indexes, we can perform semantic searches in milliseconds rather than having to recompute embeddings for each query.

```python
from utils.retrieval_utils import initialize_embeddings, initialize_indexes

# Initialize OpenAI embeddings and FAISS indexes
initialize_embeddings()
initialize_indexes()
print("Embeddings and FAISS indexes initialized successfully.")
```

Implementation details from `utils/retrieval_utils.py`:

```python
def initialize_openai_embeddings():
    """
    Initialize the global OpenAI embeddings object for vector representations.
    """
    global embeddings
    embeddings = OpenAIEmbeddings()

def initialize_faiss_indexes():
    """
    Initialize global FAISS vector indexes for different vulnerability databases.
    """
    global KEV_FAISS, NVD_FAISS, INCIDENT_HISTORY_FAISS
    if embeddings is None:
        initialize_openai_embeddings()

    # Load pre-built FAISS indexes
    KEV_FAISS = FAISS.load_local(DATA_DIR / "kev", embeddings,
                              allow_dangerous_deserialization=True)
    
    NVD_FAISS = FAISS.load_local(DATA_DIR / "nvd", embeddings,
                              allow_dangerous_deserialization=True)
    
    INCIDENT_HISTORY_FAISS = FAISS.load_local(DATA_DIR / "incident_analysis_history", 
                               embeddings, allow_dangerous_deserialization=True)
```

## 7. Testing Semantic Search

Let's test our vector indexes by performing semantic searches over the different data sources:

**Why we do this:** Verifying semantic search capabilities ensures that our system can effectively identify relevant CVEs and historical incidents. This helps validate our data preparation and embedding strategies.

```python
from utils.retrieval_utils import _search, KEV_FAISS, NVD_FAISS

# Perform a semantic search using an incident title
query_text = incidents[0]['title']
print(f"Search query: {query_text}")

# Search KEV database
kev_results = _search(KEV_FAISS, query_text, k=3)
print("\nTop 3 KEV matches:")
for i, r in enumerate(kev_results, 1):
    print(f"{i}. {r['cve_id']} (score: {r['variance']:.3f})")
    print(f"   {r.get('preview', '')[:100]}...")

# Search NVD database
nvd_results = _search(NVD_FAISS, query_text, k=3)
print("\nTop 3 NVD matches:")
for i, r in enumerate(nvd_results, 1):
    print(f"{i}. {r['cve_id']} (score: {r['variance']:.3f})")
    print(f"   {r.get('preview', '')[:100]}...")
```

Let's also examine the core search function:

```python
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
    
    Args:
        store: The FAISS vector store to search
        query: The search query string
        k: Number of top results to return
        use_mmr: Use Maximal Marginal Relevance for diverse results
        lambda_mult: Diversity control for MMR search
        fetch_k: Number of documents to fetch before filtering for MMR
        
    Returns:
        List of search results with metadata and scores
    """
    if use_mmr:
        # embed the query once
        vec = embeddings.embed_query(query)
        # if fetch_k not provided, default to 2*k
        fk = fetch_k or (2 * k)
        # call the vector-based MMR-with-scores method
        pairs = store.max_marginal_relevance_search_with_score_by_vector(
            vec, k=k, fetch_k=fk, lambda_mult=lambda_mult,
        )
    else:
        # direct text-based similarity search (score included)
        pairs = store.similarity_search_with_score(query, k=k)

    # Format results
    out = []
    for doc, score in pairs:
        meta = doc.metadata.copy()
        meta["variance"] = float(score)
        meta["preview"] = ' '.join(doc.page_content.replace('\n', ' ').split())[:120]
        out.append(meta)

    return out
``` 