# utils/retriever.py  (patched)
import logging, os
from pathlib import Path
from typing import Dict, List
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from utils.flatteners import flatten_incident
logging.getLogger("openai").setLevel(logging.ERROR)  # suppress verbose init

BASE_DIR = Path(__file__).parent.parent        # utils/ ➜ project root
DATA_DIR = BASE_DIR / "data" / "vectorstore"

# We use OpenAI Embeddings for speed and quality given the small size of the data, but this can be changed to other embedding models like Sentance Transformers' all-MiniLM-L6-v2, etc.
def initialize_embeddings():
    global embeddings
    embeddings = OpenAIEmbeddings()

def initialize_indexes():
    global KEV_FAISS, NVD_FAISS
    if embeddings is None:
        initialize_embeddings()

    KEV_FAISS  = FAISS.load_local(DATA_DIR / "kev", OpenAIEmbeddings(),
                              allow_dangerous_deserialization=True)
    NVD_FAISS  = FAISS.load_local(DATA_DIR / "nvd", OpenAIEmbeddings(),
                              allow_dangerous_deserialization=True)

def _search(
    store: FAISS,
    query: str,
    k: int = 5,
    use_mmr: bool = True,
    lambda_mult: float = 0.7,
    fetch_k: int = None
) -> List[Dict]:
    """
    Return a list of metadata dicts with 'similarity' and 'preview' for top-k hits.
    If use_mmr is True, runs Maximal Marginal Relevance by vector.
    Otherwise does a standard similarity_search_with_score.
    """
    if use_mmr:
        # embed the query once
        vec = OpenAIEmbeddings().embed_query(query)
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
        meta["preview"] = doc.page_content[:120]
        out.append(meta)

    return out


def semantic_match_incident(
    incident: dict,
    k_kev: int = 5,
    k_nvd: int = 5,
    kev_threshold: float = 0.3,
    use_mmr: bool = False,
    lambda_mult: float = 0.7,
) -> dict:
    """
    Return {"kev_candidates":[meta...], "nvd_candidates":[meta...]}
    """
    query_text = flatten_incident(incident)

    kev_hits = _search(KEV_FAISS, query_text, k_kev, use_mmr, lambda_mult)

    best_kev_score = kev_hits[0]["similarity"] if kev_hits else 1.0
    if best_kev_score < kev_threshold:
        nvd_hits = []
    else:
        nvd_hits = _search(NVD_FAISS, query_text, k_nvd, use_mmr, lambda_mult)

    return {"kev_candidates": kev_hits, "nvd_candidates": nvd_hits}

def search_text(
    text: str,
    store: FAISS,
    k: int = 5,
    use_mmr: bool = False,
    lambda_mult: float = 0.7,
) -> List[Dict]:
    # embed the query
    query_vec = OpenAIEmbeddings().embed_query(text)

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

if __name__ == "__main__":
    initialize_indexes()
    initialize_embeddings()
    test_search_text = "My browser history was deleted"
    results = search_text(test_search_text, KEV_FAISS)
    print(results)
