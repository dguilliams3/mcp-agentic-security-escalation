#!/usr/bin/env python3
"""
scripts/build_historical_incident_analyses_index.py
--------------------------------------------------
Reads incidents.json, flattens each entry,
embeds with OpenAI, builds & saves FAISS index for historical incident analyses.

Have in your .env file:
    OPENAI_API_KEY=sk-...
"""

from pathlib import Path
import json, os, argparse
from dotenv import load_dotenv
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from utils.flatteners import flatten_incident


# ---------- tiny helper --------------------------------------------------
def index_is_fresh(json_path: Path, index_dir: Path) -> bool:
    """
    Return True if index_dir/index.faiss exists and is newer than json_path.
    Used to skip needless re-embedding on repeat runs.
    """
    faiss_file = index_dir / "index.faiss"
    return faiss_file.exists() and faiss_file.stat().st_mtime >= json_path.stat().st_mtime


# -------------------------------------------------------------------------

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY not found – check your .env file.")

DATA_DIR = Path("data")
OUT_DIR = DATA_DIR / "vectorstore"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------- CLI --------------
parser = argparse.ArgumentParser()
parser.add_argument("--model", default="text-embedding-3-small")
parser.add_argument("--topk-test", type=int, default=3)
args = parser.parse_args()

embeddings = OpenAIEmbeddings(model=args.model, show_progress_bar=True)

# ---------- Build / Skip Historical Incident Analyses index ----------
incidents_json = DATA_DIR / "dummy_incidents.json"
historical_out = OUT_DIR / "incident_analysis_history"

if index_is_fresh(incidents_json, historical_out):
    print("✅ Historical Incident Analyses index up-to-date – skipping build")
else:
    print("🔄 Building Historical Incident Analyses index …")
    with open(incidents_json, "r") as f:
        incidents_raw = json.load(f)

    # Create documents by flattening each incident and converting to Document
    historical_docs = [
        Document(
            page_content=flatten_incident(incident),
            metadata={
                "incident_id": incident.get("incident_id"),
                "title": incident.get("title"),
                "timestamp": incident.get("timestamp"),
            },
        )
        for incident in incidents_raw
    ]

    # Create and save FAISS index
    FAISS.from_documents(historical_docs, embeddings).save_local(historical_out)
    print(
        "✅ Saved Historical Incident Analyses index to data/vectorstore/incident_analysis_history\n"
    )

# ---------- Smoke-test query ----------
if args.topk_test > 0:
    print(f"\n🔎 top-{args.topk_test} Historical Incident Analyses matches for 'ransomware'")
    faiss_historical = FAISS.load_local(
        historical_out, embeddings, allow_dangerous_deserialization=True
    )
    for doc, score in faiss_historical.similarity_search_with_score("ransomware", k=args.topk_test):
        print(f"• Incident ID: {doc.metadata.get('incident_id', 'N/A')} | score={score:.4f}")
        print(f"  {doc.page_content}…\n")
