#!/usr/bin/env python3
"""
scripts/build_faiss_indexes.py
------------------------------
Reads kev.json and nvd_subset.json, flattens each entry,
embeds with OpenAI, builds & saves two FAISS indexes.

Run:
    OPENAI_API_KEY=sk-... python scripts/build_faiss_indexes.py
"""

from pathlib import Path
import json
import argparse

from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from utils.flatteners import flatten_kev, flatten_nvd

DATA_DIR = Path("data")
OUT_DIR = DATA_DIR / "vectorstore"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------- CLI --------------
parser = argparse.ArgumentParser()
parser.add_argument("--model", default="text-embedding-3-small",
                    help="OpenAI embedding model")
parser.add_argument("--topk-test", type=int, default=3,
                    help="Run a smoke-test query and show K results")
args = parser.parse_args()

embeddings = OpenAIEmbeddings(model=args.model, show_progress_bar=True)


# ---------- Build KEV index ----------
kev_json = DATA_DIR / "kev.json"
print("Loading KEV JSON …")
kev_raw = json.load(kev_json.open())
kev_entries = kev_raw["vulnerabilities"]

print(f"Flattening {len(kev_entries)} KEV entries …")
kev_docs = [flatten_kev(e) for e in kev_entries]

print("Embedding & building KEV FAISS index …")
faiss_kev = FAISS.from_documents(kev_docs, embeddings)
faiss_kev.save_local(OUT_DIR / "kev")
print("✅ Saved KEV index to data/vectorstore/kev\n")


# ---------- Build NVD index ----------
nvd_json = DATA_DIR / "nvd_subset.json"
print("Loading NVD subset JSON …")
nvd_raw = json.load(nvd_json.open())
nvd_items = list(nvd_raw.values())  # dict keyed by CVE ID

print(f"Flattening {len(nvd_items)} NVD entries …")
nvd_docs = [flatten_nvd(item) for item in nvd_items]

print("Embedding & building NVD FAISS index …")
faiss_nvd = FAISS.from_documents(nvd_docs, embeddings)
faiss_nvd.save_local(OUT_DIR / "nvd")
print("✅ Saved NVD index to data/vectorstore/nvd\n")


# ---------- Smoke-test query ----------
if args.topk_test > 0:
    retriever_kev = FAISS.load_local(OUT_DIR / "kev", embeddings).as_retriever()
    print(f"\n🔎 Quick test: top-{args.topk_test} KEV matches for query ‘Fortinet stack overflow’")
    for d in retriever_kev.get_relevant_documents("Fortinet stack overflow")[: args.topk_test]:
        print(f"• {d.metadata['cve_id']}  |  score≈{d.metadata.get('score', 'NA')}")
        print(f"  {d.page_content.splitlines()[1][:100]}…\n")
