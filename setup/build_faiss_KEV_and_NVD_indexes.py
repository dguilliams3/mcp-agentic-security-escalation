#!/usr/bin/env python3
"""
scripts/build_KEV_and_NVD_faiss_indexes.py
------------------------------
Reads kev.json and nvd_subset.json, flattens each entry,
embeds with OpenAI, builds & saves two FAISS indexes.

Have in your .env file:
    OPENAI_API_KEY=sk-...
"""

from pathlib import Path
import json, os, argparse
from dotenv import load_dotenv
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from utils.flatteners import flatten_kev, flatten_nvd


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
kev_json = DATA_DIR / "kev.json"
kev_out = OUT_DIR / "kev"

# ---------- CLI --------------
parser = argparse.ArgumentParser()
parser.add_argument("--model", default="text-embedding-3-small")
parser.add_argument("--topk-test", type=int, default=3)
args = parser.parse_args()

embeddings = OpenAIEmbeddings(model=args.model, show_progress_bar=True)


def build_kev_index():
    # ---------- Build / Skip KEV index ----------

    if index_is_fresh(kev_json, kev_out):
        print("✅ KEV index up-to-date – skipping build")
    else:
        print("🔄 Building KEV index …")
        kev_raw = json.load(kev_json.open())
        kev_docs = [flatten_kev(e) for e in kev_raw["vulnerabilities"]]
        FAISS.from_documents(kev_docs, embeddings).save_local(kev_out)
        print("✅ Saved KEV index to data/vectorstore/kev\n")


def build_nvd_index():
    # ---------- Build / Skip NVD index ----------
    nvd_json = DATA_DIR / "nvd_subset.json"
    nvd_out = OUT_DIR / "nvd"

    if index_is_fresh(nvd_json, nvd_out):
        print("✅ NVD index up-to-date – skipping build")
    else:
        print("🔄 Building NVD index …")
        nvd_raw = json.load(nvd_json.open())
        nvd_docs = [flatten_nvd(item) for item in nvd_raw.values()]
        FAISS.from_documents(nvd_docs, embeddings).save_local(nvd_out)
        print("✅ Saved NVD index to data/vectorstore/nvd\n")


build_kev_index()
build_nvd_index()

# ---------- Smoke-test query ----------
if args.topk_test > 0:
    print(f"\n🔎 top-{args.topk_test} KEV matches for 'Fortinet stack overflow'")
    faiss_kev = FAISS.load_local(kev_out, embeddings, allow_dangerous_deserialization=True)
    for doc, score in faiss_kev.similarity_search_with_score(
        "Fortinet stack overflow", k=args.topk_test
    ):
        print(f"• {doc.metadata['cve_id']} | score={score:.4f}")
        print(f"  {doc.page_content.splitlines()[1][:100]}…\n")
