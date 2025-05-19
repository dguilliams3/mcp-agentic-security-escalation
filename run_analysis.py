#!/usr/bin/env python
import os
import uuid
import asyncio
from dotenv import load_dotenv
import httpx

load_dotenv()

API_URL      = os.getenv("API_URL", "http://localhost:8000/analyze_incidents")
OPENAI_KEY   = os.getenv("OPENAI_API_KEY")
MODEL_NAME   = os.getenv("MODEL_NAME", "gpt-4o-mini")
TOTAL        = int(os.getenv("TOTAL_INCIDENTS", "39"))
BATCH_SIZE   = int(os.getenv("BATCH_SIZE", "5"))
CONCURRENCY  = int(os.getenv("CONCURRENCY", "3"))  # how many batches at once
START_INDEX  = int(os.getenv("START_INDEX", "0"))

if not OPENAI_KEY:
    raise RuntimeError("Please set OPENAI_API_KEY in your .env")

async def analyze_batch(client: httpx.AsyncClient, start: int) -> dict:
    payload = {
        "start_index":    start,
        "batch_size":     BATCH_SIZE, 
        "request_id":     str(uuid.uuid4()),
        "openai_api_key": OPENAI_KEY,
        "model_name":     MODEL_NAME
    }
    resp = await client.post(API_URL, json=payload, timeout=60.0)
    resp.raise_for_status()
    return {"start": start, "result": resp.json()}

async def main():
    async with httpx.AsyncClient() as client:
        start_indexes = list(range(0, TOTAL, BATCH_SIZE))
        semaphore = asyncio.Semaphore(CONCURRENCY)

        async def guarded(start_index):
            async with semaphore:
                try:
                    out = await analyze_batch(client, start_index)
                    print(f"✅ Batch @ {start_index}: {out['result']}")
                except Exception as e:
                    print(f"❌ Batch @ {start_index} failed:", e)

        # schedule all tasks at once
        tasks = [asyncio.create_task(guarded(start_index)) for start_index in start_indexes]
        # wait for all to finish
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())

    # dev/query_db.py
    import sqlite3
    import pandas as pd

    conn = sqlite3.connect("data/incident_analysis.db")
    df = pd.read_sql_query("SELECT * FROM incident_analysis", conn)
    pd.set_option("display.max_columns", None)
    pd.set_option("display.width", None)

    print(df)
    conn.close()