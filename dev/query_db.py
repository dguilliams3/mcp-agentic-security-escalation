#!/usr/bin/env python
import sqlite3
import json
from tabulate import tabulate  # pip install tabulate

DB_PATH = "data/incident_analysis.db"

def query_all(table_name: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table_name} ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()

    if not rows:
        print("No records found.")
        return

    # Convert sqlite3.Row to dict
    data = [dict(row) for row in rows]

    print(tabulate(data, headers="keys", tablefmt="grid"))

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        table_name = sys.argv[1]
    else:
        table_name = "incident_analysis"
    query_all(table_name)
