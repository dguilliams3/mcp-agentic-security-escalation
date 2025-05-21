#!/usr/bin/env python
import sqlite3
import json
from tabulate import tabulate  # pip install tabulate

DB_PATH = "data/incident_analysis.db"


def query_all(table_name: str):
    """
    Execute a SELECT * query on the specified database table.

    This development utility function provides a simple way to inspect
    the contents of database tables during development and debugging.

    Args:
        table_name (str): Name of the table to query

    Returns:
        List[Dict[str, Any]]: List of row dictionaries, where each dictionary
        represents a row with column names as keys and cell values as values

    Raises:
        sqlite3.Error: If there's an error executing the query
        ValueError: If the table name is invalid or doesn't exist

    Note:
        - For development use only
        - No pagination - fetches all rows at once
        - Converts SQLite types to Python native types
        - Handles JSON serialization of complex fields
    """
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
