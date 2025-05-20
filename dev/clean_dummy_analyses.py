#!/usr/bin/env python3
"""
Script to remove duplicate entries from dummy_agent_incident_analyses.json.
This script reads the JSON file, identifies duplicates based on incident_id,
and overwrites the original file with a cleaned version keeping only the first occurrence of each incident_id.

NOTE: Largely useful when developing once the entries begin to pile up.  Local tool rather than part of the larger pipeline.
"""

import json
from pathlib import Path
from typing import List, Dict, Any


def remove_duplicates_by_incident_id(analyses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate entries from the analyses list based on incident_id.
    Only keeps the first occurrence of each incident_id.

    Args:
        analyses: List of analysis dictionaries

    Returns:
        List of unique analysis dictionaries (one per incident_id)
    """
    seen_incident_ids = set()
    unique_analyses = []

    for analysis in analyses:
        incident_id = analysis.get("incident_id")
        if incident_id and incident_id not in seen_incident_ids:
            seen_incident_ids.add(incident_id)
            unique_analyses.append(analysis)

    return unique_analyses


def main():
    # Setup paths
    data_dir = Path("data")
    input_file = data_dir / "dummy_agent_incident_analyses.json"

    # Read the input file
    print(f"Reading {input_file}...")
    with open(input_file) as f:
        analyses = json.load(f)

    # Get initial count
    initial_count = len(analyses)
    print(f"Initial number of analyses: {initial_count}")

    # Remove duplicates based on incident_id
    unique_analyses = remove_duplicates_by_incident_id(analyses)

    # Get final count
    final_count = len(unique_analyses)
    print(f"Final number of analyses: {final_count}")
    print(f"Removed {initial_count - final_count} duplicate incident_ids")

    # Overwrite the original file with cleaned data
    print(f"Overwriting {input_file} with cleaned data...")
    with open(input_file, "w") as f:
        json.dump(unique_analyses, f, indent=2)

    print("Done!")


if __name__ == "__main__":
    main()
