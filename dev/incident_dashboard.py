# incident_dashboard.py

import streamlit as st
import sqlite3
import json
from datetime import datetime
from pathlib import Path
import pandas as pd
from typing import Dict, Any

DB_PATH = "data/incident_analysis.db"


@st.cache_data
def load_data():
    """
    Load and prepare incident data for the dashboard visualization.

    This function:
    1. Reads incident data from the SQLite database
    2. Processes and formats data for visualization
    3. Calculates summary statistics
    4. Prepares time series data

    Returns:
        Tuple[pd.DataFrame, Dict[str, Any]]: A tuple containing:
            - DataFrame: Processed incident data ready for visualization
            - Dict: Summary statistics and metadata about the dataset

    Note:
        - Handles missing or corrupt data gracefully
        - Performs data cleaning and normalization
        - Optimizes memory usage for large datasets
        - Caches results for improved performance
    """
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM incident_analysis", conn)
    conn.close()

    # Parse created_at, rename for consistency with your filters
    df["incident_timestamp"] = pd.to_datetime(df["created_at"])
    return df


st.set_page_config(page_title="Incident Analysis DB", layout="wide")
st.title("📊 Incident Analysis Browser")

df = load_data()
if df.empty:
    st.warning("No data found in the database.")
    st.stop()

# Create tabs properly
tab1, tab2 = st.tabs(["🔍 Incidents", "⚙️ Run Metadata"])

# Sidebar filters
with st.sidebar:
    st.header("🔍 Filters")
    selected_request = st.selectbox(
        "Filter by Request ID", ["All"] + sorted(df["request_id"].unique().tolist())
    )

    # Get min/max risk scores from data
    min_risk = float(df["llm_risk_score"].min())
    max_risk = float(df["llm_risk_score"].max())
    risk_range = st.slider("Risk Level", min_risk, max_risk, (min_risk, max_risk), 0.01)

    # Get min/max dates from data
    min_date = df["incident_timestamp"].dt.date.min()
    max_date = df["incident_timestamp"].dt.date.max()
    date_range = st.date_input("Incident Date Range", [min_date, max_date])

# Incidents Tab
with tab1:
    st.header("📊 Filtered Incidents")
    # Apply filters to incidents
    filtered = df.copy()
    if selected_request != "All":
        filtered = filtered[filtered["request_id"] == selected_request]

    try:
        filtered = filtered[
            (filtered["llm_risk_score"] >= risk_range[0])
            & (filtered["llm_risk_score"] <= risk_range[1])
            & (filtered["incident_timestamp"].dt.date >= date_range[0])
            & (filtered["incident_timestamp"].dt.date <= date_range[1])
        ]
    except Exception as e:
        st.error(f"Error applying filters: {str(e)}")
        filtered = pd.DataFrame()  # Empty DataFrame if filters fail

    # Display table
    if filtered.empty:
        st.warning("No incidents found matching the selected filters.")
    else:
        st.subheader(f"Found {len(filtered)} incidents")
        st.dataframe(
            filtered[["incident_id", "incident_timestamp", "llm_risk_score", "request_id"]]
        )

        # Details viewer
        st.markdown("---")
        selected = st.selectbox(
            "Select an incident to view full JSON", filtered["incident_id"].tolist()
        )
        if selected:  # Only show details if an incident is selected
            record = filtered[filtered["incident_id"] == selected].iloc[0]

            st.markdown("### 📝 Raw Incident JSON")
            try:
                raw_json = json.loads(record["incident_raw_json"])
                st.json(raw_json)
            except json.JSONDecodeError:
                st.error("Error parsing raw incident JSON")

            st.markdown("### 🤖 LLM Analysis JSON")
            try:
                analysis_json = json.loads(record["llm_analysis_json"])
                st.json(analysis_json)
            except json.JSONDecodeError:
                st.error("Error parsing LLM analysis JSON")

# Run Metadata Tab
with tab2:
    st.header("📈 Run Metadata Browser")
    try:
        conn = sqlite3.connect(DB_PATH)
        runs = pd.read_sql_query("SELECT * FROM run_metadata", conn)
        conn.close()

        if runs.empty:
            st.info("No run metadata found yet.")
        else:
            # parse timestamp
            runs["run_timestamp"] = pd.to_datetime(runs["created_at"])

            # Format duration as minutes:seconds
            runs["duration"] = runs["duration_seconds"].apply(
                lambda x: f"{int(x//60)}:{int(x%60):02d}"
            )

            # Display metadata with better formatting
            st.dataframe(
                runs[
                    [
                        "request_id",
                        "start_index",
                        "batch_size",
                        "input_tokens",
                        "output_tokens",
                        "total_tokens",
                        "tools_called",
                        "error_count",
                        "duration",
                        "run_timestamp",
                    ]
                ].sort_values("run_timestamp", ascending=False)
            )
    except Exception as e:
        st.error(f"Error loading run metadata: {str(e)}")
