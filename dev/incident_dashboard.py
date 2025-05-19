# incident_dashboard.py

import streamlit as st
import sqlite3
import json
from datetime import datetime
from pathlib import Path
import pandas as pd

DB_PATH = "data/incident_analysis.db"

@st.cache_data
def load_data():
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
    st.stop()

tab = st.tabs(["🔍 Incidents", "⚙️ Run Metadata"])[0]

# Sidebar filters
with st.sidebar:
    st.header("🔍 Filters")
    selected_request = st.selectbox("Filter by Request ID", ["All"] + sorted(df["request_id"].unique().tolist()))
    risk_range = st.slider("Risk Level", 0.0, 1.0, (0.0, 1.0), 0.01)
    date_range = st.date_input("Incident Date Range", [df["incident_timestamp"].dt.date.min(), df["incident_timestamp"].dt.date.max()])

with tab:
    st.header("📊 Filtered Incidents")
    # Apply filters to incidents
    filtered = df.copy()
    if selected_request != "All":
        filtered = filtered[filtered["request_id"] == selected_request]

    filtered = filtered[
        (filtered["llm_risk_score"] >= risk_range[0]) &
        (filtered["llm_risk_score"] <= risk_range[1]) &
        (filtered["incident_timestamp"].dt.date >= date_range[0]) &
        (filtered["incident_timestamp"].dt.date <= date_range[1])
    ]

# Display table
st.subheader(f"Found {len(filtered)} incidents")
st.dataframe(filtered[["incident_id", "incident_timestamp", "llm_risk_score", "request_id"]])

# Details viewer
st.markdown("---")
selected = st.selectbox("Select an incident to view full JSON", filtered["incident_id"].tolist())
record = filtered[filtered["incident_id"] == selected].iloc[0]

st.markdown("### 📝 Raw Incident JSON")
st.json(json.loads(record["incident_raw_json"]))

st.markdown("### 🤖 LLM Analysis JSON")
st.json(json.loads(record["llm_analysis_json"]))

# -------------------------------------------------------------------
# Second tab: run_metadata
with st.tabs(["🔍 Incidents", "⚙️ Run Metadata"])[1]:
    st.header("📈 Run Metadata Browser")
    conn = sqlite3.connect(DB_PATH)
    runs = pd.read_sql_query("SELECT * FROM run_metadata", conn)
    conn.close()

    if runs.empty:
        st.info("No run metadata found yet.")
    else:
        # parse timestamp
        runs["run_timestamp"] = pd.to_datetime(runs["created_at"])
        st.dataframe(
            runs[[
                "id", "request_id", "start_index", "batch_size",
                "input_tokens", "output_tokens", "total_tokens",
                "tools_called", "error_count", "duration_seconds",
                "run_timestamp"
            ]]
        )