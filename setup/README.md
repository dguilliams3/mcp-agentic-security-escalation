# FAISS Index Building Scripts

## Overview
These scripts are used to create FAISS vector indexes for different data sources in the MCP Agents RADSecurity project.

## Prerequisites
- Python 3.11+
- OpenAI API Key
- Required Python packages (install via `pip install -r requirements.txt`)

## Available Scripts

### `download_cve_data.py`
- Downloads KEV data from streaming URL
- Downloads NVD entries from 2025, unzips, and creates a smaller JSON by mapping from `incident.json`'s affected-software information.

### `build_faiss_KEV_and_NVD_indexes.py`
Builds FAISS indexes for:
- Known Exploited Vulnerabilities (KEV)
- National Vulnerability Database (NVD)

### `build_historical_incident_analyses_index.py`
Builds a FAISS index for historical incident analyses from `incidents.json`

### `setup_initial_CVE_data_and_FAISS_indexes.sh`
Shell script to just run the data setup in one go.

## Usage

1. Ensure you have a `.env` file with your OpenAI API key:
   ```
   OPENAI_API_KEY=sk-your_openai_api_key_here
   ```

2. Run the scripts:
   ```bash
   # Build all indexes
   python scripts/build_faiss_indexes.py

   # Build historical incident analyses index
   python scripts/build_historical_incident_analyses_index.py
   ```

Or simply
   ```bash
   sh setup_initial_CVE_data_and_FAISS_indexes.sh
   ```
  
## Customization
- Use `--model` argument to specify a different embedding model
- Use `--topk-test` to control the number of test matches displayed

## Notes
- Indexes are saved in `data/vectorstore/`
- Scripts check timestamp to avoid unnecessary re-embedding
- Requires `utils.flatteners` module for document preparation