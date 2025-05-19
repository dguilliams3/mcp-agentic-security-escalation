# FAISS Index Building Scripts

## Overview
These scripts are used to create FAISS vector indexes for different data sources in the MCP Agents RADSecurity project.

## Prerequisites
- Python 3.8+
- OpenAI API Key
- Required Python packages (install via `pip install -r requirements.txt`)

## Available Scripts

### `build_faiss_indexes.py`
Builds FAISS indexes for:
- Known Exploited Vulnerabilities (KEV)
- National Vulnerability Database (NVD)

### `build_historical_incident_analyses_index.py`
Builds a FAISS index for historical incident analyses from `incidents.json`

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

## Customization
- Use `--model` argument to specify a different embedding model
- Use `--topk-test` to control the number of test matches displayed

## Notes
- Indexes are saved in `data/vectorstore/`
- Scripts check timestamp to avoid unnecessary re-embedding
- Requires `utils.flatteners` module for document preparation 