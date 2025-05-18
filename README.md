# MCP CVE Server

## Overview

The MCP (Multi-Context Processor) CVE Server is a sophisticated vulnerability intelligence tool designed to provide semantic search and analysis capabilities across Known Exploited Vulnerabilities (KEV) and the National Vulnerability Database (NVD).

## Features

- 🔍 Semantic Search Across Vulnerability Databases
- 🔬 Incident-to-CVE Matching
- 📊 Flexible Query Capabilities
- 🚀 High-Performance Indexing

### Key Tools

1. **Semantic CVE Search**
   - Search across KEV and NVD databases
   - Supports multiple search strategies
   - Configurable result count and matching algorithm

2. **Incident Correlation**
   - Match incident details to potential CVEs
   - Supports multiple matching strategies

3. **Detailed Schema Exploration**
   - Retrieve schemas for KEV and NVD databases
   - Understand data structures programmatically

## Prerequisites

- Python 3.8+
- Dependencies listed in `requirements.txt`

## Installation

```bash
# Clone the repository
git clone https://github.com/dguilliams3/mcp-agentic-security-escalation.git

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`

# Install dependencies
pip install -r requirements.txt
```

## Configuration

1. Copy `.env.example` to `.env`
2. Configure any necessary environment variables

## Available Tools

### Semantic Search
```python
# Search CVEs
semantic_search_cves("remote code execution")

# Match incident to CVEs
match_incident_to_cves("incident_123")
```

## Development

### Running Tests
```bash
pytest tests/
```
