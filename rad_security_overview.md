# RAD Security: CVE-Aware Analysis Agent

## AI Engineer Take-Home Exercise

This document outlines the architecture and implementation of an LLM-powered agent designed to analyze security incidents in the context of CVE data. The agent uses semantic search, retrieval-augmented generation, and structured agent tools to provide contextual prioritization of security vulnerabilities.

### Key Features

- **Semantic Search**: Searches over KEV, NVD, and historical incident records
- **Agent Tools**: Uses MCP (Model Control Protocol) for structured tool access
- **Contextual Prioritization**: Ranks CVEs based on their relevance to specific incidents
- **Historical Learning**: Builds a vector store of past analyses for normalization
- **Persistence**: Stores analyses in SQLite for future reference

## Why This Architecture

The architecture is designed to address several key challenges in security incident analysis:

1. **Volume Challenge**: Security teams face thousands of CVEs and alerts daily
2. **Context Challenge**: Understanding the relationship between vulnerabilities and incidents requires contextual knowledge
3. **Expertise Challenge**: Security expertise is scarce and expensive
4. **Consistency Challenge**: Manual analysis leads to inconsistent prioritization

Our solution uses LLMs and semantic search to understand incident context, identify relevant CVEs, prioritize them based on impact, and generate human-readable explanations of the analysis.

## 1. Setup and Dependencies

Let's start by installing the required dependencies and setting up our environment.

**Why we do this:** Ensuring all required packages are available creates a reproducible environment. This setup step loads essential libraries for LangChain, LangGraph, OpenAI, FAISS vector storage, and Redis caching.

```python
# Install requirements
%pip install -r requirements.txt

# Below is our requirements.txt content for reference
# aiohttp==3.8.5
# fastapi==0.100.0
# fastmcp==0.2.0
# httpx==0.25.0
# langchain==0.0.331
# langchain-community==0.0.11
# langchain-core==0.1.3
# langchain-mcp-adapters==0.0.3
# langchain-openai==0.0.2
# langgraph==0.0.16
# openai==1.1.2
# pydantic==2.4.2
# python-dotenv==1.0.0
# redis==4.6.0
# numpy==1.24.4
# faiss-cpu==1.7.4
# uvicorn==0.23.2
# sqlalchemy==2.0.19
# streamlit==1.26.0
```

## 2. Start Redis (for Idempotency Cache)

We'll use Redis for request deduplication and caching. This ensures our system is idempotent and avoids redundant processing.

**Why we do this:** Redis provides fast, in-memory caching that helps us:
1. Deduplicate analysis requests (idempotency)
2. Cache expensive operations like semantic searches
3. Reduce API costs and latency by storing LLM responses
4. Ensure consistent behavior even with intermittent failures

```python
# Start Docker Service for Redis:
!docker run -d --name local-redis -p 6379:6379 redis:latest
```

## 3. System Architecture Overview

Our system follows a layered architecture with distinct components handling specific responsibilities:

```
┌─────────────────────────────────┐
│          Client Layer           │
│ (Notebook, run_analysis.py)     │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│        API Service Layer        │
│ (main_security_agent_server.py) │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│        Agent Layer             │
│ (LangChain, LangGraph, ReAct)   │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│       Tools Layer               │
│ (MCP Server, mcp_cve_server.py) │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│       Storage Layer             │
│ (FAISS, Redis, SQLite)          │
└─────────────────────────────────┘
```

**Why this architecture:** 

1. **Separation of Concerns**: Each layer has a distinct responsibility
2. **Scalability**: Components can be scaled independently
3. **Resilience**: Failures in one layer don't cascade to others
4. **Maintainability**: Easier to update or replace individual components
5. **Testing**: Components can be tested in isolation

### Key Project Files and Their Roles

```
.
├── main_security_agent_server.py  # FastAPI server coordinating analysis
├── mcp_cve_server.py              # Tool server providing CVE search capabilities
├── run_analysis.py                # CLI script for batch processing
├── data/                          # Data storage
│   ├── incidents.json             # Input security incidents
│   ├── kev.json                   # Known Exploited Vulnerabilities
│   ├── nvd_subset.json            # National Vulnerability Database subset
│   └── vectorstore/               # FAISS vector indexes
├── setup/                         # Setup scripts
│   ├── download_cve_data.py       # Downloads CVE data
│   └── build_faiss_indexes.py     # Builds vector indexes
└── utils/                         # Utility functions
    ├── retrieval_utils.py         # Vector search functions
    ├── flatteners.py              # Text preprocessing for embeddings
    ├── prompt_utils.py            # Prompt generation
    ├── datastore_utils.py         # Database operations
    └── decorators.py              # Logging and caching
``` 