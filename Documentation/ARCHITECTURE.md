# Architecture Documentation

## System Overview

The Security CVE Analysis Agent is designed as a modular, scalable system that leverages AI to analyze security incidents and identify relevant CVEs. The system is built around several key components that work together to provide comprehensive security analysis.

```
┌─────────────────────────────────┐
│          Client Layer           │
│        (run_analysis.py)        │
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

## Component Breakdown

### 1. Client Layer

**Purpose**: Provides interfaces for users to interact with the system.

**Components**:
- `run_analysis.py`: CLI tool for batch processing of incidents
- Jupyter Notebooks: Interactive exploration and analysis
- (Future) Web UI: For interactive incident analysis

**Key Features**:
- Asynchronous batch processing
- Configurable concurrency and batch sizes
- Request idempotency via unique request IDs

### 2. API Service Layer

**Purpose**: Exposes system functionality via RESTful API endpoints.

**Components**:
- `main_security_agent_server.py`: FastAPI server
- API endpoints: `/analyze_incidents`, `/health`

**Key Features**:
- Request validation with Pydantic
- Redis-based request deduplication
- Comprehensive error handling
- Performance metrics and logging

### 3. Agent Layer

**Purpose**: Orchestrates the analysis workflow using LLM reasoning.

**Components**:
- LangChain ReAct agent
- Prompt templates and generation logic
- Output parsing and validation

**Key Features**:
- Tool selection and orchestration
- Complex reasoning about security incidents
- Structured output generation
- Chain-of-thought reasoning

### 4. Tools Layer

**Purpose**: Provides specialized tools for the agent to use during analysis.

**Components**:
- `mcp_cve_server.py`: MCP-based tool server
- Semantic search tools
- Keyword search tools
- Schema lookup tools

**Key Features**:
- Cached tool responses for efficiency
- Performance metrics for each tool
- Clean separation from agent logic

### 5. Storage Layer

**Purpose**: Manages data persistence and efficient retrieval.

**Components**:
- FAISS vector stores for semantic search
- Redis for caching and request deduplication
- SQLite for structured data storage

**Key Features**:
- Vector embeddings for semantic similarity
- Historical analysis storage
- Efficient data retrieval

## Data Flow

1. **Incident Input**:
   - User submits incidents via API or batch processing
   - System validates request format and checks for duplicates

2. **Semantic Analysis**:
   - Incidents are converted to vector embeddings
   - System searches KEV and NVD databases for relevant CVEs
   - Historical incident analyses are retrieved for context

3. **Agent Processing**:
   - LLM agent receives incident data, CVE matches, and historical context
   - Agent uses tools to gather additional information as needed
   - Agent reasons about relevance and risk

4. **Output Generation**:
   - Structured analysis is produced with prioritized CVEs
   - Analysis includes risk scores and explanations
   - Output is validated against Pydantic models

5. **Persistence**:
   - Analysis is stored in SQLite database
   - Vector embeddings are added to historical FAISS index
   - Results are returned to client

## Key Technologies

- **LangChain/LangGraph**: For agent orchestration and tool use
- **FAISS**: For efficient vector similarity search
- **FastAPI**: For API endpoints and request handling
- **Redis**: For caching and request deduplication
- **SQLite**: For structured data storage
- **OpenAI Embeddings**: For vector representations of text
- **Docker**: For containerization and deployment

## Performance Considerations

- **Caching**: Tool responses are cached to improve performance
- **Batch Processing**: Incidents are processed in configurable batches
- **Concurrency**: Multiple batches can be processed concurrently
- **Vector Search**: FAISS provides efficient similarity search
- **MMR**: Maximal Marginal Relevance ensures diverse, relevant results

## Deployment Architecture

The system is designed to be deployed as a set of Docker containers:

- **Redis**: For caching and request deduplication
- **MCP CVE Server**: For tool functionality
- **API Server**: For handling client requests
- **Analysis Runner**: For batch processing

These containers can be orchestrated using Docker Compose for development or Kubernetes for production deployments.

## Future Enhancements

1. **Scalability**: 
   - Horizontal scaling of API servers
   - Distributed vector stores

2. **Monitoring**:
   - Prometheus metrics
   - Grafana dashboards

3. **Feedback Loop**:
   - User feedback incorporation
   - Continuous model improvement

4. **Additional Data Sources**:
   - Threat intelligence feeds
   - Asset inventory integration 
