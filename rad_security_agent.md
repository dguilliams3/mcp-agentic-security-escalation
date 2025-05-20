# 8. Agent Architecture and MCP Tools

In this section, we'll explore the core agent architecture and the MCP (Model Control Protocol) tools it uses to analyze security incidents and identify relevant CVEs.

## 8.1 MCP Server: Tool Definitions

Our agent uses a toolkit of specialized functions for incident analysis. These tools are defined in `mcp_cve_server.py` and exposed via the MCP protocol.

**Why we do this:** 
- MCP provides a standardized way for LLMs to interact with external tools
- Tools are defined with rich metadata (annotations) to guide the LLM
- The server handles caching, error handling, and logging consistently
- Tool definitions are separate from agent logic, enabling reuse

```python
# Core tool definitions from mcp_cve_server.py
from fastmcp import FastMCP
from utils.decorators import timing_metric, cache_result

mcp = FastMCP("cve")

@mcp.tool(annotations={
    "title": "Match Incident to CVEs using semantic search",
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False
})
@timing_metric
@cache_result(ttl_seconds=30)  # cache identical incident queries for 30s
def match_incident_to_cves_tool(incident_id: str, k: int = 5, use_mmr: bool = True) -> dict:
    """
    Match an incident to potentially relevant CVEs using semantic search.
    
    Args:
        incident_id: The ID of the incident to match
        k: Maximum number of matches to return
        use_mmr: Whether to use MMR for diversity
        
    Returns:
        Dict containing matching CVEs from KEV and NVD databases
    """
    return match_incident_to_cves(incident_id, k, use_mmr)

@mcp.tool(
  annotations={
    "title": "Semantic Free-Form CVE Search",
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False
  }
)
@timing_metric
@cache_result(ttl_seconds=30)  # cache identical free-form queries
def semantic_search_cves_tool(
    query: str,
    sources: List[str] = ["kev", "nvd", "historical"],
    k: int = 5,
    use_mmr: bool = False,
    lambda_mult: float = 0.7
) -> Dict[str, Any]:
    """
    Perform a semantic search for CVEs using a free-form query.
    
    Args:
        query: Free-form search query
        sources: Which databases to search ("kev", "nvd", "historical")
        k: Maximum number of results per source
        use_mmr: Whether to use MMR for diversity
        lambda_mult: Diversity parameter for MMR
        
    Returns:
        Dict containing search results from specified sources
    """
    return semantic_search_cves(query, sources, k, use_mmr, lambda_mult)

@mcp.tool(annotations={
    "title": "Search NVD Entries for a specific match for ALL words in the query",
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": False
})
@timing_metric
@cache_result(ttl_seconds=30)  # cache identical free-form queries
def search_nvd(query: str, limit: int = 10) -> list[dict]:
    """
    Return up to `limit` full CVE records whose fields match ALL words in `query`.
    Case-insensitive substring match over CVE ID, description, and any reference URLs.
    """
    qwords = query.lower().split()
    matches = []
    for cve_id, rec in NVD_INDEX.items():
        # flatten searchable text
        desc = rec.get("cve", {}) \
                  .get("description", {}) \
                  .get("description_data", [{}])[0] \
                  .get("value", "")
        refs = " ".join([r.get("url","") for r in rec.get("cve",{}) \
                                          .get("references",{}) \
                                          .get("reference_data",[])])
        text = f"{cve_id} {desc} {refs}".lower()
        if all(w in text for w in qwords):
            # return the full record so the agent can inspect any fields
            matches.append(rec)
            if len(matches) >= limit:
                break
    return matches
```

## 8.2 Prompt Engineering

The heart of our agent is the prompt that guides its reasoning. Let's examine our prompt engineering strategy:

**Why we do this:** Well-crafted prompts are critical for LLM performance. Our prompts are designed to:
- Provide clear instructions and context
- Include example formats for outputs
- Guide the agent to use appropriate tools at the right time
- Support structured JSON output via Pydantic models

```python
# Prompt template from utils/prompt_utils.py
SYSTEM_TMPL = """
You are a CVE‐analysis assistant. Analyze the following incidents and provide structured analysis.

Incident Details:
{incident_details}

Batch FAISS matches (KEV/NVD):
{batch_faiss_results}

Historical FAISS‐anchoring context:
{historical_faiss_results}

{format_instructions}

Now, when I ask you to analyze incidents, use the KEV/NVD context to inform your severity rankings and the historical context to normalize your severity rankings.
"""

# Human query example
query = """
I need you to help me analyze some security incidents and rank their actual severity, using identify potential CVE connections and details.
For each incident:
1. Understand Incident Context: Reason about the affected assets, observed TTPs, and initial findings.
2. Identify Relevant CVEs: Determine which CVEs are potentially relevant based on the incident context.
3. Prioritize CVEs: Assess the risk and impact of relevant CVEs in the context of the specific incident.
4. Generate Analysis: Provide a brief, human-readable explanation of why certain CVEs are prioritized.
"""
```

## 8.3 Pydantic Output Parsing

We use Pydantic models to define the structure of the agent's output:

**Why we do this:** Structured outputs ensure:
- Consistency in the format of analyses
- Validation of required fields
- Clear typing for downstream processing
- Enforced schema compliance

```python
# Pydantic models from utils/prompt_utils.py
from pydantic import BaseModel, Field
from langchain.output_parsers import PydanticOutputParser

class CVEInfo(BaseModel):
    """
    A Pydantic model for CVE information.
    This model defines the structure of the output from the CVE analysis.
    It includes fields for the CVE ID, summary, relevance, and risk level.
    """
    cve_id: str = Field(description="The CVE ID that is related to the incident")
    cve_summary: str = Field(description="A brief summary of the CVE and its relation to the incident")
    cve_relevance: float = Field(description="The estimated relevance level of the CVE match (0.0-1.0)")
    cve_risk_level: float = Field(description="The risk level of the CVE on a scale of (0.0-1.0)")

class IncidentAnalysis(BaseModel):
    """
    A Pydantic model for incident analysis.
    This model defines the structure of the output from the incident analysis.
    It includes fields for the incident ID, summary, list of related CVEs, and the risk level of the incident.
    """
    incident_id: str = Field(description="The ID of the incident that caused the error")
    incident_summary: str = Field(description="A brief summary of the incident")
    cve_ids: list[CVEInfo] = Field(description="List of related CVEs and their details")
    incident_risk_level: float = Field(description="The risk level of the incident (0.0-1.0)")
    incident_risk_level_explanation: str = Field(description="An explanation of the rationale for the risk level assessment")

class IncidentAnalysisList(BaseModel):
    incidents: list[IncidentAnalysis] = Field(description="List of incident analyses")

# Initialize the parser
parser = PydanticOutputParser(pydantic_object=IncidentAnalysisList)
```

## 8.4 LangChain ReAct Agent

We use LangChain's ReAct agent pattern to orchestrate the analysis process:

**Why we do this:** The ReAct agent pattern combines:
- **Re**asoning: Understanding the task and formulating a plan
- **Act**ion: Using tools to gather information
- Observation: Processing the results of tool calls
- Generation: Producing a final analysis

```python
# Agent setup from main_security_agent_server.py
import asyncio
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from mcp import ClientSession, StdioServerParameters, stdio_client

# Setup server parameters and model
server_parameters = StdioServerParameters(
    command="python",
    args=["mcp_cve_server.py"],
)
model = ChatOpenAI(model="gpt-4o-mini", openai_api_key=os.getenv("OPENAI_API_KEY"))

async def run_agent(query, start_index, batch_size):
    async with stdio_client(server_parameters) as (read, write):
        # Initialize client session
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Load MCP tools and create ReAct agent
            tools = await load_mcp_tools(session)
            agent = create_react_agent(model, tools, name="CVE_Agent")
            
            # Prepare incident batch and historical context
            batch_faiss_results = batch_match_incident_to_cves(
                batch_size=batch_size,
                start_index=start_index,
                top_k=3
            )
            
            historical_results = batch_get_historical_context(
                incident_ids=[r["incident_id"] for r in batch_faiss_results["results"]],
                top_k=2
            )
            
            # Generate prompt with all context
            prompt_messages = generate_prompt(
                query=query,
                batch_faiss_results=batch_faiss_results,
                historical_faiss_results=historical_results
            )
            
            # Execute agent
            final_msg, full_response = await agent.ainvoke({"messages": prompt_messages})
            
            # Parse and validate results
            analysis = parser.parse(final_msg.content)
            
            return analysis, full_response
```

## 8.5 Running the Agent

Let's run the agent to analyze a batch of security incidents:

**Why we do this:** Running a complete analysis demonstrates the end-to-end workflow and validates our agent's ability to:
- Understand incident context
- Find relevant CVEs
- Assess risk levels
- Provide clear explanations

```python
import asyncio
from utils.prompt_utils import AnalysisRequest

# Create a request to analyze a batch of incidents
async def analyze_incidents():
    request = AnalysisRequest(
        start_index=0,
        batch_size=2,
        request_id="demo-123",
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        model_name="gpt-4o-mini"
    )
    
    # Run the analysis
    analysis, response = await run_agent(
        query=query,
        start_index=request.start_index,
        batch_size=request.batch_size
    )
    
    # Display the results
    print("Analysis Results:")
    for incident in analysis.incidents:
        print(f"\nIncident: {incident.incident_id}")
        print(f"Summary: {incident.incident_summary}")
        print(f"Risk Level: {incident.incident_risk_level}")
        print(f"Explanation: {incident.incident_risk_level_explanation}")
        print("\nRelevant CVEs:")
        for cve in incident.cve_ids:
            print(f"  - {cve.cve_id} (Relevance: {cve.cve_relevance}, Risk: {cve.cve_risk_level})")
            print(f"    {cve.cve_summary}")
    
    # Display usage metrics
    print("\nUsage Metrics:")
    print(f"Input tokens: {response['usage_metadata']['input_tokens']}")
    print(f"Output tokens: {response['usage_metadata']['output_tokens']}")
    print(f"Total tokens: {response['usage_metadata']['total_tokens']}")
    
    return analysis

# Run the analysis
analysis = asyncio.run(analyze_incidents()) 