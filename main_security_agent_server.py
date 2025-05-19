# Required imports for async operations, LangChain components, and MCP client functionality
import os
import asyncio
# Immidiately set the event loop policy to the ProactorEventLoop if on Windows
if os.name == "nt":
    # on Windows, use the ProactorEventLoop so subprocesses work
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# +++ General Imports +++
import json
from dotenv import load_dotenv
from datetime import timedelta
import time
from typing import Any, Dict, List, Tuple
from contextlib import asynccontextmanager
import redis.asyncio as redis

# LangChain & MCP
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langchain_openai import OpenAIEmbeddings
from langchain_core.messages import AIMessage
from langchain.output_parsers import PydanticOutputParser
from mcp import ClientSession, StdioServerParameters, stdio_client

# FastAPI Imports
from fastapi import Depends, FastAPI, HTTPException

# Local imports
from utils.decorators import timing_metric, cache_result
from utils.logging_utils import setup_logger
from utils.retrieval_utils import (
    add_incident_to_history,
    get_incident,
    save_incident_analysis,
    batch_match_incident_to_cves,
    batch_get_historical_context
)
from utils.datastore_utils import init_db, save_incident_and_analysis_to_db, save_run_metadata
from utils.prompt_utils import generate_prompt, parser, AnalysisRequest

logger = None # We set this in the lifespan
MCP_SERVER_NAME = None # We set this in the lifespan
embeddings = None # We set this in the lifespan
server_parameters = None # We set this in the lifespan

# Initialize parser
# parser = PydanticOutputParser(pydantic_object=IncidentAnalysisList)

# model_name = os.getenv("MODEL_NAME", "gpt-4o-mini")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost")
redis = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)

@asynccontextmanager
async def lifespan(_: FastAPI):
    # Startup
    global logger, embeddings, MCP_SERVER_NAME, server_parameters

    load_dotenv()
    logger = setup_logger()
    logger.info("FastAPI application starting up...")

    logger.info("Initializing embeddings...")
    embeddings = OpenAIEmbeddings()

    MCP_SERVER_NAME = os.getenv("MCP_SERVER_NAME", "mcp_cve_server.py")

    init_db()
    logger.info(f"Configuring server parameters for mcp server {MCP_SERVER_NAME}...")
    server_parameters = StdioServerParameters(
        command="python",
        args=[MCP_SERVER_NAME],
    )
    logger.info("FastAPI application startup initialization complete.")

    yield  # This is where the application runs

    # Shutdown (if needed)
    logger.info("Shutting down...")

# Update the FastAPI app initialization to use the lifespan
app = FastAPI(title="MCP CVE Analysis Agent API", lifespan=lifespan)

async def claim_request_id(request: AnalysisRequest):
    """Ensure we don't process the same request twice by capturing the request_id in Redis"""
    key = f"processed:{request.request_id}"
    ok = await redis.setnx(key, "1")
    if not ok:
        raise HTTPException(
            status_code=409,
            detail=f"Request {request.request_id!r} is already processed."
        )
    await redis.expire(key, 3600)


query = """
I need you to help me analyze some security incidents and rank their actual severity, using identify potential CVE connections and details.
Let's start with a small sample to test the system:
1. Note the incident IDs and summaries you have available to you already.
2. For each incident:
    a.  Understand Incident Context: Reason about the affected assets, observed TTPs, and initial findings.
    b.  Identify Relevant CVEs: Determine which CVEs are potentially relevant based on the incident context and affected software/hardware, using LLM reasoning and potentially querying data sources.
    c.  Prioritize CVEs: Assess the risk and impact of relevant CVEs in the context of the specific incident, going beyond standard scores like CVSS.
    d.  Generate Analysis: Provide a brief, human-readable explanation of why certain CVEs are prioritized, linking them back to the incident details.
3. Finally, and most importantly, provide an organized list of all analyzed incidents in the following format:
{
    "incidents": [
        {
            "incident_id": "The ID of the incident that caused the error",
            "incident_summary": "A brief summary of the incident",
            "cve_ids": [
                {
                    "cve_id": "The CVE ID that is related to the incident",
                    "cve_summary": "A brief summary of the CVE and its relation to the incident",
                    "cve_relevance": "The estimated relevance level of the CVE match (0.0-1.0)",
                    "cve_risk_level": "The risk level of the CVE on a scale of (0.0-1.0)"
                }
            ],
            "incident_risk_level": "The risk level of the incident (0.0-1.0)",
            "incident_risk_level_explanation": "An explanation of the rationale for the risk level assessment"
        }
    ]
}

Note: If any tools return an error, please give the exact response, the exception details, and any additional specific details of the error and the tool in question. Format this as a JSON object with the following keys:
{
    "error": "The exact error message from the tool",
    "tool": "The name of the tool that returned the error",
    "input_variables": "The input variables that were used to call the tool",
    "error_details": "Any additional specific details of the error (included returned responses)"
}
"""

# For debugging, we can use the following query:
debug_query = """
# I need you to help me analyze some security incidents and identify potential CVE connections. Let's start with a small sample to test the system:

# First, we need to do a meta test to debug.  Please try all of the tools you have.  List what you did and what specific inputs you gave to which functions and what the reutnred value(s) or errors were.
# Focus mainly on just getting a single incident ID, then describe your process for trying to map it to a CVE ID given the tools you have.

# Actively perform the steps, always specifying exactly which functions you executed, the exact inputs, and the exact returned output or error message, you describe and give a full report of the results of what you did and what happened along the way.
# """

@timing_metric
@cache_result(ttl_seconds=3600)
async def ask_agent(agent, query: str):
    logger.info("Executing agent query:")
    logger.debug(f"Query: {query}")
    # Use invoke with proper message format and await the response
    response = await agent.ainvoke({ "messages": query })

    # Get the final AI message (the actual analysis)
    final_message = next(msg for msg in reversed(response["messages"])
                        if isinstance(msg, AIMessage) and msg.content)
    logger.debug(f"Final message: {final_message}")
    # Return both the final message and the response json with metadata
    return final_message, response

@timing_metric
@cache_result(ttl_seconds=3600)
async def ask_mcp_agent(server_parameters, model, query, start_index: int, batch_size: int = 5, request_id: str = None):
    start_ts = time.perf_counter()
    error_count = 0
    try:
        logger.info("Starting MCP agent...")
        async with stdio_client(server_parameters) as (read, write):
            logger.info("Server connection established!")
            # Initialize client session for communication
            async with ClientSession(
                read,
                write,
                read_timeout_seconds=timedelta(seconds=15)
            ) as session:
                logger.info("Initializing client session...")
                await session.initialize()
                logger.info("Client session initialized!")
                # Load MCP tools and create ReAct agent
                tools = await load_mcp_tools(session)
                logger.info(f"MCP tools loaded.  Tools count: {len(tools)}")
                logger.debug(f"Tool names: {[tool.name for tool in tools]}")

                # Create the agent with the returned tools and sent the query
                agent = create_react_agent(model, tools, name="CVE_Agent")
                logger.info(f"Agent {agent.name} created and ready to process requests!")

                logger.info("Querying KEV/NVD indexes...")
                batch_faiss_results = batch_match_incident_to_cves(
                    batch_size=batch_size,
                    start_index=start_index,
                    top_k=3
                )
                logger.info("KEV/NVD indexes queried successfully!")
                logger.debug(f"Batch FAISS results: {batch_faiss_results}")

                # Extract incident IDs from batch_faiss_results
                incident_ids = [
                    result["incident_id"]
                    for result in batch_faiss_results.get("results", [])
                    if "incident_id" in result
                ]
                logger.info(f"Found {len(incident_ids)} incidents to analyze")

                logger.info("Querying historical context...")
                historical_faiss_results = batch_get_historical_context(
                    incident_ids=incident_ids,  # Use the specific incident IDs
                    top_k=3  # Get top 3 similar incidents for each
                )
                logger.info("Historical context queried successfully!")
                logger.debug(f"Historical context results: {historical_faiss_results}")

                logger.info("Generating prompt...")
                prompt = generate_prompt(query, batch_faiss_results, historical_faiss_results)
                logger.info("Prompt generated successfully!")
                logger.debug(f"Prompt: {prompt}")

                logger.info("Asking agent...")
                final_message, response = await ask_agent(agent, prompt)
                logger.info("Agent asked successfully!")

                # Save the analysis if it's a valid JSON response
                try:
                    if isinstance(final_message.content, str):
                        # Parse the response using our Pydantic model
                        logger.info("Parsing response using Pydantic model...")
                        analysis_list = parser.parse(final_message.content)
                        logger.info("Response parsed successfully!")

                        # Save each incident analysis
                        logger.info(f"Saving {len(analysis_list.incidents)} incident analyses to database and adding historical context to FAISS index...")
                        for analysis in analysis_list.incidents:
                            # Save the individual incident analysis.
                            # Note: We wouldn't need this in a larger system, we'd simply use the below writing to a database/datastore instead,
                            # but we keep it here for the sake of the demo and to show how we'd do it in a larger system.
                            await save_incident_analysis(analysis.incident_id, analysis.model_dump())

                            # Get the incident data and add to historical data FAISS index for future use
                            logger.debug(f"Getting incident data for incident_id: {analysis.incident_id}...")
                            incident = get_incident(analysis.incident_id)
                            # Check if it's found, and if so, add to historical data FAISS index
                            if incident.get("found"):
                                logger.debug("Incident found data found!")
                                logger.debug(f"Adding incident to historical data FAISS index for incident_id: {analysis.incident_id}...")
                                incident_data = incident["incident_data"]
                                await add_incident_to_history(incident_data, analysis.model_dump())
                            else:
                                logger.error(f"Incident not found for incident_id: {analysis.incident_id}")
                                incident_data = None

                            # Here, we save both the incident and analysis to a database for retrieval, lineage, reporting, etc. with the request_id as the primary key
                            # Note that we are saving even if we don't find the incident!
                            logger.info(f"Saving incident and analysis to database for request_id: {request_id}, incident_id: {analysis.incident_id}...")
                            save_incident_and_analysis_to_db(
                                request_id=request_id,
                                incident_id=analysis.incident_id,
                                model_name=model.name,
                                incident=incident_data, # We save the incident data itself since the incident object contains metadata from the get_incident() call
                                analysis=analysis.model_dump()
                            )
                except Exception as e:
                    logger.error(f"Error processing analysis: {str(e)}")
                    logger.debug(f"Raw response content: {final_message.content}")

                # Log results
                logger.info("Processing complete!")
                logger.debug("Response messages metadata: %s",
                    [(m.id, getattr(m, "additional_kwargs", {}))
                    for m in response["messages"]])
    except Exception as e:
        error_count += 1
        logger.debug(f"Added error {e} to error count: {error_count}")
        raise
    finally:
        # Capture total duration and error count if any
        duration = time.perf_counter() - start_ts
        logger.debug(f"Total duration: {duration:.2f} seconds (request_id={request_id})")
        logger.info(f"Total errors: {error_count}")

        # Capture total token usage
        usage_metrics = {}
        if "final_message" in locals():
            usage_metadata = final_message.usage_metadata
            usage_metrics = {
                "input_tokens": usage_metadata.get("input_tokens"),
                "output_tokens": usage_metadata.get("output_tokens"),
                "total_tokens": usage_metadata.get("total_tokens"),
                "input_token_details": usage_metadata.get("input_token_details"),
                "output_token_details": usage_metadata.get("output_token_details")
            }
        logger.debug(f"Usage metrics: {usage_metrics}")

        # Pull tool names out of your ToolMessage calls
        tools = []
        if "response" in locals():
            for msg in response["messages"]:
                if hasattr(msg, "additional_kwargs") and msg.additional_kwargs.get("tool_calls"):
                    for call in msg.additional_kwargs["tool_calls"]:
                        tools.append(call["function"]["name"])
            logger.debug(f"Tools called: {tools}")

        # finally save the run‐level row
        save_run_metadata(
            request_id     = request_id,
            start_index    = start_index,
            batch_size     = batch_size,
            usage_metrics  = usage_metrics,
            tools          = tools,
            duration       = duration,
            error_count    = error_count
        )


@timing_metric
@cache_result(ttl_seconds=3600)
@app.post("/analyze_incidents")
async def analyze_incidents(request: AnalysisRequest, _dedupe: None = Depends(claim_request_id)):
    try:
        logger.info(f"Request received!\nRequest_id: {request.request_id}")
        logger.debug(f"Request: {request}")
        model_name = request.model_name
        logger.info(f"Initializing Model {model_name}...")

        try:
            openai_api_key = request.openai_api_key
            if not openai_api_key:
                logger.info("OPENAI_API_KEY not found in request, checking environment variables...")
                openai_api_key = os.getenv("OPENAI_API_KEY","")
                if not openai_api_key:
                    logger.error("OPENAI_API_KEY not found in environment variables either!")
                    raise HTTPException(status_code=401, detail="OPENAI_API_KEY not included in request and not found in environment variables.")

            model = ChatOpenAI(openai_api_key=openai_api_key, model=model_name)
            logger.info(f"Model {model_name} initialized successfully!")
        except Exception as e:
            logger.error(f"Error initializing model: {e}")
            raise HTTPException(status_code=500, detail=f"Error initializing model: {e}")

        await ask_mcp_agent(
            request_id=request.request_id,
            server_parameters=server_parameters,
            model=model,
            query=query,
            start_index=request.start_index,
            batch_size=request.batch_size
        )

        return {
            "status": "success",
            "request_id": request.request_id,
            "message": f"Successfully processed {request.batch_size} incidents starting at index {request.start_index}"
        }
    except Exception as e:
        # this will print the full traceback to your console
        logger.exception(f"Uncaught error in /analyze_incidents (request_id={request.request_id}):")
        # then turn it into a 500 so your client still sees 500
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error, check server logs (request_id={request.request_id})"
        )

@app.get("/health", tags=["Internal"])
async def health_check():
    """
    Simple health check endpoint.
    Returns 200 OK with a basic status payload.
    """
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 