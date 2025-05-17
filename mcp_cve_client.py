# Required imports for async operations, LangChain components, and MCP client functionality
import asyncio
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from mcp import ClientSession, StdioServerParameters, stdio_client
from langchain_core.messages import HumanMessage, AIMessage
import os
from dotenv import load_dotenv
from utils.decorators import timing_metric, cache_result
from utils.logging_utils import setup_logger

load_dotenv()  # Load environment variables from .env file
logger = setup_logger()  # Optional: pass custom name or log_file

# Input variables (model_name, query, MCP_SERVER_NAME)
model_name = "gpt-4o-mini"
query = """
I need you to help me analyze some security incidents and rank their actual severity, using identify potential CVE connections and details. 
Let's start with a small sample to test the system:
1. Get 3 random incidents from our dataset
2. For each incident:
    a.  Understand Incident Context: Reason about the affected assets, observed TTPs, and initial findings. 
    b.  Identify Relevant CVEs: Determine which CVEs are potentially relevant based on the incident context and affected software/hardware, using LLM reasoning and potentially querying data sources. 
    c.  Prioritize CVEs: Assess the risk and impact of relevant CVEs in the context of the specific incident, going beyond standard scores like CVSS. 
    d.  Generate Analysis: Provide a brief, human-readable explanation of why certain CVEs are prioritized, linking them back to the incident details.
3. Finally, and most importantly, append an organized list of Incident IDs, brief descriptions, related CVEs with confidence levels, and your assessment on the actual risk level of the incident on a level between 1 and 10.
Format this as a JSON object with the following keys:
{
    "incident_id": "The ID of the incident that caused the error",
    "incident_summary": "A brief summary of the incident",
    "cve_ids": {
        "cve_id": "The CVE IDs that is related to the incident",
        "cve_summary": "A brief summary of the CVE and its relalation to the incident",
        "cve_relevance": "The estimated relevance level of the CVE match (0.0-1.0)",
        "cve_risk_level": "The risk level of the CVE on a scale of (0.0-1.0)"
    },
    "incident_risk_level": "The risk level of the incident (0.0-1.0)"
    "incident_risk_level_explanation": "An explanation, somewhat briefly, of the rationale for the risk level assessment for each of the incidents."
}

Note: If any tools return an error, please give the exact response, the exception details, and any additional specific details of the error and the tool in question. Format this as a JSON object with the following keys:
{
    "error": "The exact error message from the tool",
    "tool": "The name of the tool that returned the error",
    "input_variables": "The input variables that were used to call the tool",
    "error_details": "Any additional specific details of the error (included returned responses)"
}
"""

MCP_SERVER_NAME = os.getenv("MCP_SERVER_NAME", "mcp_cve_server.py")

# For debugging, we can use the following query:
debug_query = """
# I need you to help me analyze some security incidents and identify potential CVE connections. Let's start with a small sample to test the system:

# First, we need to do a meta test to debug.  Please try all of the tools you have.  List what you did and what specific inputs you gave to which functions and what the reutnred value(s) or errors were.
# Focus mainly on just getting a single incident ID, then describe your process for trying to map it to a CVE ID given the tools you have.

# Actively perform the steps, always specifying exactly which functions you executed, the exact inputs, and the exact returned output or error message, you describe and give a full report of the results of what you did and what happened along the way.
# """


# Get OpenAI API key from environment variables
openai_api_key = os.getenv("OPENAI_API_KEY")
if not openai_api_key:
    raise ValueError("OPENAI_API_KEY not found in environment variables. Please check your .env file.")

logger.info("OpenAI API key loaded successfully")

# Initialize ChatGPT model with specific version
logger.info(f"Initializing Model {model_name}...")
model = ChatOpenAI(openai_api_key=openai_api_key, model=model_name)

# Configure server parameters for the Python subprocess
server_parameters = StdioServerParameters(
    command="python",
    args=["mcp_cve_server.py"],
)

@timing_metric
@cache_result(ttl_seconds=3600)
async def ask_agent(agent, query: str):
    logger.info("Executing agent query...")
    # Use invoke with proper message format and await the response
    response = await agent.ainvoke({
        "messages": [
            HumanMessage(content=query)
        ]
    })
    
    # Get the final AI message (the actual analysis)
    final_message = next(msg for msg in reversed(response["messages"]) 
                        if isinstance(msg, AIMessage) and msg.content)
    
    # Return both the final message and the response json with metadata
    return final_message, response

@timing_metric
@cache_result(ttl_seconds=3600)
async def ask_mcp_agent(server_parameters, query):
    logger.info("Starting MCP agent...")
    async with stdio_client(server_parameters) as (read, write):
        logger.info("Server connection established!")
        # Initialize client session for communication
        async with ClientSession(read, write) as session:
            logger.info("Initializing client session...")
            await session.initialize()
            logger.info("Client session initialized!")
            # Load MCP tools and create ReAct agent
            tools = await load_mcp_tools(session)
            logger.info(f"MCP tools loaded.  Tools count: {len(tools)}")
            logger.info(f"Tool names: {[tool.name for tool in tools]}")

            # Create the agent with the returned tools and sent the query
            agent = create_react_agent(model, tools, name="CVE_Agent")
            logger.info(f"Agent {agent.name} created and ready to process requests")
            final_message, response = await ask_agent(agent, query)
            
            # Log results and return message and accompanying metadata
            logger.info("📝 Received final agent message")
            logger.debug("Response messages metadata: %s", 
                 [(m.id, getattr(m, "additional_kwargs", {})) 
                  for m in response["messages"]])

            return final_message, response

@timing_metric
@cache_result(ttl_seconds=3600)
async def main():
    server_parameters = StdioServerParameters(
        command="python",
        args=[MCP_SERVER_NAME],
    )
    final_message, response = await ask_mcp_agent(server_parameters, query)                              
    logger.info(f"Agent Raw Response:\n{response}")
    logger.info(f"Agent Analysis (final message):\n{final_message.content}")
    
if __name__ == "__main__":
    asyncio.run(main())
