import os, json
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from langchain.output_parsers import PydanticOutputParser
from langchain.prompts import (
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
)
from utils.retrieval_utils import get_incident


class CVEInfo(BaseModel):
    """
    A Pydantic model for CVE information.
    This model defines the structure of the output from the CVE analysis.
    It includes fields for the CVE ID, summary, relevance, and risk level.
    """

    cve_id: str = Field(description="The CVE ID that is related to the incident")
    cve_summary: str = Field(
        description="A brief summary of the CVE and its relation to the incident"
    )
    cve_relevance: float = Field(
        description="The estimated relevance level of the CVE match (0.0-1.0)"
    )
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
    incident_risk_level_explanation: str = Field(
        description="An explanation of the rationale for the risk level assessment"
    )


class IncidentAnalysisList(BaseModel):
    incidents: list[IncidentAnalysis] = Field(description="List of incident analyses")


class AnalysisRequest(BaseModel):
    """
    A Pydantic model for the analysis request - this is the payload to the FastAPI server wrapping the core agent logic.
    It includes fields for the start index, batch size, request ID, OpenAI API key, and model name.
    """

    start_index: int = Field(default=0, description="Starting index for batch processing")
    batch_size: int = Field(default=5, description="Number of incidents to process")
    request_id: str = Field(description="Unique identifier for idempotency")
    openai_api_key: str = Field(description="OpenAI API key for this request")
    model_name: str = Field(
        description="Model name for this request", default=os.getenv("MODEL_NAME", "gpt-4o-mini")
    )


# Initialize the parser
parser = PydanticOutputParser(pydantic_object=IncidentAnalysisList)

# We want our templates to save the LLM time and tokens by pre-processing and providing data we assume will always be relevant including:
# 1) Incident Details: The raw JSON of the incidents it's being asked to analyze
#
# 2) Batch FAISS matches (KEV/NVD): The results of semantic searching the KEV/NVD indexes for the incidents
#       Note: The agent still has access to query the indexes by incident or by custom strings if it needs more information or to check for more matches.
#
# 3) Historical FAISS‐anchoring context: The top results of searching for similar incidents in the past and the LLM's decision/ranking on those incidents.
#       Note: This will help it normalize the severity rankings and provide a more accurate assessment of the incidents.
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

default_query = """
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
"""

# For debugging, we can use the following query:
debug_query = """
I need you to help me analyze some security incidents and identify potential CVE connections. Let's start with a small sample to test the system:
First, we need to do a meta test to debug.  Please try all of the tools you have.  List what you did and what specific inputs you gave to which functions and what the reutnred value(s) or errors were.
Focus mainly on just getting a single incident ID, then describe your process for trying to map it to a CVE ID given the tools you have.
Actively perform the steps, always specifying exactly which functions you executed, the exact inputs, and the exact returned output or error message, you describe and give a full report of the results of what you did and what happened along the way.
Note: If any tools return an error, please give the exact response, the exception details, and any additional specific details of the error and the tool in question. Format this as a JSON object with the following keys:
{
    "error": "The exact error message from the tool",
    "tool": "The name of the tool that returned the error",
    "input_variables": "The input variables that were used to call the tool",
    "error_details": "Any additional specific details of the error (included returned responses)"
}
"""


# Now we can use that (or optionally another) templaate to generate the prompt
def generate_prompt(
    query: str,
    batch_faiss_results: List[Dict[str, Any]],
    historical_faiss_results: List[Dict[str, Any]],
    template=SYSTEM_TMPL,
):
    """
    Generate a prompt using LangChain's classes: SystemMessagePromptTemplate, HumanMessagePromptTemplate, and ChatPromptTemplate.
    This ensures that the prompt is properly formatted and can be used by the agent.
    We additionally add a PydanticOutputParser to the prompt to ensure that the output is properly formatted.
    """
    # Extract incident IDs and get full details
    incident_ids = [
        result["incident_id"]
        for result in batch_faiss_results.get("results", [])
        if "incident_id" in result
    ]

    # Get full incident details
    incident_details = []
    for incident_id in incident_ids:
        incident_data = get_incident(incident_id)
        if incident_data.get("found"):
            incident_details.append(incident_data["incident_data"])

    system_prompt = SystemMessagePromptTemplate.from_template(template)
    human_prompt = HumanMessagePromptTemplate.from_template("{user_query}")
    chat_prompt = ChatPromptTemplate.from_messages([system_prompt, human_prompt])

    complete_prompt = chat_prompt.format_prompt(
        incident_details=json.dumps(incident_details, indent=2),
        batch_faiss_results=json.dumps(batch_faiss_results, indent=2),
        historical_faiss_results=json.dumps(historical_faiss_results, indent=2),
        format_instructions=parser.get_format_instructions(),
        user_query=query,
    ).to_messages()

    return complete_prompt
