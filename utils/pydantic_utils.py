import os
from typing import List
from pydantic import BaseModel, Field

# Pydantic models for structured output
class CVEInfo(BaseModel):
    cve_id: str = Field(description="The CVE ID that is related to the incident")
    cve_summary: str = Field(description="A brief summary of the CVE and its relation to the incident")
    cve_relevance: float = Field(description="The estimated relevance level of the CVE match (0.0-1.0)")
    cve_risk_level: float = Field(description="The risk level of the CVE on a scale of (0.0-1.0)")

class IncidentAnalysis(BaseModel):
    incident_id: str = Field(description="The ID of the incident that caused the error")
    incident_summary: str = Field(description="A brief summary of the incident")
    cve_ids: List[CVEInfo] = Field(description="List of related CVEs and their details")
    incident_risk_level: float = Field(description="The risk level of the incident (0.0-1.0)")
    incident_risk_level_explanation: str = Field(description="An explanation of the rationale for the risk level assessment")

class IncidentAnalysisList(BaseModel):
    incidents: List[IncidentAnalysis] = Field(description="List of incident analyses")

class AnalysisRequest(BaseModel):
    start_index: int = Field(default=0, description="Starting index for batch processing")
    batch_size: int = Field(default=5, description="Number of incidents to process")
    request_id: str = Field(description="Unique identifier for idempotency")
    openai_api_key: str = Field(description="OpenAI API key for this request")
    model_name: str = Field(description="Model name for this request", default=os.getenv("MODEL_NAME", "gpt-4o-mini"))