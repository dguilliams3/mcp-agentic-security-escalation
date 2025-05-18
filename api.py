from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import asyncio
from mcp_cve_client import ask_mcp_agent, StdioServerParameters, MCP_SERVER_NAME

app = FastAPI(title="CVE Analysis API")

class AnalysisRequest(BaseModel):
    start_index: int = 0
    batch_size: int = 5
    query: Optional[str] = None

@app.post("/analyze")
async def analyze_incidents(request: AnalysisRequest):
    try:
        server_parameters = StdioServerParameters(
            command="python",
            args=[MCP_SERVER_NAME],
        )
        
        # Use default query if none provided
        query = request.query or """
        I need you to help me analyze some security incidents and rank their actual severity, 
        using identify potential CVE connections and details.
        """
        
        await ask_mcp_agent(
            server_parameters=server_parameters,
            query=query,
            start_index=request.start_index,
            batch_size=request.batch_size
        )
        
        return {"status": "success", "message": "Analysis completed successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 