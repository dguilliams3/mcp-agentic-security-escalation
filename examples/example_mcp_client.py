# Required imports for async operations, LangChain components, and MCP client functionality
import asyncio
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from langchain_core.messages import HumanMessage, AIMessage
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

# Get OpenAI API key from environment variables
openai_api_key = os.getenv("OPENAI_API_KEY")
if not openai_api_key:
    raise ValueError("OPENAI_API_KEY not found in environment variables. Please check your .env file.")

print("OpenAI API key loaded successfully")

# Initialize ChatGPT model with specific version
model = ChatOpenAI(openai_api_key=openai_api_key, model="gpt-4o-mini")

# Configure server parameters for the Python subprocess
server_parameters = StdioServerParameters(
    command="python",
    args=["example_mcp_server.py"],
)

async def main():
    print("Establishing connection to server...")
    # Create stdio client connection to server
    async with stdio_client(server_parameters) as (read, write):
        print("Server connection established")
        # Initialize client session for communication
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("Client session initialized")
            # Load MCP tools and create ReAct agent
            tools = await load_mcp_tools(session)
            print("MCP tools loaded")
            agent = create_react_agent(model, tools)
            print("Agent created and ready to process requests")
            
            # Execute agent query about Apple revenue trends
            print("Executing agent query...")
            # Use invoke with proper message format and await the response
            response = await agent.ainvoke({
                "messages": [
                    HumanMessage(content="Analyze how the revenue of Apple has changed over time compared to the revenue of Samsung and Microsoft.  Then, tell me about the revenue of Dan Guilliams")
                ]
            })
            
            # Get the final AI message (the actual analysis)
            final_message = next(msg for msg in reversed(response["messages"]) 
                               if isinstance(msg, AIMessage) and msg.content)
            
            print("\nAgent Analysis:")
            print(final_message.content)

if __name__ == "__main__":
    asyncio.run(main())
