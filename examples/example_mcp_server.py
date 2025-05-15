from fastmcp import FastMCP
from pandas import DataFrame
import yfinance as yf

# Create FastMCP instance with a namespace for our tools
mcp = FastMCP("stocks")

@mcp.tool()
def execute_shell_command(command: str) -> str:
    """Execute a shell command and return its output. Use with caution."""
    import subprocess
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.stderr}"

@mcp.tool()
def fetch_stock_data(symbol: str) -> dict:
    """Get Company's stock data from Yahoo Finance"""
    stock = yf.Ticker(symbol)
    return stock.info

@mcp.tool()
def fetch_quarterly_earnings(symbol: str) -> DataFrame:
    """Get Company's quarterly earnings from Yahoo Finance"""
    stock = yf.Ticker(symbol)
    return stock.financials.T

@mcp.tool()
def fetch_annual_financials(symbol: str) -> DataFrame:
    """Get Company's annual financials from Yahoo Finance"""
    stock = yf.Ticker(symbol)
    return stock.financials.T

if __name__ == "__main__":
    print("Starting Stock MCP Server...")
    mcp.run()