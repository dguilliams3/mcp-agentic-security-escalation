# MCP Agents RAD Security

A Python-based project utilizing the Mission Control Protocol (MCP) framework along with LangChain for AI agent implementation, focused on security analysis.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/mcp-agents-radsecurity.git
cd mcp-agents-radsecurity

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Unix/MacOS:
source .venv/bin/activate

# Install the package with development dependencies
pip install -e ".[dev]"

# Set up environment variables
cp .env.example .env
# Edit .env and add your OpenAI API key
```

## Requirements

- Python 3.12 or higher
- OpenAI API key (required for LangChain integration)

## Project Structure

```
mcp-agents-radsecurity/
├── mcp_cve_server.py     # Contains MCP Tools for agent(s)
├── mcp_cve_client.py     # Client to use tools and perform main LLM call
├── utils/                # Utility functions
├── tests/               # Test files
├── data/                # Data resources (imported .json files, etc.)
└── examples/            # Example usage
```

## Usage

### Basic Usage

```python
from mcp_cve_server import test_server, search_incidents
from mcp_cve_client import CVEClient

# Test server connection
test_server()

# Search for incidents
results = search_incidents("your_query")
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_specific.py

# Run with coverage report
pytest --cov=.
```

## Development

### Setup Development Environment

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (optional)
pre-commit install
```

### Code Style

This project uses:
- Black for code formatting
- isort for import sorting
- Ruff for linting

Format your code:
```bash
black .
isort .
ruff check .
```

### Making Changes

1. Create a new branch for your feature
2. Make your changes
3. Run the test suite
4. Submit a pull request

## Troubleshooting

### Common Issues

1. **Import Errors**: Make sure you've installed the package in editable mode with `pip install -e ".[dev]"`
2. **API Key Issues**: Verify your OpenAI API key is correctly set in `.env`
3. **Python Version**: Ensure you're using Python 3.12 or higher

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
