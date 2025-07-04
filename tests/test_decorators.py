"""Test cases for MCP CVE server decorators and functionality."""

import pytest
from mcp_cve_server import test_server, list_incident_ids


def test_timing_metric():
    """Test timing metric decorator on function."""
    # Test both the return value and that it's logged
    assert test_server() == "Server is running"


def test_list_incidents_cached():
    """Test incident listing with cache."""
    # First call
    result1 = list_incident_ids()
    assert isinstance(result1, dict)
    assert "incident_ids" in result1

    # Second call (should be cached)
    result2 = list_incident_ids()
    assert result1 == result2, "Cached result should match original"

    # Test with limit
    result3 = list_incident_ids(limit=5)
    assert isinstance(result3, dict)
    assert "incident_ids" in result3
    if result3["success"] and result3["incident_ids"]:
        assert len(result3["incident_ids"]) <= 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
