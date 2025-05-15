import pytest
from pathlib import Path
import json
from mcp_cve_server import (
    list_incident_ids,
    get_incident,
    search_incidents,
    get_incident_schema,
    fetch_cve_data
)

# Fixture to load test data
@pytest.fixture
def sample_incidents():
    data_file = Path("data/incidents.json")
    with open(data_file, 'r', encoding='utf-8') as f:
        return json.load(f)

def test_list_incident_ids():
    # Test without limit
    result = list_incident_ids()
    assert isinstance(result, dict)
    assert "success" in result
    assert "incident_ids" in result
    assert "debug_info" in result
    
    # Test with limit
    limited_result = list_incident_ids(limit=5)
    assert len(limited_result["incident_ids"]) <= 5

def test_get_incident(sample_incidents):
    # Test with valid incident ID
    first_incident_id = "INC-2023-08-01-001"  # We know this ID exists in our test data
    result = get_incident(first_incident_id)
    assert result["found"] is True
    assert "incident_data" in result
    assert "metadata" in result
    
    # Test with invalid incident ID
    invalid_result = get_incident("non-existent-id")
    assert invalid_result["found"] is False
    assert "error" in invalid_result

def test_search_incidents():
    # Test search with common term
    result = search_incidents("VPN")
    assert isinstance(result, dict)
    assert "metadata" in result
    assert "results" in result
    
    # Test search with limit
    limited_result = search_incidents("VPN", limit=2)
    assert len(limited_result["results"]) <= 2

def test_get_incident_schema():
    schema = get_incident_schema()
    assert isinstance(schema, dict)
    assert "type" in schema
    assert "properties" in schema
    assert "incident_id" in schema["properties"]
    assert "timestamp" in schema["properties"]

def test_edge_cases():
    # Test list_incident_ids with zero limit
    zero_limit = list_incident_ids(limit=0)
    assert isinstance(zero_limit["incident_ids"], list)
    
    # Test search with empty query
    empty_search = search_incidents("")
    assert isinstance(empty_search["results"], list)
    
    # Test get_incident with empty ID
    empty_id = get_incident("")
    assert empty_id["found"] is False

def test_fetch_cve_data():
    # Test with a CVE that should be in our local database
    result = fetch_cve_data("CVE-2023-1234")  # Using a sample CVE ID
    assert isinstance(result, dict)
    assert "success" in result
    
    # Test with non-existent CVE
    invalid_result = fetch_cve_data("CVE-9999-9999")
    assert isinstance(invalid_result, dict)
    assert "success" in invalid_result
    assert not invalid_result["success"]
    assert "error" in invalid_result

@pytest.mark.parametrize("invalid_id", [
    None,
    123,  # non-string
    "INC-9999-99-999",  # non-existent format
    "' OR '1'='1",  # SQL injection attempt
])
def test_input_validation(invalid_id):
    result = get_incident(invalid_id)
    assert result["found"] is False
    assert "error" in result 