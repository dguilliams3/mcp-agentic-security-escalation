import pytest
from pathlib import Path
import json
from mcp_cve_server import (
    list_incident_ids,
    get_incident,
    get_incident_schema,
    search_nvd,
    search_kevs,
    lookup_kev_by_cve_id,
    get_current_time,
    get_system_info,
)


# Fixture to load test data
@pytest.fixture
def sample_incidents():
    data_file = Path("data/incidents.json")
    with open(data_file, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def nvd_data():
    """Load NVD data for testing."""
    data_file = Path("data/nvd_subset.json")
    with open(data_file, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def kev_data():
    """Load KEV data for testing."""
    data_file = Path("data/kev.json")
    with open(data_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        return data.get("vulnerabilities", [])


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

    # Test get_incident with empty ID
    empty_id = get_incident("")
    assert empty_id["found"] is False


@pytest.mark.parametrize(
    "invalid_id",
    [
        None,
        123,  # non-string
        "INC-9999-99-999",  # non-existent format
        "' OR '1'='1",  # SQL injection attempt
    ],
)
def test_input_validation(invalid_id):
    result = get_incident(invalid_id)
    assert result["found"] is False
    assert "error" in result


def test_search_nvd(nvd_data):
    """Test NVD search functionality."""
    # Get a real CVE ID from the data
    sample_cve_id = next(iter(nvd_data))
    sample_desc = (
        nvd_data[sample_cve_id]
        .get("cve", {})
        .get("description", {})
        .get("description_data", [{}])[0]
        .get("value", "")
    )
    search_term = sample_desc.split()[0] if sample_desc else "vulnerability"

    # Test with actual term from the data
    result = search_nvd(search_term)
    assert isinstance(result, list)
    assert len(result) <= 10  # Default limit

    # Test with limit
    limited_result = search_nvd(search_term, limit=3)
    assert len(limited_result) <= 3

    # Test with CVE ID
    cve_result = search_nvd(sample_cve_id)
    assert isinstance(cve_result, list)
    assert len(cve_result) > 0

    # Test with empty query - should return up to limit results
    empty_result = search_nvd("")
    assert isinstance(empty_result, list)
    assert len(empty_result) <= 10  # Should return up to default limit


def test_search_kevs(kev_data):
    """Test KEV search functionality."""
    if not kev_data:
        pytest.skip("No KEV data available for testing")

    # Get a real vendor/product from the data
    sample_entry = kev_data[0]
    search_term = (
        sample_entry.get("vendorProject", "") or sample_entry.get("product", "") or "windows"
    )

    # Test with actual term from the data
    result = search_kevs(search_term)
    assert isinstance(result, list)
    assert len(result) > 0
    assert len(result) <= 10  # Default limit

    # Test with limit
    limited_result = search_kevs(search_term, limit=3)
    assert len(limited_result) <= 3

    # Test with CVE ID
    cve_result = search_kevs(sample_entry.get("cveID", ""))
    assert isinstance(cve_result, list)
    if sample_entry.get("cveID"):  # Only assert if we actually had a CVE ID
        assert len(cve_result) > 0

    # Test with empty query - should return up to limit results
    empty_result = search_kevs("")
    assert isinstance(empty_result, list)
    assert len(empty_result) <= 10  # Should return up to default limit


def test_lookup_kev_by_cve_id():
    """Test KEV lookup by CVE ID."""
    # First get a valid CVE ID from the KEV entries
    kev_file = Path("data/kev.json")
    with open(kev_file, "r") as f:
        kev_data = json.load(f)
        if kev_data.get("vulnerabilities"):
            sample_cve = kev_data["vulnerabilities"][0]["cveID"]

            # Test with valid CVE ID
            result = lookup_kev_by_cve_id(sample_cve)
            assert isinstance(result, dict)
            assert result.get("cveID") == sample_cve

    # Test with invalid CVE ID
    invalid_result = lookup_kev_by_cve_id("CVE-9999-9999")
    assert invalid_result is None

    # Test with malformed CVE ID
    malformed_result = lookup_kev_by_cve_id("not-a-cve")
    assert malformed_result is None


@pytest.mark.asyncio
async def test_get_current_time():
    """Test server time retrieval."""
    result = await get_current_time()
    assert isinstance(result, str)

    # Test ISO 8601 format
    from datetime import datetime

    try:
        # This will raise ValueError if format is invalid
        datetime.fromisoformat(result)
    except ValueError as e:
        pytest.fail(f"Time string {result} is not in ISO format: {e}")


@pytest.mark.asyncio
async def test_get_system_info():
    """Test system information retrieval."""
    result = await get_system_info()

    # Test structure
    assert isinstance(result, dict)
    required_keys = {"system", "version", "machine", "python_version"}
    assert all(key in result for key in required_keys)

    # Test content
    assert all(isinstance(v, str) for v in result.values()), "All values should be strings"
    assert all(bool(v.strip()) for v in result.values()), "No empty values allowed"

    # Test Python version format (should be like "3.12.0")
    import re

    assert re.match(r"^\d+\.\d+\.\d+", result["python_version"]), "Invalid Python version format"
