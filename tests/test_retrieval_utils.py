import pytest
from unittest.mock import Mock, patch, MagicMock
from utils.retrieval_utils import (
    batch_get_historical_context,
    get_similar_incidents_with_analyses,
    get_incident_analyses_from_database,
)


@pytest.fixture
def mock_incident_data():
    return {
        "found": True,
        "incident_data": {
            "incident_id": "INC-2023-08-01-001",
            "title": "Test Incident",
            "description": "Test incident for unit testing",
        },
    }


@pytest.fixture
def mock_similar_incidents():
    return [
        {"incident_id": "INC-2024-07-14-020", "variance": 0.85},
        {"incident_id": "INC-2024-07-21-027", "variance": 0.75},
    ]


@pytest.fixture
def mock_analyses():
    return [
        {
            "incident_id": "INC-2024-07-14-020",
            "analysis": {
                "incident_risk_level": 0.8,
                "incident_summary": "Test summary 1",
                "cve_ids": ["CVE-2023-001"],
                "incident_risk_level_explanation": "Test explanation 1",
            },
        },
        {
            "incident_id": "INC-2024-07-21-027",
            "analysis": {
                "incident_risk_level": 0.7,
                "incident_summary": "Test summary 2",
                "cve_ids": ["CVE-2023-002"],
                "incident_risk_level_explanation": "Test explanation 2",
            },
        },
    ]


@pytest.mark.asyncio
async def test_batch_get_historical_context(
    mock_incident_data, mock_similar_incidents, mock_analyses
):
    with (
        patch("utils.retrieval_utils.get_incident") as mock_get_incident,
        patch("utils.retrieval_utils.get_similar_incidents_with_analyses") as mock_get_similar,
        patch("utils.retrieval_utils.get_incident_analyses_from_database") as mock_get_analyses,
    ):

        # Setup mocks
        mock_get_incident.return_value = mock_incident_data
        mock_get_similar.return_value = {
            "similar_incidents": mock_similar_incidents,
            "analyses": {},
            "metadata": {"num_incidents_found": 2, "num_analyses_retrieved": 0},
        }
        mock_get_analyses.return_value = mock_analyses

        # Test the function
        result = batch_get_historical_context(["INC-2023-08-01-001"])

        # Verify the result structure
        assert result["success"] is True
        assert len(result["results"]) == 1

        # Check the historical context
        historical_context = result["results"][0]["historical_context"]
        assert len(historical_context["analyses"]) == 2

        # Verify the analysis data is properly formatted
        analysis = historical_context["analyses"]["INC-2024-07-14-020"]
        assert "incident_risk_level" in analysis
        assert "incident_summary" in analysis
        assert "cve_ids" in analysis
        assert "incident_risk_level_explanation" in analysis

        # Verify the values
        assert analysis["incident_risk_level"] == 0.8
        assert analysis["incident_summary"] == "Test summary 1"


def test_get_similar_incidents_with_analyses(mock_similar_incidents, mock_analyses):
    with (
        patch("utils.retrieval_utils.search_similar_incidents") as mock_search,
        patch("utils.retrieval_utils.get_incident_analyses_from_database") as mock_get_analyses,
    ):

        # Setup mocks
        mock_search.return_value = mock_similar_incidents
        mock_get_analyses.return_value = mock_analyses

        # Test with default fields
        result = get_similar_incidents_with_analyses(
            incident={"incident_id": "test"},
            incident_fields=["incident_id", "variance"],
            analysis_fields=["incident_risk_level", "incident_summary", "cve_ids"],
        )

        # Verify structure
        assert "similar_incidents" in result
        assert "analyses" in result
        assert "metadata" in result

        # Check filtered incident fields
        assert len(result["similar_incidents"]) == 2
        assert all("incident_id" in inc for inc in result["similar_incidents"])
        assert all("variance" in inc for inc in result["similar_incidents"])

        # Check filtered analysis fields
        analyses = result["analyses"]
        assert len(analyses) == 2
        first_analysis = analyses["INC-2024-07-14-020"]
        assert "incident_risk_level" in first_analysis
        assert "incident_summary" in first_analysis
        assert "cve_ids" in first_analysis
        assert "incident_risk_level_explanation" not in first_analysis  # Not in requested fields

        # Test with custom fields
        result = get_similar_incidents_with_analyses(
            incident={"incident_id": "test"},
            incident_fields=["incident_id"],
            analysis_fields=["incident_risk_level", "incident_risk_level_explanation"],
        )

        # Verify custom field filtering
        first_analysis = result["analyses"]["INC-2024-07-14-020"]
        assert "incident_risk_level" in first_analysis
        assert "incident_risk_level_explanation" in first_analysis
        assert "incident_summary" not in first_analysis
        assert "cve_ids" not in first_analysis


def test_get_similar_incidents_with_analyses_empty_analysis():
    with (
        patch("utils.retrieval_utils.search_similar_incidents") as mock_search,
        patch("utils.retrieval_utils.get_incident_analyses_from_database") as mock_get_analyses,
    ):

        # Setup mocks with empty/invalid analysis data
        mock_search.return_value = [{"incident_id": "test-1", "variance": 0.8}]
        mock_get_analyses.return_value = [
            {"incident_id": "test-1"},  # No analysis field
            {"incident_id": "test-2", "analysis": None},  # Null analysis
        ]

        result = get_similar_incidents_with_analyses(
            incident={"incident_id": "test"},
            incident_fields=["incident_id", "variance"],
            analysis_fields=["incident_risk_level"],
        )

        # Verify empty analyses are handled gracefully
        assert len(result["analyses"]) == 0
        assert result["metadata"]["num_analyses_retrieved"] == 0
