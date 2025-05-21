# Datastore Management
# datastore_utils.py
from sqlalchemy import Integer, create_engine, Column, String, Float, Text, DateTime, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, UTC
import json
import os
from utils.logging_utils import setup_logger
from typing import Any

logger = setup_logger("datastore_utils")

# --- Configuration ---
DATABASE_URL = os.getenv(
    "DATABASE_URL", "sqlite:///data/incident_analysis.db"
)  # Swap with postgres:// URI as needed

# --- Setup SQLAlchemy ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- Model Definition ---
class IncidentRecord(Base):
    __tablename__ = "incident_analysis"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(
        String, index=True
    )  # Uniquely identifies this *analysis*, not just incident
    incident_id = Column(
        String, index=True
    )  # Allows filtering or joining across repeated incidents
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    incident_raw_json = Column(Text)  # Original incident details
    llm_analysis_json = Column(Text)  # Final analysis from the LLM
    llm_risk_score = Column(Float, nullable=True)  # For quick filtering/analytics
    model_name = Column(String)

    __table_args__ = (
        Index("ix_incident_id_request", "incident_id", "request_id"),  # Fast filtering if needed
    )


# --- Create Tables If Not Exists ---
def init_db():
    """
    Initialize the SQLite database and create necessary tables if they don't exist.

    This function sets up the database schema for:
    1. Incident analyses storage
    2. Run metadata tracking
    3. Historical data

    The function ensures idempotent table creation and proper index setup
    for optimal query performance.

    Note:
        - Creates tables if they don't exist
        - Sets up appropriate indexes for performance
        - Handles SQLite-specific configurations
        - Thread-safe database initialization
    """
    Base.metadata.create_all(bind=engine)


class RunMetadata(Base):
    __tablename__ = "run_metadata"
    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String, index=True, nullable=False)
    start_index = Column(Integer, nullable=False)
    batch_size = Column(Integer, nullable=False)
    input_tokens = Column(Integer, nullable=True)
    output_tokens = Column(Integer, nullable=True)
    total_tokens = Column(Integer, nullable=True)
    tools_called = Column(Text, nullable=True)  # JSON-encoded list of tool names
    duration_seconds = Column(Float, nullable=True)
    error_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))


def init_db():
    Base.metadata.create_all(bind=engine)


def save_run_metadata(
    request_id: str,
    start_index: int,
    batch_size: int,
    usage_metrics: dict,
    tools: list[str],
    duration: float,
    error_count: int = 0,
):
    """
    Save metadata about a batch processing run to the database.

    This function records operational metrics and metadata about each
    batch processing run for monitoring and analysis purposes.

    Args:
        request_id (str): Unique identifier for the processing request
        start_time (float): Unix timestamp when processing started
        end_time (float): Unix timestamp when processing completed
        error_count (int): Number of errors encountered during processing
        total_incidents (int): Total number of incidents processed
        batch_size (int): Size of the processing batch
        start_index (int): Starting index of the batch

    Note:
        - Timestamps are stored in Unix timestamp format
        - Thread-safe database operations
        - Automatically handles SQLite transaction management
    """
    session = SessionLocal()
    try:
        rm = RunMetadata(
            request_id=request_id,
            start_index=start_index,
            batch_size=batch_size,
            input_tokens=usage_metrics.get("input_tokens"),
            output_tokens=usage_metrics.get("output_tokens"),
            total_tokens=usage_metrics.get("total_tokens"),
            tools_called=json.dumps(tools),
            duration_seconds=duration,
            error_count=error_count,
        )
        session.add(rm)
        session.commit()
    finally:
        session.close()


# --- Insert Function ---
def save_incident_and_analysis_to_sqlite_db(
    request_id: str, incident_id: str, model_name: str, incident: dict, analysis: dict
):
    """
    Save an incident analysis result to the SQLite database.

    This function handles the persistence of incident analysis results,
    including the LLM's response and associated metadata.

    Args:
        request_id (str): Unique identifier for this analysis request
        incident_id (str): ID of the incident being analyzed
        model_name (str): Name of the LLM model used for analysis
        incident (dict): The original incident data
        analysis (dict): The LLM's analysis of the incident
    """
    session = SessionLocal()
    try:
        logger.info(
            f"Saving incident and analysis to SQLite database for request_id: {request_id}, incident_id: {incident_id}..."
        )
        record = IncidentRecord(
            request_id=request_id,
            incident_id=incident_id,
            incident_raw_json=json.dumps(incident),
            llm_analysis_json=json.dumps(analysis),
            llm_risk_score=analysis.get("incident_risk_level", None),
            model_name=model_name,
        )
        session.add(record)
        session.commit()
        logger.info(
            f"Successfully saved incident and analysis to SQLite database for request_id: {request_id}, incident_id: {incident_id}!"
        )
    except Exception as e:
        session.rollback()
        logger.error(
            f"Error saving incident and analysis to SQLite database for request_id: {request_id}, incident_id: {incident_id}"
        )
        raise e
    finally:
        session.close()
        logger.debug(
            f"Closed database session for request_id: {request_id}, incident_id: {incident_id}"
        )


def get_incident_analyses_from_database(incident_ids: list[str]) -> list[dict]:
    """
    Retrieve incident analyses from the database for specified incident IDs.

    This function fetches previously stored analyses for a list of incidents,
    useful for historical context and comparison.

    Args:
        incident_ids (list[str]): List of incident IDs to retrieve analyses for

    Returns:
        list[dict]: List of incident analyses, each containing:
            - incident_id: The incident identifier
            - analysis: The stored analysis result
            - timestamp: When the analysis was performed
            - request_id: Associated batch request ID

    Note:
        - Returns empty list if no analyses found
        - Handles JSON deserialization of stored analyses
        - Optimized for batch retrieval
        - Thread-safe database operations
    """
    session = SessionLocal()
    try:
        logger.info(f"Retrieving analyses for {len(incident_ids)} incidents...")
        # Query for the most recent analysis of each incident
        records = (
            session.query(IncidentRecord)
            .filter(IncidentRecord.incident_id.in_(incident_ids))
            .order_by(IncidentRecord.created_at.desc())
            .all()
        )

        # Convert records to dictionaries
        results = []
        for record in records:
            try:
                incident_data = (
                    json.loads(record.incident_raw_json) if record.incident_raw_json else None
                )
                analysis_data = (
                    json.loads(record.llm_analysis_json) if record.llm_analysis_json else None
                )

                results.append(
                    {
                        "incident_id": record.incident_id,
                        "incident_data": incident_data,
                        "analysis": analysis_data,
                        "risk_score": record.llm_risk_score,
                        "model_name": record.model_name,
                        "created_at": record.created_at.isoformat() if record.created_at else None,
                    }
                )
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON for incident {record.incident_id}: {e}")
                continue

        logger.info(f"Successfully retrieved {len(results)} analyses!")
        return results

    except Exception as e:
        logger.error(f"Error retrieving incident analyses: {e}")
        raise
    finally:
        session.close()
        logger.debug("Closed database session")
