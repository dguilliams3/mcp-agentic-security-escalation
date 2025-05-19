# Datastore Management
# datastore_utils.py
from sqlalchemy import Integer, create_engine, Column, String, Float, Text, DateTime, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, UTC
import json
import os
from utils.logging_utils import setup_logger

logger = setup_logger()

# --- Configuration ---
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///data/incident_analysis.db")  # Swap with postgres:// URI as needed

# --- Setup SQLAlchemy ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Model Definition ---
class IncidentRecord(Base):
    __tablename__ = "incident_analysis"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String, index=True)  # Uniquely identifies this *analysis*, not just incident
    incident_id = Column(String, index=True)       # Allows filtering or joining across repeated incidents
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    incident_raw_json = Column(Text)               # Original incident details
    llm_analysis_json = Column(Text)               # Final analysis from the LLM
    llm_risk_score = Column(Float, nullable=True)  # For quick filtering/analytics
    model_name = Column(String)

    __table_args__ = (
        Index("ix_incident_id_request", "incident_id", "request_id"),  # Fast filtering if needed
    )

# --- Create Tables If Not Exists ---
def init_db():
    Base.metadata.create_all(bind=engine)

# --- Insert Function ---
def save_incident_and_analysis_to_db(
    request_id: str,
    incident_id: str,
    model_name: str,
    incident: dict,
    analysis: dict
):
    session = SessionLocal()
    try:
        logger.info(f"Saving incident and analysis to database for request_id: {request_id}, incident_id: {incident_id}...")
        record = IncidentRecord(
            request_id=request_id,
            incident_id=incident_id,
            incident_raw_json=json.dumps(incident),
            llm_analysis_json=json.dumps(analysis),
            llm_risk_score=analysis.get("incident_risk_level", None),
            model_name=model_name
        )
        session.add(record)
        session.commit()
        logger.info(f"Successfully saved incident and analysis to database for request_id: {request_id}, incident_id: {incident_id}!")
    except Exception as e:
        session.rollback()
        logger.error(f"Error saving incident and analysis to database for request_id: {request_id}, incident_id: {incident_id}")
        raise e
    finally:
        session.close()
        logger.debug(f"Closed database session for request_id: {request_id}, incident_id: {incident_id}")

class RunMetadata(Base):
    __tablename__ = "run_metadata"
    id               = Column(Integer, primary_key=True, autoincrement=True)
    request_id       = Column(String, index=True, nullable=False)
    start_index      = Column(Integer, nullable=False)
    batch_size       = Column(Integer, nullable=False)
    input_tokens     = Column(Integer, nullable=True)
    output_tokens    = Column(Integer, nullable=True)
    total_tokens     = Column(Integer, nullable=True)
    tools_called     = Column(Text, nullable=True)    # JSON-encoded list of tool names
    duration_seconds = Column(Float, nullable=True)
    error_count      = Column(Integer, default=0)
    created_at       = Column(DateTime, default=lambda: datetime.now(UTC))

def init_db():
    Base.metadata.create_all(bind=engine)

def save_run_metadata(
    request_id: str,
    start_index: int,
    batch_size: int,
    usage_metrics: dict,
    tools: list[str],
    duration: float,
    error_count: int = 0
):
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
            error_count=error_count
        )
        session.add(rm)
        session.commit()
    finally:
        session.close()

def get_incident_analyses(incident_ids: list[str]) -> list[dict]:
    """
    Retrieve incident analyses from the database for a list of incident IDs.
    Returns a list of dictionaries containing both incident and analysis data.

    Args:
        incident_ids (list[str]): List of incident IDs to retrieve analyses for

    Returns:
        list[dict]: List of dictionaries containing incident data and analysis
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
                incident_data = json.loads(record.incident_raw_json) if record.incident_raw_json else None
                analysis_data = json.loads(record.llm_analysis_json) if record.llm_analysis_json else None

                results.append({
                    "incident_id": record.incident_id,
                    "incident_data": incident_data,
                    "analysis": analysis_data,
                    "risk_score": record.llm_risk_score,
                    "model_name": record.model_name,
                    "created_at": record.created_at.isoformat() if record.created_at else None
                })
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