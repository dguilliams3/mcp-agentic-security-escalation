# Datastore Management
# datastore_utils.py
from sqlalchemy import create_engine, Column, String, Float, Text, DateTime, Index
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

    request_id = Column(String, primary_key=True)  # Uniquely identifies this *analysis*, not just incident
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
