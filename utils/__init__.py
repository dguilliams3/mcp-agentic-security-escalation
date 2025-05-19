"""Utility functions and decorators for the MCP CVE Analysis system.

This package provides a comprehensive set of utilities for the MCP CVE Analysis system,
including data processing, logging, database operations, and AI model interactions.

The package is organized into several modules:
- decorators: Performance monitoring and caching utilities
- flatteners: Data structure normalization utilities
- retrieval_utils: Vector search and embedding utilities
- logging_utils: Logging configuration and management
- prompt_utils: AI prompt generation and management
- clean_json: JSON data cleaning and validation
- datastore_utils: Database operations and models

Example:
    Basic usage of the package::

        from utils import setup_logger, save_incident_and_analysis_to_db
        
        # Initialize logging
        logger = setup_logger()
        
        # Save analysis to database
        save_incident_and_analysis_to_db(
            request_id="req_123",
            incident_id="inc_456",
            model_name="gpt-4",
            incident={"data": "..."},
            analysis={"result": "..."}
        )
"""

from .decorators import timing_metric, cache_result
from .flatteners import flatten_kev, flatten_nvd, flatten_incident
from .retrieval_utils import (
    initialize_embeddings,
    initialize_indexes,
    _search,
    KEV_FAISS,
    NVD_FAISS,
    INCIDENT_HISTORY_FAISS
)
from .logging_utils import setup_logger
from .prompt_utils import (
    generate_prompt,
    IncidentAnalysis,
    IncidentAnalysisList,
    AnalysisRequest,
    SYSTEM_TMPL
)
from .clean_json import clean_json_file
from .datastore_utils import (
    init_db,
    save_incident_and_analysis_to_db,
    save_run_metadata,
    get_incident_analyses,
    IncidentRecord,
    RunMetadata,
    SessionLocal,
    Base,
    engine
)

# Public API documentation
__all__ = [
    # Decorators
    'timing_metric',  # Decorator for measuring function execution time
    'cache_result',   # Decorator for caching function results
    
    # Flatteners
    'flatten_kev',      # Flattens KEV (Known Exploited Vulnerabilities) data structure
    'flatten_nvd',      # Flattens NVD (National Vulnerability Database) data structure
    'flatten_incident', # Flattens incident data structure
    
    # Retrieval Utils
    'initialize_embeddings',  # Initialize embedding models for vector search
    'initialize_indexes',     # Initialize FAISS indexes for vector search
    '_search',               # Internal search function for vector similarity
    'KEV_FAISS',            # FAISS index for KEV data
    'NVD_FAISS',            # FAISS index for NVD data
    'INCIDENT_HISTORY_FAISS',     # FAISS index for historical incident data
    
    # Logging Utils
    'setup_logger',         # Configure and initialize logging system
    
    # Prompt Utils
    'generate_prompt',      # Generate AI model prompts
    'IncidentAnalysis',     # Class for incident analysis results
    'IncidentAnalysisList', # Class for managing multiple incident analyses
    'AnalysisRequest',      # Class for analysis request parameters
    'SYSTEM_TMPL',          # System template for prompt generation
    # Clean JSON Utils
    'clean_json_file',      # Clean and validate JSON files
    
    # Datastore Utils
    'init_db',                     # Initialize database tables
    'save_incident_and_analysis_to_db',  # Save incident and analysis to database
    'save_run_metadata',           # Save run metadata to database
    'get_incident_analyses',       # Retrieve incident analyses from database
    'IncidentRecord',             # SQLAlchemy model for incident records
    'RunMetadata',                # SQLAlchemy model for run metadata
    'SessionLocal',               # SQLAlchemy session factory
    'Base',                       # SQLAlchemy declarative base
    'engine'                      # SQLAlchemy database engine
]

# Type hints for better IDE support
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .prompt_utils import IncidentAnalysis, IncidentAnalysisList, AnalysisRequest
    from .datastore_utils import IncidentRecord, RunMetadata
    from sqlalchemy.orm import Session
    from sqlalchemy.engine import Engine
    from sqlalchemy.ext.declarative import DeclarativeMeta