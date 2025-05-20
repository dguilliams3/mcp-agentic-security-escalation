# 9. Persistence and Data Management

This section covers how the system persists analysis results and manages data for continuous learning and reference.

## 9.1 SQLite Database

Our system uses SQLite for structured persistence of incident analyses. This provides a lightweight, file-based database that requires no external server.

**Why we do this:** Persistent storage enables:
- Historical reference of past analyses
- Audit trails for security review
- Query capabilities for reporting and dashboards
- Cross-referencing between incidents
- Continuous learning for the system

```python
# Database initialization from utils/datastore_utils.py
import sqlite3
from sqlite3 import Error
import os
import json
from pathlib import Path
from datetime import datetime

DATA_DIR = Path("data")
DB_PATH = DATA_DIR / "incident_analysis.db"

def init_db():
    """Initialize the SQLite database with necessary tables."""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create incidents table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            initial_findings TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        ''')
        
        # Create analyses table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id TEXT PRIMARY KEY,
            incident_id TEXT,
            analysis_json TEXT,
            model_name TEXT,
            created_at TEXT,
            FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
        )
        ''')
        
        # Create run_metadata table for tracking API usage
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS run_metadata (
            run_id TEXT PRIMARY KEY,
            request_id TEXT,
            model_name TEXT,
            input_tokens INTEGER,
            output_tokens INTEGER,
            total_tokens INTEGER,
            start_time TEXT,
            end_time TEXT,
            duration_seconds REAL
        )
        ''')
        
        conn.commit()
        print("Database initialized successfully")
    except Error as e:
        print(f"Error initializing database: {e}")
    finally:
        if conn:
            conn.close()
```

## 9.2 Saving Analysis Results

When the agent completes an analysis, we save the results in both SQLite and as JSON backups:

```python
def save_incident_and_analysis_to_sqlite_db(incident, analysis, model_name):
    """
    Save an incident and its analysis to the SQLite database.
    
    Args:
        incident: The incident dictionary
        analysis: The analysis dictionary (from Pydantic model)
        model_name: The name of the LLM used for analysis
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Save incident info
        now = datetime.now().isoformat()
        cursor.execute('''
        INSERT OR REPLACE INTO incidents 
        (incident_id, title, description, initial_findings, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            incident.get('incident_id'),
            incident.get('title', ''),
            incident.get('description', ''),
            incident.get('initial_findings', ''),
            now,
            now
        ))
        
        # Save analysis
        analysis_id = f"{incident.get('incident_id')}_{now.replace(':', '-')}"
        cursor.execute('''
        INSERT INTO analyses
        (analysis_id, incident_id, analysis_json, model_name, created_at)
        VALUES (?, ?, ?, ?, ?)
        ''', (
            analysis_id,
            incident.get('incident_id'),
            json.dumps(analysis),
            model_name,
            now
        ))
        
        conn.commit()
        return True
    except Error as e:
        print(f"Error saving to database: {e}")
        return False
    finally:
        if conn:
            conn.close()
```

In addition to SQLite, we also save JSON backups:

```python
def save_incident_analysis_backup_json(incident_id, analysis_data):
    """Save a backup of analysis data as JSON."""
    backup_dir = DATA_DIR / "backups"
    backup_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"analysis_{incident_id}_{timestamp}.json"
    
    with open(backup_path, 'w') as f:
        json.dump(analysis_data, f, indent=2)
    
    return backup_path
```

## 9.3 FAISS Vector Index Updates

To support continuous learning, we update the FAISS vector index with new analyses:

**Why we do this:** Updating vector indexes enables:
- The system to learn from new analyses
- Improved results over time as more examples are added
- Reference to previous analyses when encountering similar incidents
- Consistency in risk evaluation by referring to precedents

```python
from langchain.docstore.document import Document
from langchain_community.vectorstores import FAISS
from utils.flatteners import flatten_incident_analysis

def add_incident_to_faiss_history_index(incident_id, analysis):
    """
    Add a completed incident analysis to the historical FAISS index.
    
    Args:
        incident_id: The ID of the analyzed incident
        analysis: The analysis object from the agent
    """
    global INCIDENT_HISTORY_FAISS, embeddings
    
    if INCIDENT_HISTORY_FAISS is None or embeddings is None:
        initialize_openai_embeddings()
        initialize_faiss_indexes()
    
    # Create a document from the analysis
    flattened_text = flatten_incident_analysis(analysis)
    doc = Document(
        page_content=flattened_text,
        metadata={
            "incident_id": incident_id,
            "analysis_id": analysis.get("analysis_id", "unknown"),
            "created_at": datetime.now().isoformat()
        }
    )
    
    # Add to FAISS index
    INCIDENT_HISTORY_FAISS.add_documents([doc])
    
    # Save updated index
    index_path = DATA_DIR / "vectorstore" / "incident_analysis_history"
    INCIDENT_HISTORY_FAISS.save_local(index_path)
    
    return True
```

## 9.4 Usage Metadata Tracking

We track usage metadata to monitor performance and costs:

```python
def save_run_metadata(
    request_id, 
    model_name, 
    input_tokens, 
    output_tokens, 
    start_time,
    end_time
):
    """Save metadata about an API run to track usage."""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        run_id = f"{request_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        duration = (end_time - start_time).total_seconds()
        
        cursor.execute('''
        INSERT INTO run_metadata
        (run_id, request_id, model_name, input_tokens, output_tokens, 
         total_tokens, start_time, end_time, duration_seconds)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            run_id,
            request_id,
            model_name,
            input_tokens,
            output_tokens,
            input_tokens + output_tokens,
            start_time.isoformat(),
            end_time.isoformat(),
            duration
        ))
        
        conn.commit()
        return True
    except Error as e:
        print(f"Error saving run metadata: {e}")
        return False
    finally:
        if conn:
            conn.close()
```

## 9.5 Caching Strategy

To optimize performance and reduce API costs, we implement a multi-level caching strategy:

**Why we do this:** Effective caching:
- Reduces redundant computation
- Minimizes API calls to OpenAI
- Improves response times
- Ensures consistent responses for identical queries
- Optimizes resource usage

```python
# Redis-based caching decorator from utils/decorators.py
import functools
import json
import hashlib
import time
import redis
import os
import inspect
from typing import Callable, Any

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost")
redis_client = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)

def cache_result(ttl_seconds=3600):
    """
    Cache function results in Redis.
    
    Args:
        ttl_seconds: Time-to-live for cached results in seconds
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Create a unique key from function name and arguments
            key_parts = [func.__name__]
            
            # Add positional args
            for arg in args:
                if isinstance(arg, (str, int, float, bool)):
                    key_parts.append(str(arg))
                else:
                    try:
                        key_parts.append(json.dumps(arg))
                    except:
                        # If we can't serialize, use object id as fallback
                        key_parts.append(str(id(arg)))
            
            # Add keyword args (sorted for consistency)
            for k in sorted(kwargs.keys()):
                v = kwargs[k]
                key_parts.append(k)
                if isinstance(v, (str, int, float, bool)):
                    key_parts.append(str(v))
                else:
                    try:
                        key_parts.append(json.dumps(v))
                    except:
                        key_parts.append(str(id(v)))
            
            # Create a hash of the key parts
            cache_key = hashlib.md5("_".join(key_parts).encode()).hexdigest()
            
            # Check if result is in cache
            cached = redis_client.get(cache_key)
            if cached:
                try:
                    return json.loads(cached)
                except:
                    # If we can't deserialize, ignore cache
                    pass
            
            # Call the original function
            result = await func(*args, **kwargs) if inspect.iscoroutinefunction(func) else func(*args, **kwargs)
            
            # Store result in cache
            try:
                redis_client.setex(cache_key, ttl_seconds, json.dumps(result))
            except:
                # If we can't serialize, just return the result
                pass
            
            return result
        return wrapper
    return decorator
```

## 9.6 Data Retention and Privacy

Our system implements data retention policies and privacy controls:

**Why we do this:** Proper data management ensures:
- Compliance with regulations (GDPR, CCPA, etc.)
- Protection of sensitive information
- Minimization of storage requirements
- Risk reduction for data breaches

Key privacy and retention strategies:
- Incident data is stored with role-based access controls
- PII is anonymized in vector embeddings
- Analysis results are encrypted in the database
- Automated purging of data based on configurable retention periods
- Audit logs for all access to sensitive data

## 9.7 Backup and Recovery

To ensure data durability, we implement backup and recovery procedures:

- Daily database backups
- Vector index snapshots
- Redundant storage for JSON backups
- Point-in-time recovery capability
- Automated recovery testing

By implementing comprehensive persistence strategies, our system ensures that valuable analysis results are preserved while maintaining performance, privacy, and compliance. 