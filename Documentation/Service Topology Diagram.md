+---------------------+
|   Analyzer Service  |
|   (run_analysis.py) |
+---------------------+
           |
           |  REST POST /analyze_incidents
           v
+---------------------+         +-------------------+
|   FastAPI Server    | <-----> |   Redis (Cache)   |
| (main_security_...) |         +-------------------+
           |
           |  read/write
           v
+---------------------+
|     SQLite DB       |
|  (incident records) |
+---------------------+
           ^
           |  read-only
           |
+---------------------+
|   Streamlit UI      |
| (incident_dashboard)|
+---------------------+
