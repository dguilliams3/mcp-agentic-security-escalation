echo "Downloading CVE data..."
python ./setup/download_cve_data.py

echo "Building FAISS indexes for KEV and NVD..."
python ./setup/build_faiss_KEV_and_NVD_indexes.py

echo "Building historical incident analysis index..."
python ./setup/build_historical_incident_analyses_index.py

echo "Done!"