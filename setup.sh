#!/bin/bash
# Setup script for RAD Security CVE Analysis Agent

echo "Setting up RAD Security CVE Analysis Agent..."

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null || ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker and Docker Compose are required to run this application."
    echo "Please install them first: https://docs.docker.com/get-docker/"
    exit 1
fi

echo "Checking for .env file..."
if [ ! -f .env ]; then
    echo "Creating .env file..."
    echo "OPENAI_API_KEY=" > .env
    echo "MODEL_NAME=gpt-4o-mini" >> .env
    echo "REDIS_URL=redis://redis:6379" >> .env
    echo "LOG_LEVEL=INFO" >> .env
    echo "DATABASE_URL=sqlite:///data/incident_analysis.db" >> .env
    echo ".env file created. Please add your OpenAI API key to the .env file."
    echo "You can do this by running: echo \"OPENAI_API_KEY=your_key_here\" >> .env"
fi

# Run setup scripts to download and process CVE data
echo "Running setup scripts to download CVE data and build indexes..."
cd setup
sh setup_initial_CVE_data_and_FAISS_indexes.sh
cd ..

echo "Setup complete! You can now run the application using Docker Compose."
echo "To start the application: docker-compose up -d"
echo "To view logs: docker-compose logs -f"
echo "To stop the application: docker-compose down"

echo "Thank you for trying out RAD Security CVE Analysis Agent!" 