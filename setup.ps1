# Setup script for RAD Security CVE Analysis Agent (PowerShell Version)

Write-Host "Setting up RAD Security CVE Analysis Agent..." -ForegroundColor Green

# Check if Docker and Docker Compose are installed
$dockerInstalled = $null -ne (Get-Command "docker" -ErrorAction SilentlyContinue)
if (-not $dockerInstalled) {
    Write-Host "Error: Docker is required to run this application." -ForegroundColor Red
    Write-Host "Please install Docker Desktop: https://docs.docker.com/desktop/install/windows-install/" -ForegroundColor Red
    exit 1
}

Write-Host "Checking for .env file..." -ForegroundColor Cyan
if (-not (Test-Path .env)) {
    Write-Host "Creating .env file..." -ForegroundColor Yellow
    @"
OPENAI_API_KEY=
MODEL_NAME=gpt-4o-mini
REDIS_URL=redis://redis:6379
LOG_LEVEL=INFO
DATABASE_URL=sqlite:///data/incident_analysis.db
"@ | Out-File -FilePath .env -Encoding utf8

    Write-Host ".env file created. Please add your OpenAI API key to the .env file." -ForegroundColor Yellow
    Write-Host "You can do this by adding your key after OPENAI_API_KEY= in the .env file." -ForegroundColor Yellow
}

# Run setup scripts to download and process CVE data
Write-Host "Running setup scripts to download CVE data and build indexes..." -ForegroundColor Cyan
Set-Location -Path .\setup
& .\setup_initial_CVE_data_and_FAISS_indexes.sh
Set-Location ..

Write-Host "Setup complete! You can now run the application using Docker Compose." -ForegroundColor Green
Write-Host "To start the application: docker-compose up -d" -ForegroundColor Cyan
Write-Host "To view logs: docker-compose logs -f" -ForegroundColor Cyan
Write-Host "To stop the application: docker-compose down" -ForegroundColor Cyan

Write-Host "Thank you for trying out RAD Security CVE Analysis Agent!" -ForegroundColor Green 