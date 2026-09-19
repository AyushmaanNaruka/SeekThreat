# SeekThreat API & Worker image
# Single image — command: override selects API (uvicorn) vs worker (celery).
#
# Build context: project root (e.g. docker compose uses context: ..)
#
# Usage:
#   docker build -f apps/api/Dockerfile -t seekthreat-api .

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (nmap for the scanner adapter)
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer-cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source tree
COPY . .

# Default: run the API. Override with command: in docker-compose for the worker.
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
