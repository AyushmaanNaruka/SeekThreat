# SeekThreat API & Worker image
# Single image — command: override selects API (uvicorn) vs worker (celery).
#
# Build context: project root (e.g. docker compose uses context: ..)
#
# Usage:
#   docker build -f apps/api/Dockerfile -t seekthreat-api .

FROM python:3.11-slim

WORKDIR /app

# nmap: available as an apt package.
# nuclei (ProjectDiscovery, MIT — see THIRD_PARTY.md): NOT packaged for
# Debian, so we fetch the pinned linux_amd64 release binary directly and
# verify it against the release's published sha256 checksum before
# extracting. Bump NUCLEI_VERSION and NUCLEI_SHA256 together when updating.
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap curl unzip ca-certificates \
    && curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum -c - \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && apt-get purge -y --auto-remove curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer-cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source tree
COPY . .

# Default: run the API. Override with command: in docker-compose for the worker.
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
