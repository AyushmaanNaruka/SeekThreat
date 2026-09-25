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
# Similarly, nuclei-templates is pinned to an immutable release archive with
# SHA256 verification (MIT — see THIRD_PARTY.md) to guarantee deterministic builds.
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_TEMPLATES_VERSION=10.4.9
ARG NUCLEI_TEMPLATES_SHA256=1c70b9c6797a9cdcf8c8b328377f8019c6ec0d1523cdc0341be143172bbf6dec

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap curl unzip ca-certificates \
    && curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum -c - \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && curl -fsSL -o /tmp/nuclei-templates.zip \
        "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.zip" \
    && echo "${NUCLEI_TEMPLATES_SHA256}  /tmp/nuclei-templates.zip" | sha256sum -c - \
    && unzip -q -o /tmp/nuclei-templates.zip -d /root \
    && mv /root/nuclei-templates-${NUCLEI_TEMPLATES_VERSION} /root/nuclei-templates \
    && rm /tmp/nuclei.zip /tmp/nuclei-templates.zip \
    && apt-get purge -y --auto-remove curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer-cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source tree
COPY . .

# Default: run the API. Override with command: in docker-compose for the worker.
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
