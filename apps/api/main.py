"""SeekThreat API. Scaffold only."""

from fastapi import FastAPI

app = FastAPI(
    title="SeekThreat",
    description="Centralized vulnerability detection and intelligent query interface",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


# TODO: routers
#   /engagements   create engagement + authorization record
#   /scans         dispatch scans — MUST validate authorization first
#   /findings      normalized, enriched findings
#   /paths         attack paths with per-edge evidence
#   /assistant     RAG queries with citations
#
# Authorization is enforced HERE, not in the UI.
