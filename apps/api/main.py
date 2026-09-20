"""SeekThreat API. Scaffold only."""

from fastapi import FastAPI

from apps.api.routers import engagements, scans

app = FastAPI(
    title="SeekThreat",
    description="Centralized vulnerability detection and intelligent query interface",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(engagements.router, prefix="/engagements", tags=["engagements"])
app.include_router(scans.router, prefix="/scans", tags=["scans"])
