"""SeekThreat API: engagement/authorization management and scan dispatch over Celery."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from apps.api.core.config import settings
from apps.api.routers import engagements, observations, scans

app = FastAPI(
    title="SeekThreat",
    description="Centralized vulnerability detection and intelligent query interface",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(engagements.router, prefix="/engagements", tags=["engagements"])
app.include_router(scans.router, prefix="/scans", tags=["scans"])
app.include_router(observations.router, prefix="/observations", tags=["observations"])
