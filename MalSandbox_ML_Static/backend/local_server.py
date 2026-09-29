"""One-command local launcher for MalSandbox ML.

Runs the actual FastAPI API + orchestrator and serves the local dashboard from
this repository. LOCAL_MODE keeps Redis optional; Docker is already handled by
the orchestrator's existing simulation fallback.
"""
import os
os.environ.setdefault("LOCAL_MODE", "1")
os.environ.setdefault("HF_SPACE", "0")

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from api.main import app

DASHBOARD = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "local"))
app.mount("/dashboard", StaticFiles(directory=DASHBOARD, html=True), name="dashboard")

@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(os.path.join(DASHBOARD, "index.html"))
