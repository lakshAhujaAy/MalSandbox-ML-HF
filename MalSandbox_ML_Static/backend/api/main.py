"""
Dynamic Malware Analysis Sandbox — FastAPI entrypoint
"""
import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from api.models import AnalysisRequest, AnalysisResponse, JobStatus
from api.connection_manager import ConnectionManager
from job_queue_service.job_queue import JobQueue
from sandbox.orchestrator import SandboxOrchestrator
from utils.logger import get_logger

logger = get_logger(__name__)
manager = ConnectionManager()
job_queue: JobQueue = None
orchestrator: SandboxOrchestrator = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global job_queue, orchestrator
    job_queue = JobQueue()
    await job_queue.connect()
    orchestrator = SandboxOrchestrator(job_queue=job_queue, ws_manager=manager)
    asyncio.create_task(orchestrator.run_forever())
    logger.info("Sandbox orchestrator started")
    yield
    await job_queue.disconnect()
    logger.info("Shutdown complete")


app = FastAPI(
    title="Malware Sandbox API",
    description="Dynamic malware analysis with ML classification",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── REST endpoints ────────────────────────────────────────────────────────────

@app.post("/analyze", response_model=AnalysisResponse)
async def submit_analysis(req: AnalysisRequest):
    """Submit a URL or file hash for sandboxed analysis."""
    job_id = str(uuid.uuid4())
    await job_queue.push(job_id, req.model_dump())
    logger.info(f"Job queued: {job_id} → {req.target}")
    return AnalysisResponse(
        job_id=job_id,
        status=JobStatus.QUEUED,
        target=req.target,
        submitted_at=datetime.utcnow().isoformat(),
    )


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    """Poll job status and results."""
    result = await job_queue.get_result(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return result


@app.get("/jobs")
async def list_jobs(limit: int = 20):
    """List recent analysis jobs."""
    return await job_queue.list_recent(limit)


@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


# ── WebSocket — live job stream ───────────────────────────────────────────────

@app.websocket("/ws/{job_id}")
async def websocket_job(websocket: WebSocket, job_id: str):
    """Stream live progress events for a specific job."""
    await manager.connect(job_id, websocket)
    try:
        while True:
            await asyncio.sleep(30)  # keep-alive ping
    except WebSocketDisconnect:
        manager.disconnect(job_id, websocket)


@app.websocket("/ws/feed/all")
async def websocket_feed(websocket: WebSocket):
    """Broadcast all job events to dashboard subscribers."""
    await manager.connect("__feed__", websocket)
    try:
        while True:
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        manager.disconnect("__feed__", websocket)
