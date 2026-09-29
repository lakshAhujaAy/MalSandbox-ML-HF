from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, HttpUrl, field_validator


class TargetType(str, Enum):
    URL = "url"
    FILE_HASH = "file_hash"


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"


class AnalysisRequest(BaseModel):
    target: str
    target_type: TargetType = TargetType.URL
    options: Dict[str, Any] = {}

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target must not be empty")
        return v


class ThreatLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class MLScore(BaseModel):
    model: str
    score: float          # 0.0 = safe, 1.0 = malicious
    confidence: float
    threat_level: ThreatLevel
    features: Dict[str, Any] = {}
    reasoning: List[str] = []


class SandboxLog(BaseModel):
    timestamp: str
    level: str            # info | warn | alert
    category: str         # network | filesystem | process | visual
    message: str
    raw: Optional[Dict[str, Any]] = None


class SandboxResult(BaseModel):
    network_requests: List[Dict[str, Any]] = []
    dns_queries: List[str] = []
    file_operations: List[Dict[str, Any]] = []
    process_events: List[Dict[str, Any]] = []
    screenshot_b64: Optional[str] = None
    page_title: Optional[str] = None
    final_url: Optional[str] = None
    logs: List[SandboxLog] = []
    execution_ms: int = 0


class AnalysisResponse(BaseModel):
    job_id: str
    status: JobStatus
    target: str
    submitted_at: str


class AnalysisResult(BaseModel):
    job_id: str
    status: JobStatus
    target: str
    submitted_at: str
    completed_at: Optional[str] = None

    # Aggregate
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    aggregate_score: float = 0.0

    # Per-model results
    url_nlp: Optional[MLScore] = None
    behavior: Optional[MLScore] = None
    vision: Optional[MLScore] = None

    # Raw sandbox data
    sandbox: Optional[SandboxResult] = None
    error: Optional[str] = None
