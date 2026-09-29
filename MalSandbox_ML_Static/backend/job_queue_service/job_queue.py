"""Job queue with Redis in production and an in-memory fallback for local development."""
import asyncio
import json
import os
from collections import deque
from datetime import datetime
from typing import Optional, List, Dict, Any

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None

from api.models import JobStatus
from utils.logger import get_logger

logger = get_logger(__name__)
QUEUE_KEY = "sandbox:queue"
JOB_PREFIX = "sandbox:job:"
RECENT_KEY = "sandbox:recent"


class JobQueue:
    def __init__(self):
        self._url = os.getenv("REDIS_URL", "redis://localhost:6379")
        self._redis = None
        self._local = os.getenv("LOCAL_MODE", "0") == "1" or aioredis is None
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._recent = deque(maxlen=100)
        self._queue: asyncio.Queue[str] = asyncio.Queue()

    async def connect(self):
        if self._local:
            logger.info("Using in-memory queue (LOCAL_MODE or Redis package unavailable)")
            return
        try:
            self._redis = await aioredis.from_url(self._url, decode_responses=True)
            await self._redis.ping()
            logger.info(f"Redis connected: {self._url}")
        except Exception as exc:
            logger.warning(f"Redis unavailable ({exc}); using in-memory queue")
            self._redis = None
            self._local = True

    async def disconnect(self):
        if self._redis:
            await self._redis.aclose()

    async def push(self, job_id: str, payload: Dict[str, Any]):
        data = {
            "job_id": job_id,
            "status": JobStatus.QUEUED,
            "submitted_at": datetime.utcnow().isoformat(),
            **payload,
        }
        if self._local:
            self._jobs[job_id] = data
            self._recent.appendleft(job_id)
            await self._queue.put(job_id)
            return
        await self._redis.set(f"{JOB_PREFIX}{job_id}", json.dumps(data))
        await self._redis.lpush(QUEUE_KEY, job_id)
        await self._redis.lpush(RECENT_KEY, job_id)
        await self._redis.ltrim(RECENT_KEY, 0, 99)

    async def pop(self, timeout: int = 5) -> Optional[Dict[str, Any]]:
        if self._local:
            try:
                job_id = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            except asyncio.TimeoutError:
                return None
            return self._jobs.get(job_id)
        result = await self._redis.brpop(QUEUE_KEY, timeout=timeout)
        if result is None:
            return None
        _, job_id = result
        raw = await self._redis.get(f"{JOB_PREFIX}{job_id}")
        return json.loads(raw) if raw else None

    async def update(self, job_id: str, updates: Dict[str, Any]):
        if self._local:
            data = self._jobs.get(job_id, {})
            data.update(updates)
            self._jobs[job_id] = data
            return
        raw = await self._redis.get(f"{JOB_PREFIX}{job_id}")
        data = json.loads(raw) if raw else {}
        data.update(updates)
        await self._redis.set(f"{JOB_PREFIX}{job_id}", json.dumps(data), ex=3600)

    async def get_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        if self._local:
            return self._jobs.get(job_id)
        raw = await self._redis.get(f"{JOB_PREFIX}{job_id}")
        return json.loads(raw) if raw else None

    async def list_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        if self._local:
            return [self._jobs[j] for j in list(self._recent)[:limit] if j in self._jobs]
        job_ids = await self._redis.lrange(RECENT_KEY, 0, limit - 1)
        results = []
        for jid in job_ids:
            raw = await self._redis.get(f"{JOB_PREFIX}{jid}")
            if raw:
                results.append(json.loads(raw))
        return results
