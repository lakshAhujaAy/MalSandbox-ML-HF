"""
ml/worker.py — standalone ML worker process
Pulls raw sandbox results from Redis, runs all 3 models, writes back scores.
Used when ML is offloaded from the API process (e.g. GPU server).
"""
import asyncio
import json
import os
import signal
import sys

import redis.asyncio as aioredis

from ml.url_nlp.analyzer import URLAnalyzer
from ml.behavior.analyzer import BehaviorAnalyzer
from ml.vision.analyzer import VisionAnalyzer
from utils.logger import get_logger

logger = get_logger("ml.worker")

ML_QUEUE = "sandbox:ml_queue"
RESULT_PREFIX = "sandbox:ml_result:"


class MLWorker:
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.vision_analyzer = VisionAnalyzer()
        self._running = True

    async def run(self):
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        r = await aioredis.from_url(redis_url, decode_responses=True)
        logger.info(f"ML Worker connected to Redis: {redis_url}")

        while self._running:
            try:
                item = await r.brpop(ML_QUEUE, timeout=3)
                if item is None:
                    continue

                _, raw = item
                payload = json.loads(raw)
                job_id = payload.get("job_id")
                target = payload.get("target", "")
                sandbox = payload.get("sandbox", {})

                logger.info(f"Processing ML job: {job_id}")

                url_result = self.url_analyzer.analyze(target)
                behavior_result = self.behavior_analyzer.analyze(sandbox)
                vision_result = self.vision_analyzer.analyze(sandbox)

                result = {
                    "job_id": job_id,
                    "url_nlp": url_result,
                    "behavior": behavior_result,
                    "vision": vision_result,
                }

                await r.set(
                    f"{RESULT_PREFIX}{job_id}",
                    json.dumps(result),
                    ex=3600
                )
                logger.info(f"ML job complete: {job_id}")

            except Exception as e:
                logger.exception(f"ML worker error: {e}")
                await asyncio.sleep(1)

        await r.aclose()
        logger.info("ML Worker stopped")

    def stop(self):
        self._running = False


async def main():
    worker = MLWorker()

    def shutdown(sig, frame):
        logger.info(f"Signal {sig} received, shutting down…")
        worker.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
