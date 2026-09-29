# MalSandbox ML — Local Working Demo

This local mode uses the **actual backend analyzers and orchestrator code from the project**.
It adds only a development fallback so the application can run on a machine without Redis or Docker:

- Redis → in-memory FIFO queue when `LOCAL_MODE=1`.
- Docker → the repository's existing `_simulate_sandbox()` fallback when Docker is unavailable.
- URL NLP → actual `URLAnalyzer`.
- Behavior → actual `BehaviorAnalyzer`.
- Vision → actual `VisionAnalyzer`; without a real browser screenshot it transparently uses its existing rule-based fallback.
- Aggregation → the actual 25% / 45% / 30% weighted aggregation in `SandboxOrchestrator`.
- UI → local dashboard served by FastAPI at `/`.

## Run

```bash
python run_local.py
```

Open **http://127.0.0.1:8000**.

The browser dashboard submits to the real `/analyze` endpoint and polls `/jobs/<job_id>`. The API also exposes `/docs`.

For the full production-style stack (Redis + Docker sandbox + React frontend), use the original `docker-compose.yml` on a machine with Docker.
