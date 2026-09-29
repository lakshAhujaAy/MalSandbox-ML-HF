# Contributing

Thanks for your interest in improving MalSandbox ML. Here's how to get set up.

## Development setup

```bash
git clone https://github.com/your-username/sandbox-ml
cd sandbox-ml

# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-ml.txt
pip install pytest ruff

# Frontend
cd ../frontend
npm install
```

## Running tests

```bash
cd backend
pytest tests/ -v
```

## Linting

```bash
ruff check backend/
```

## Branch convention

| Branch | Purpose |
|--------|---------|
| `main` | Stable, passing CI |
| `dev` | Integration branch |
| `feat/<name>` | New features |
| `fix/<name>` | Bug fixes |

## Pull request checklist

- [ ] All existing tests pass (`pytest tests/`)
- [ ] New behaviour has tests
- [ ] No secrets or real URLs committed
- [ ] `ruff check` passes with no errors
- [ ] Updated `README.md` if you changed the architecture or API

## Adding a new ML model

1. Create `backend/ml/<model_name>/analyzer.py`
2. Implement an `analyze(input) -> dict` method that returns `{model, score, confidence, threat_level, features, reasoning}`
3. Register it in `sandbox/orchestrator.py` under `_handle_job`
4. Add its weight to `_aggregate()`
5. Wire it into the React dashboard in `frontend/src/App.jsx`
6. Add tests in `backend/tests/test_ml_models.py`

## Reporting issues

Please include:
- OS and Docker version
- The URL or sample that triggered the issue (redact if sensitive)
- Full error output from `docker compose logs api`
