# Changelog

All notable changes to this project will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] — 2025-01-15

### Added
- FastAPI backend with REST + WebSocket endpoints
- Redis-backed FIFO job queue with pub/sub streaming
- Sandbox orchestrator with Docker container lifecycle management
- Playwright headless browser execution inside isolated containers
- **ML Model 1 — URL NLP:** Shannon entropy, DGA detection, brand mismatch, IP-in-URL, typosquatting heuristics
- **ML Model 2 — Behavior Classifier:** Binary download detection, C2 port analysis, encoded PowerShell detection, process injection heuristics
- **ML Model 3 — Vision CNN:** Brand color palette matching, urgency language detection, phishing layout analysis
- Weighted aggregate scoring (URL 25% · Behavior 45% · Vision 30%)
- React 18 dashboard with live WebSocket feed, radar chart, sandbox telemetry tabs
- Docker Compose orchestration for all services
- GitHub Actions CI pipeline (lint, test, Docker build)
- Comprehensive unit tests for all three ML models
