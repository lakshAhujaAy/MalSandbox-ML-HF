---
title: MalSandbox ML
emoji: 🛡️
colorFrom: indigo
colorTo: purple
sdk: static
pinned: false
short_description: Interactive browser demo of the MalSandbox ML threat-analysis pipeline.
---

# MalSandbox ML

Interactive static demonstration of **MalSandbox ML**, a dynamic malware-analysis and threat-classification project.

## What this Space demonstrates

- URL NLP analysis
- Behavioral evidence
- Vision/phishing evidence
- 25% / 45% / 30% weighted aggregation
- SAFE / SUSPICIOUS / MALICIOUS verdicts
- Pipeline visualization and demo telemetry

## Important deployment note

This is a **Static Space**, so it does not run the project's FastAPI, Redis, Docker sandbox, or Playwright browser. It intentionally does not execute or browse arbitrary submitted URLs. The browser demo uses deterministic heuristics and simulated telemetry to demonstrate the analysis workflow safely.

The complete project architecture remains:

`URL → FastAPI → Redis → ephemeral Docker sandbox → Playwright telemetry → URL/Behavior/Vision analysis → weighted verdict → WebSocket/dashboard`

See the full implementation in the project repository:
https://github.com/lakshAhujaAy/sandbox-ml

## Project model configuration

- URL NLP: 25%
- Behavior: 45%
- Vision CNN: 30%

The project synopsis reports an 88,647-row labeled phishing dataset for the URL model, 93% test accuracy, 82.5% recall on held-out real PhishTank URLs, MITRE ATT&CK-grounded synthetic behavior telemetry, and a ResNet18-based vision model.
