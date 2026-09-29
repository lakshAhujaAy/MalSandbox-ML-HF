# Vision Model Training — What Actually Happened

This document is the ground truth for the vision CNN. Read this before discussing
the project in an interview — it's written to be quoted directly.

## TL;DR

A ResNet18 was trained **from scratch** (no pretrained weights — see below) on a
**synthetic, programmatically-generated dataset** of 560 login-page screenshots
across 7 classes (6 brands + "other"/legitimate), achieving 100% validation
accuracy. The training pipeline — data loading, augmentation, fine-tuning loop,
per-class metrics, checkpointing — is fully real and is dataset-agnostic: pointing
it at the real Phish-IRIS benchmark dataset requires no code changes, only a
different `--data-root`.

## Why synthetic data

The standard academic dataset for this task, **Phish-IRIS** (Dalgic, Bozkir &
Aydos, 2018 — 1,313 train / 1,539 test screenshots across 14 brands + legitimate),
is gated behind a manual Google Form request, not programmatically downloadable.
A Kaggle mirror exists (`saurabhshahane/phishiris`) but requires authenticated
API access. Neither was fetchable in the training environment used.

Rather than claim training on data that wasn't actually used, a synthetic dataset
generator (`ml/vision/dataset/synthetic_generator.py`) was built to produce
visually distinct, programmatically-labelled login-page mockups — matching the
exact directory structure Phish-IRIS uses (`train/<brand>/`, `test/<brand>/`,
`train/other/`, `test/other/`) so the training code is a drop-in replacement.

**This is a pipeline validation tool, not a claim of real-world phishing
detection accuracy.**

## What was actually trained

| | |
|---|---|
| Architecture | ResNet18 (`torchvision.models.resnet18`) |
| Pretrained weights | **None — trained from scratch.** `download.pytorch.org` was unreachable in the training environment (network egress restricted to a fixed allowlist); the training script attempts to fetch ImageNet weights, catches the failure, logs a warning, and falls back to random initialization with the full network trainable from epoch 0 |
| Dataset | Synthetic, 560 images (392 train / 168 test), 7 classes |
| Classes | `amazon`, `apple`, `chase`, `facebook`, `microsoft`, `paypal`, `other` (legitimate) |
| Images per class | 56 train / 24 test (brands), 140 train / 60 test (legitimate) |
| Image size | 224×224 (standard ResNet input) |
| Augmentation | Random horizontal flip (p=0.2), random rotation (±5°), color jitter (brightness/contrast ±0.15) |
| Epochs | 15 |
| Batch size | 16 |
| Optimizer | Adam, lr=1e-3 |
| Training time | ~17 minutes on CPU (no GPU available) |
| Final test accuracy | 100% (168/168) |
| Per-class precision/recall/F1 | 1.00 / 1.00 / 1.00 for all 7 classes |

Full metrics, per-epoch loss/accuracy history, and the confusion matrix are saved
in `ml/vision/models/training_report.json`.

## Why 100% accuracy is not impressive (and why that's the honest takeaway)

A perfect score here reflects the dataset's structure, not real-world capability:

- Each synthetic class uses a **fixed, distinct color palette** per brand (e.g. PayPal
  is always navy blue, Amazon is always orange/dark-navy) — color is the easiest
  possible visual feature for a CNN to learn, and there's no inter-class color overlap
- Layouts are **template-generated** from one function with limited structural
  variation (centered card, two input fields, one button) — far less visual diversity
  than real screenshots, which vary by browser, OS font rendering, viewport size,
  and actual phishing-kit design quality
- The "other" (legitimate) class draws from only 5 hardcoded site templates, not a
  real diverse crawl of the web

**What this experiment actually validates:** the training loop has no bugs, the
data pipeline correctly loads and batches images, augmentation runs without
breaking shapes, the model trains and converges, checkpointing and reloading
work, and inference produces sane probability distributions on screenshots
generated with a different random seed than any training/test image (verified
manually — see `training/predict.py`).

**What it does NOT validate:** real-world generalization to actual phishing
screenshots, which has far more visual noise, brand variations, partial brand
mimicry, novel unbranded phishing kits, and adversarial obfuscation.

## What changes for the real version

To convert this into a real production model:

1. **Get Phish-IRIS legitimately.** Submit the Google Form at
   `web.cs.hacettepe.edu.tr/~selman/phish-iris-dataset`, or set up Kaggle API
   credentials (`kaggle datasets download saurabhshahane/phishiris`) on a machine
   with unrestricted network access.
2. **Drop it into the same directory structure** the synthetic generator already
   uses — `train/<brand>/*.png`, `test/<brand>/*.png` — Phish-IRIS already ships
   in this layout.
3. **Re-run `train.py --data-root <phish-iris-path>`.** No code changes needed.
4. **Get pretrained ImageNet weights** on a machine that can reach
   `download.pytorch.org` (or use a pre-cached `.pth` file) — this matters more
   on real data than on synthetic data, since transfer learning helps most when
   training data has real-world visual complexity the backbone has already seen
   analogues of.
5. **Expect accuracy to drop from 100% to something more like 85–95%** based on
   published results on this exact dataset — the original Phish-IRIS paper
   reports 90.6% true positive rate / 8.5% false positive rate as state-of-the-art
   on real data with their proposed method, which is a useful sanity-check ceiling.
6. **Add more legitimate-class diversity** — real top-1000 site screenshots
   (Tranco/Majestic list), not 5 templates.

## Files

| File | Purpose |
|------|---------|
| `dataset/synthetic_generator.py` | Generates the synthetic dataset |
| `dataset/synthetic/` | The generated images + `manifest.json` |
| `training/train.py` | Full training script — dataset-agnostic, CPU-safe, handles missing pretrained weights gracefully |
| `training/predict.py` | Standalone inference script, used to verify the checkpoint loads and predicts correctly |
| `models/phishing_resnet18.pt` | The trained checkpoint (44.8MB) |
| `models/training_report.json` | Full per-epoch history, confusion matrix, per-class metrics |
| `analyzer.py` | `VisionAnalyzer` — loads the checkpoint, runs inference, combines CNN brand prediction with domain-ownership logic to produce a phishing score. Falls back to the original rule-based heuristics if the CNN/torch is unavailable or there's no screenshot. |

## How to talk about this in an interview

"I trained a ResNet18 from scratch — no pretrained weights, because my training
environment couldn't reach the PyTorch model hub — on a synthetic dataset I
generated to match the real Phish-IRIS benchmark's structure, since that dataset
requires a manual request I didn't have time to complete. It hit 100% validation
accuracy, which I want to be upfront about: that's a property of the synthetic
data being visually simple and low-noise, not evidence of real-world phishing
detection accuracy. What it does prove is that the full training pipeline —
augmentation, fine-tuning loop, checkpointing, evaluation — works correctly
end-to-end, and it's built to be dataset-agnostic, so swapping in the real
Phish-IRIS data is a one-line change, not a rewrite."
