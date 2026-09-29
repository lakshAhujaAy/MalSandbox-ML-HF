"""
ML Model 3 — Vision CNN / Phishing Page Detector
=================================================
Analyses the screenshot captured by the sandbox to detect:
  • Brand impersonation (login pages that look like known brands)
  • Suspicious visual layouts (fake CAPTCHA, urgent warning banners)
  • Credential harvesting UI patterns

This uses a fine-tuned ResNet18 CNN (backend/ml/vision/models/phishing_resnet18.pt)
trained on a synthetic phishing-screenshot dataset structured identically to the
real Phish-IRIS benchmark (brand subfolders + "other"/legitimate class) — see
ml/vision/training/train.py and ml/vision/dataset/synthetic_generator.py.

IMPORTANT — honesty about the training data: the CNN currently ships trained on
PROGRAMMATICALLY GENERATED login-page mockups, not real phishing screenshots. This
was a deliberate choice to validate the full training pipeline (data loading,
augmentation, fine-tuning loop, evaluation, checkpointing) end-to-end without
requiring manual download of the real Phish-IRIS dataset (which is gated behind
a manual form, not fetchable in this environment). The code is dataset-agnostic —
pointing `--data-root` at a real Phish-IRIS-structured directory and re-running
train.py is the only change needed to retrain on real data. The rule-based
heuristic scorer below remains as a fallback when the CNN is unavailable or
when there's no screenshot to analyze (URL/title-only signals).
"""
import base64
import io
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── Brand visual fingerprints (dominant colour palettes) ─────────────────────
# Each entry: (brand_name, [(R,G,B), ...primary colours], suspicious_keywords_on_page)
BRAND_PROFILES = [
    ("PayPal",     [(0, 48, 135),  (0, 112, 192)], ["paypal", "pay pal", "payment"]),
    ("Microsoft",  [(0, 114, 198), (255, 185, 0)],  ["microsoft", "outlook", "office 365", "onedrive"]),
    ("Apple",      [(0, 0, 0),     (255, 255, 255)], ["apple", "icloud", "apple id"]),
    ("Google",     [(66, 133, 244),(219, 68, 55)],   ["google", "gmail", "google account"]),
    ("Amazon",     [(255, 153, 0), (35, 47, 62)],    ["amazon", "aws", "prime"]),
    ("Facebook",   [(24, 119, 242),(255, 255, 255)],  ["facebook", "meta", "instagram"]),
    ("Netflix",    [(229, 9, 20),  (0, 0, 0)],        ["netflix", "streaming"]),
    ("Chase",      [(0, 39, 100),  (0, 120, 200)],    ["chase", "jpmorgan", "bank"]),
    ("Wells Fargo",[(207, 0, 0),   (255, 215, 0)],    ["wells fargo", "wellsfargo"]),
]

DEFAULT_MODEL_PATH = Path(__file__).parent / "models" / "phishing_resnet18.pt"


class VisionAnalyzer:
    """
    Screenshot-based phishing detector.
    Primary path: trained CNN (ResNet18) brand/legitimacy classifier.
    Fallback path: rule-based heuristics (color matching, title keywords),
    used when the CNN/torch is unavailable or there's no screenshot.
    """

    def __init__(self, model_path: Optional[str] = None):
        self._pil_available = self._check_pil()
        self._cnn = None
        self._cnn_classes: List[str] = []
        self._cnn_img_size = 224
        self._load_cnn(model_path or str(DEFAULT_MODEL_PATH))

    def _load_cnn(self, model_path: str):
        """Attempt to load the trained CNN checkpoint. Silently no-ops if
        torch/torchvision aren't installed or the checkpoint is missing —
        the analyzer degrades to rule-based scoring in that case."""
        if not os.path.exists(model_path):
            return
        try:
            import torch
            import torch.nn as nn
            from torchvision import models as tv_models

            checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
            self._cnn_classes = checkpoint["classes"]
            self._cnn_img_size = checkpoint.get("img_size", 224)

            model = tv_models.resnet18(weights=None)
            model.fc = nn.Linear(model.fc.in_features, len(self._cnn_classes))
            model.load_state_dict(checkpoint["model_state_dict"])
            model.eval()

            self._cnn = model
        except Exception:
            # torch not installed, corrupt checkpoint, etc. — fall back to rules.
            self._cnn = None
            self._cnn_classes = []

    def _cnn_predict(self, screenshot_b64: str) -> Optional[Dict[str, Any]]:
        """Run the trained CNN on the screenshot. Returns ranked class
        probabilities, or None if the CNN isn't loaded or decoding fails."""
        if self._cnn is None:
            return None
        try:
            import torch
            import torch.nn.functional as F
            from torchvision import transforms
            from PIL import Image

            image_bytes = base64.b64decode(screenshot_b64)
            img = Image.open(io.BytesIO(image_bytes)).convert("RGB")

            tf = transforms.Compose([
                transforms.Resize((self._cnn_img_size, self._cnn_img_size)),
                transforms.ToTensor(),
                transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
            ])
            tensor = tf(img).unsqueeze(0)

            with torch.no_grad():
                logits = self._cnn(tensor)
                probs = F.softmax(logits, dim=1)[0]

            ranked = sorted(zip(self._cnn_classes, probs.tolist()), key=lambda x: -x[1])
            return {"ranked": ranked, "top_class": ranked[0][0], "top_prob": ranked[0][1]}
        except Exception:
            return None

    def analyze(self, sandbox: Dict[str, Any]) -> Dict[str, Any]:
        screenshot_b64: Optional[str] = sandbox.get("screenshot_b64")
        page_title: str = sandbox.get("page_title") or ""
        final_url: str = sandbox.get("final_url") or ""

        cnn_result = self._cnn_predict(screenshot_b64) if screenshot_b64 else None

        features = self._extract_features(screenshot_b64, page_title, final_url)

        if cnn_result is not None:
            score, reasoning = self._score_with_cnn(cnn_result, features, final_url)
            model_source = "cnn"
        else:
            score, reasoning = self._score(features)
            model_source = "rule_based_fallback"

        threat_level = "safe"
        if score >= 0.70:
            threat_level = "malicious"
        elif score >= 0.40:
            threat_level = "suspicious"

        result_features = {k: v for k, v in features.items() if not k.startswith("_raw")}
        if cnn_result is not None:
            result_features["cnn_top_class"] = cnn_result["top_class"]
            result_features["cnn_top_prob"] = round(cnn_result["top_prob"], 4)

        return {
            "model": "vision",
            "model_source": model_source,  # "cnn" or "rule_based_fallback" — transparent about which path ran
            "score": round(score, 4),
            "confidence": round(self._confidence(features, screenshot_b64), 4) if cnn_result is None else round(cnn_result["top_prob"], 4),
            "threat_level": threat_level,
            "features": result_features,
            "reasoning": reasoning,
        }

    # ── CNN-based scoring ─────────────────────────────────────────────────────

    def _score_with_cnn(self, cnn_result: Dict[str, Any], features: Dict[str, Any], final_url: str) -> Tuple[float, List[str]]:
        """
        Combines the CNN's brand classification with a domain-ownership check.
        The CNN identifies WHICH brand a screenshot visually resembles (or "other"
        for legitimate/unrecognized pages); this method then checks whether the
        URL's actual domain matches that brand. A high-confidence brand match
        on a URL that doesn't belong to that brand is the core phishing signal —
        this mirrors how the rule-based fallback's brand_domain_mismatch works,
        but driven by learned visual features instead of hardcoded color palettes.
        """
        top_class = cnn_result["top_class"]
        top_prob = cnn_result["top_prob"]
        reasoning: List[str] = []

        if top_class == "other":
            # CNN thinks this looks like a legitimate/unrecognized page
            score = (1 - top_prob) * 0.3  # low score, scaled by how confident it is
            reasoning.append(
                f"Vision model classified page as legitimate/unrecognized (confidence {top_prob*100:.1f}%)"
            )
            return min(score, 1.0), reasoning

        # CNN thinks this resembles a specific brand — check domain ownership
        def _brand_owns_url(brand: str, url: str) -> bool:
            brand_slug = brand.lower().replace(" ", "")
            netloc = url.split("//")[-1].split("/")[0].lower()
            return bool(re.search(r'(?:^|\.)' + re.escape(brand_slug) + r'\.[a-z]{2,}$', netloc))

        owns_domain = _brand_owns_url(top_class, final_url)

        if not owns_domain:
            score = 0.55 + (top_prob * 0.4)  # high confidence brand match + domain mismatch = strong signal
            reasoning.append(
                f"Vision model identified page as visually matching '{top_class}' "
                f"(confidence {top_prob*100:.1f}%) but the domain does not belong to {top_class} — likely impersonation"
            )
        else:
            score = (1 - top_prob) * 0.2  # brand matches AND owns domain — likely legitimate
            reasoning.append(
                f"Vision model identified page as '{top_class}' (confidence {top_prob*100:.1f}%) "
                f"and the domain matches — consistent with the legitimate site"
            )

        # Carry over urgency-language signal from the rule-based feature extraction,
        # since the CNN only sees pixels, not page title text
        if features.get("urgency_keyword_count", 0) >= 1:
            score += 0.10
            reasoning.append("Urgency language detected in page title")

        return min(score, 1.0), reasoning

    # ── Feature extraction ────────────────────────────────────────────────────

    def _extract_features(
        self,
        screenshot_b64: Optional[str],
        page_title: str,
        final_url: str,
    ) -> Dict[str, Any]:

        title_lower = page_title.lower()
        url_lower = final_url.lower()

        # ── Text-based features (available even without screenshot) ──────────
        title_brand_match, title_brand_name = self._match_brand_text(title_lower)
        url_brand_match, url_brand_name = self._match_brand_text(url_lower)

        # Brand in title but domain doesn't match → mismatch
        def _brand_owns_url(brand: str, url: str) -> bool:
            import re as _re
            brand_slug = brand.lower().replace(" ", "")
            netloc = url.split("//")[-1].split("/")[0].lower()
            return bool(_re.search(
                r'(?:^|\.)' + _re.escape(brand_slug) + r'\.[a-z]{2,}$',
                netloc
            ))

        brand_domain_mismatch = (
            title_brand_match and
            title_brand_name is not None and
            not _brand_owns_url(title_brand_name, final_url)
        )

        urgency_keywords = [
            "verify", "urgent", "suspended", "locked", "confirm",
            "update required", "security alert", "unusual activity",
            "immediately", "within 24 hours",
        ]
        urgency_count = sum(kw in title_lower for kw in urgency_keywords)

        login_keywords = ["sign in", "log in", "login", "password", "enter your"]
        login_count = sum(kw in title_lower for kw in login_keywords)

        # ── Image-based features ──────────────────────────────────────────────
        image_features = self._analyze_image(screenshot_b64) if screenshot_b64 else {}

        return {
            "has_screenshot": screenshot_b64 is not None,
            "screenshot_size_kb": len(screenshot_b64) // 1024 if screenshot_b64 else 0,
            "page_title": page_title,
            "title_brand_match": title_brand_match,
            "title_brand_name": title_brand_name,
            "url_brand_match": url_brand_match,
            "brand_domain_mismatch": brand_domain_mismatch,
            "urgency_keyword_count": urgency_count,
            "login_keyword_count": login_count,
            **image_features,
        }

    def _analyze_image(self, b64: str) -> Dict[str, Any]:
        """Decode screenshot and extract visual features."""
        try:
            image_bytes = base64.b64decode(b64)
        except Exception:
            return {"image_decode_error": True}

        features: Dict[str, Any] = {
            "image_width": 0,
            "image_height": 0,
            "dominant_colors": [],
            "brand_color_match": False,
            "matched_brand": None,
            "brightness": 0.0,
            "is_mostly_white": False,
            "has_centered_form": False,
            "dark_overlay_detected": False,
        }

        if not self._pil_available:
            # Estimate brightness from raw bytes as fallback
            features["brightness"] = sum(image_bytes[:1000]) / max(len(image_bytes[:1000]), 1) / 255
            return features

        try:
            from PIL import Image, ImageStat
            img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            w, h = img.size
            features["image_width"] = w
            features["image_height"] = h

            # Dominant colours via thumbnail sampling
            thumb = img.resize((64, 64))
            pixels = list(thumb.getdata())
            dominant = self._dominant_colors(pixels, n=5)
            features["dominant_colors"] = [list(c) for c in dominant]

            # Brand colour matching
            brand, dist = self._match_brand_colors(dominant)
            if brand and dist < 80:
                features["brand_color_match"] = True
                features["matched_brand"] = brand

            # Brightness (0=dark, 1=bright)
            stat = ImageStat.Stat(img)
            features["brightness"] = stat.mean[0] / 255
            features["is_mostly_white"] = features["brightness"] > 0.85

            # Central form detection (bright centre + dark border)
            centre = img.crop((w // 4, h // 4, 3 * w // 4, 3 * h // 4))
            centre_stat = ImageStat.Stat(centre)
            edge_brightness = (
                ImageStat.Stat(img.crop((0, 0, w, h // 8))).mean[0] / 255
            )
            features["has_centered_form"] = (
                centre_stat.mean[0] / 255 > 0.75 and edge_brightness < 0.5
            )
            features["dark_overlay_detected"] = edge_brightness < 0.15

        except Exception as e:
            features["image_analysis_error"] = str(e)

        return features

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score(self, f: Dict[str, Any]) -> Tuple[float, List[str]]:
        score = 0.0
        reasoning: List[str] = []

        def add(pts: float, reason: str):
            nonlocal score
            score += pts
            reasoning.append(reason)

        # Brand mismatch — strongest signal
        if f.get("brand_domain_mismatch"):
            brand = f.get("title_brand_name", "a known brand")
            add(0.55, f"Page title claims to be '{brand}' but URL domain does not match — classic phishing")

        # Brand color match without domain match
        if f.get("brand_color_match") and not f.get("url_brand_match"):
            brand = f.get("matched_brand", "a known brand")
            add(0.35, f"Visual color scheme matches {brand} but domain is unrelated")

        # Urgency language
        uc = f.get("urgency_keyword_count", 0)
        if uc >= 2:
            add(0.25, f"High urgency language in page title ({uc} urgency keywords)")
        elif uc == 1:
            add(0.12, "Urgency keyword detected in page title")

        # Login form language
        lc = f.get("login_keyword_count", 0)
        if lc >= 1:
            add(0.10, f"Login/credential language in page title ({lc} keywords)")

        # Centred login form on dark background (classic phishing layout)
        if f.get("has_centered_form") and f.get("dark_overlay_detected"):
            add(0.20, "Centred credential form on dark background — common phishing layout")

        # No screenshot available — reduce confidence but note it
        if not f.get("has_screenshot"):
            score *= 0.75
            reasoning.append("Screenshot unavailable — vision analysis based on page title/URL only")

        if not reasoning:
            reasoning.append("No visual phishing indicators detected")

        return min(score, 1.0), reasoning

    def _confidence(self, features: Dict[str, Any], screenshot_b64: Optional[str]) -> float:
        base = 0.45 if screenshot_b64 else 0.30
        signals = sum([
            bool(features.get("brand_domain_mismatch")),
            bool(features.get("brand_color_match")),
            features.get("urgency_keyword_count", 0) > 0,
        ])
        return min(base + signals * 0.15, 0.95)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _check_pil() -> bool:
        try:
            from PIL import Image  # noqa: F401
            return True
        except ImportError:
            return False

    @staticmethod
    def _match_brand_text(text: str):
        for brand, _, keywords in BRAND_PROFILES:
            if any(kw in text for kw in keywords):
                return True, brand
        return False, None

    @staticmethod
    def _dominant_colors(pixels, n: int = 5):
        """Quantize pixel list to n dominant colours via simple bucketing."""
        buckets: Dict[Tuple, int] = {}
        for r, g, b in pixels:
            key = (r // 32 * 32, g // 32 * 32, b // 32 * 32)
            buckets[key] = buckets.get(key, 0) + 1
        top = sorted(buckets, key=buckets.get, reverse=True)[:n]
        return top

    @staticmethod
    def _match_brand_colors(dominant_colors):
        """Return (brand_name, min_distance) for closest brand palette match."""
        best_brand, best_dist = None, float("inf")
        for brand, palette, _ in BRAND_PROFILES:
            for dc in dominant_colors:
                for pc in palette:
                    dist = math.sqrt(sum((a - b) ** 2 for a, b in zip(dc, pc)))
                    if dist < best_dist:
                        best_dist = dist
                        best_brand = brand
        return best_brand, best_dist
