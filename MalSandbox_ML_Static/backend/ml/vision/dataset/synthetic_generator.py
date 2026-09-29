"""
ml/vision/dataset/synthetic_generator.py
=========================================
Generates synthetic login-page screenshots for bootstrapping the vision
training pipeline, structured to match the real Phish-IRIS dataset layout
(brand subfolders + "other"/legitimate folder) so this code is a drop-in
replacement once the real dataset is available.

This is NOT a substitute for real-world data — it's a pipeline-validation
tool. The model trained on this data learns the STRUCTURE of the training
code (data loading, augmentation, fine-tuning loop, evaluation) using
clean synthetic signal, so swapping in real images later requires zero
code changes — only a different `data_root`.
"""
import os
import random
import string
from pathlib import Path
from typing import List, Tuple

from PIL import Image, ImageDraw, ImageFont


# ── Brand visual profiles (mirrors the real Phish-IRIS class structure) ───────
# Each brand gets a primary/secondary color pair + plausible login copy.
BRAND_PROFILES = {
    "paypal":    {"primary": (0, 48, 135),   "secondary": (255, 255, 255), "title": "PayPal", "cta": "Log In to Your Account"},
    "microsoft": {"primary": (0, 114, 198),  "secondary": (255, 185, 0),   "title": "Microsoft", "cta": "Sign in to your account"},
    "apple":     {"primary": (20, 20, 20),   "secondary": (255, 255, 255), "title": "Apple ID", "cta": "Sign in with your Apple ID"},
    "amazon":    {"primary": (35, 47, 62),   "secondary": (255, 153, 0),   "title": "Amazon", "cta": "Sign in to continue"},
    "facebook":  {"primary": (24, 119, 242), "secondary": (255, 255, 255), "title": "Facebook", "cta": "Log into Facebook"},
    "chase":     {"primary": (0, 39, 100),   "secondary": (0, 120, 200),   "title": "Chase", "cta": "Sign in to Chase Online"},
}

LEGITIMATE_SITES = [
    {"primary": (36, 41, 46),   "secondary": (255, 255, 255), "title": "GitHub", "cta": "Sign in to GitHub"},
    {"primary": (255, 255, 255),"secondary": (66, 133, 244),  "title": "Wikipedia", "cta": "Search Wikipedia"},
    {"primary": (255, 255, 255),"secondary": (0, 0, 0),       "title": "The New York Times", "cta": "Today's Paper"},
    {"primary": (240, 240, 240),"secondary": (50, 50, 50),    "title": "Stack Overflow", "cta": "Ask a Question"},
    {"primary": (255, 255, 255),"secondary": (255, 87, 34),   "title": "Reddit", "cta": "Browse communities"},
]

URGENCY_PHRASES = [
    "Your account has been suspended", "Verify your identity immediately",
    "Unusual activity detected", "Action required within 24 hours",
    "Security Alert: Confirm your details",
]

IMG_SIZE = 224  # matches ResNet/EfficientNet expected input


def _get_font(size: int):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", size)
    except (OSError, IOError):
        return ImageFont.load_default()


def _draw_centered_form(draw: ImageDraw.Draw, profile: dict, is_phishing: bool, w: int, h: int):
    """Draws a login-form-like layout: header bar, centered box, input fields, button."""
    primary = profile["primary"]
    secondary = profile["secondary"]

    # Header bar
    draw.rectangle([0, 0, w, 36], fill=primary)
    font_title = _get_font(14)
    draw.text((12, 8), profile["title"], fill=secondary, font=font_title)

    # Background
    bg_color = (245, 245, 248) if is_phishing else (255, 255, 255)
    draw.rectangle([0, 36, w, h], fill=bg_color)

    # Centered form card
    card_w, card_h = int(w * 0.7), int(h * 0.45)
    cx, cy = w // 2, h // 2 + 10
    card_box = [cx - card_w // 2, cy - card_h // 2, cx + card_w // 2, cy + card_h // 2]
    draw.rectangle(card_box, fill=(255, 255, 255), outline=(200, 200, 200), width=1)

    font_cta = _get_font(11)
    draw.text((card_box[0] + 10, card_box[1] + 10), profile["cta"], fill=(30, 30, 30), font=font_cta)

    # Urgency banner for phishing samples
    if is_phishing and random.random() < 0.6:
        phrase = random.choice(URGENCY_PHRASES)
        draw.rectangle([card_box[0], card_box[1] - 22, card_box[2], card_box[1] - 4], fill=(220, 53, 69))
        font_warn = _get_font(9)
        draw.text((card_box[0] + 6, card_box[1] - 20), phrase, fill=(255, 255, 255), font=font_warn)

    # Input fields
    field_y = card_box[1] + 35
    for label in ["Email or phone", "Password"]:
        draw.rectangle([card_box[0] + 10, field_y, card_box[2] - 10, field_y + 18],
                        fill=(250, 250, 250), outline=(180, 180, 180))
        draw.text((card_box[0] + 14, field_y + 3), label, fill=(150, 150, 150), font=_get_font(8))
        field_y += 26

    # Submit button
    btn_color = primary if not is_phishing else (random.choice([primary, (220, 53, 69)]))
    draw.rectangle([card_box[0] + 10, field_y + 4, card_box[2] - 10, field_y + 26], fill=btn_color)
    draw.text((card_box[0] + 18, field_y + 9), "Submit", fill=(255, 255, 255), font=_get_font(9))

    # Phishing samples get slightly "off" visual noise — imperfect brand mimicry
    if is_phishing:
        # Slightly shifted color tint (typical of cloned/recreated pages)
        noise_overlay = Image.new("RGBA", (w, h), (
            random.randint(0, 30), random.randint(0, 30), random.randint(0, 30), 15
        ))
        return noise_overlay
    return None


def generate_image(profile: dict, is_phishing: bool) -> Image.Image:
    img = Image.new("RGB", (IMG_SIZE, IMG_SIZE), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    overlay = _draw_centered_form(draw, profile, is_phishing, IMG_SIZE, IMG_SIZE)
    if overlay is not None:
        img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")

    # Random jitter to simulate real-world screenshot variance
    if random.random() < 0.3:
        img = img.rotate(random.uniform(-1.5, 1.5), fillcolor=(255, 255, 255))

    return img


def build_dataset(root: str, n_per_brand: int = 60, n_legitimate: int = 200, seed: int = 42):
    """
    Builds a directory structure identical to Phish-IRIS:
        root/train/<brand>/*.png
        root/train/other/*.png
        root/test/<brand>/*.png
        root/test/other/*.png
    """
    random.seed(seed)
    root_path = Path(root)

    classes: List[Tuple[str, dict, bool]] = [
        (name, profile, True) for name, profile in BRAND_PROFILES.items()
    ]

    manifest = []

    for split, n_brand, n_legit in [("train", int(n_per_brand * 0.7), int(n_legitimate * 0.7)),
                                      ("test", int(n_per_brand * 0.3), int(n_legitimate * 0.3))]:
        # Phishing brand classes
        for brand_name, profile, is_phishing in classes:
            out_dir = root_path / split / brand_name
            out_dir.mkdir(parents=True, exist_ok=True)
            for i in range(n_brand):
                img = generate_image(profile, is_phishing=True)
                fname = f"{brand_name}_{i:04d}.png"
                img.save(out_dir / fname)
                manifest.append({"path": str(out_dir / fname), "label": brand_name, "is_phishing": 1})

        # Legitimate ("other") class
        out_dir = root_path / split / "other"
        out_dir.mkdir(parents=True, exist_ok=True)
        for i in range(n_legit):
            site = random.choice(LEGITIMATE_SITES)
            img = generate_image(site, is_phishing=False)
            fname = f"legit_{i:04d}.png"
            img.save(out_dir / fname)
            manifest.append({"path": str(out_dir / fname), "label": "other", "is_phishing": 0})

    return manifest


if __name__ == "__main__":
    import json

    out_root = os.environ.get("DATASET_ROOT", "/home/claude/sandbox-ml/backend/ml/vision/dataset/synthetic")
    manifest = build_dataset(out_root, n_per_brand=60, n_legitimate=200)

    with open(Path(out_root) / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    n_train = sum(1 for m in manifest if "/train/" in m["path"])
    n_test = sum(1 for m in manifest if "/test/" in m["path"])
    print(f"Generated {len(manifest)} images → {out_root}")
    print(f"  train: {n_train}  test: {n_test}")
    print(f"  classes: {list(BRAND_PROFILES.keys()) + ['other']}")
