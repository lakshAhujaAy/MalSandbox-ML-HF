"""
ml/vision/training/predict.py
================================
Loads the trained checkpoint and runs inference on a single image.
Used to verify the saved model actually works end-to-end, and as the
template for wiring the trained model into VisionAnalyzer.analyze().
"""
import argparse
import torch
import torch.nn.functional as F
from torchvision import transforms, models
import torch.nn as nn
from PIL import Image


def load_model(checkpoint_path: str):
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    classes = checkpoint["classes"]
    img_size = checkpoint["img_size"]

    model = models.resnet18(weights=None)
    model.fc = nn.Linear(model.fc.in_features, len(classes))
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    return model, classes, img_size


def predict(model, classes, img_size, image_path: str):
    tf = transforms.Compose([
        transforms.Resize((img_size, img_size)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])

    img = Image.open(image_path).convert("RGB")
    tensor = tf(img).unsqueeze(0)

    with torch.no_grad():
        logits = model(tensor)
        probs = F.softmax(logits, dim=1)[0]

    ranked = sorted(zip(classes, probs.tolist()), key=lambda x: -x[1])
    return ranked


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", default="../models/phishing_resnet18.pt")
    parser.add_argument("--image", required=True)
    args = parser.parse_args()

    model, classes, img_size = load_model(args.checkpoint)
    ranked = predict(model, classes, img_size, args.image)

    print(f"Image: {args.image}")
    print(f"Classes: {classes}\n")
    for cls, prob in ranked:
        bar = "█" * int(prob * 30)
        print(f"  {cls:12s} {prob*100:5.1f}%  {bar}")
