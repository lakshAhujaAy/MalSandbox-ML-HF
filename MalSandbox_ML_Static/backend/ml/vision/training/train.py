"""
ml/vision/training/train.py
=============================
Fine-tunes a ResNet18 (pretrained on ImageNet) for phishing brand
classification. Designed to run on CPU and to be dataset-agnostic —
point `--data-root` at either the synthetic dataset or a real
Phish-IRIS-structured directory and nothing else changes.

Usage:
    python train.py --data-root ../dataset/synthetic --epochs 8
"""
import argparse
import json
import time
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from torchvision import datasets, transforms, models


def build_dataloaders(data_root: str, batch_size: int = 16, img_size: int = 224):
    """
    Expects ImageFolder-compatible structure:
        data_root/train/<class_name>/*.png
        data_root/test/<class_name>/*.png
    This is exactly the structure of Phish-IRIS, so swapping datasets
    requires only changing --data-root.
    """
    train_tf = transforms.Compose([
        transforms.Resize((img_size, img_size)),
        transforms.RandomHorizontalFlip(p=0.2),
        transforms.RandomRotation(5),
        transforms.ColorJitter(brightness=0.15, contrast=0.15),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),  # ImageNet stats
    ])
    eval_tf = transforms.Compose([
        transforms.Resize((img_size, img_size)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])

    train_ds = datasets.ImageFolder(Path(data_root) / "train", transform=train_tf)
    test_ds = datasets.ImageFolder(Path(data_root) / "test", transform=eval_tf)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=0)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False, num_workers=0)

    return train_loader, test_loader, train_ds.classes


def build_model(n_classes: int, freeze_backbone: bool = True, pretrained: bool = True):
    """
    ResNet18, optionally pretrained on ImageNet, fine-tuned head.
    Chosen over ResNet50/EfficientNet for CPU feasibility — ~11M params
    vs ~25M+, while still benefiting from transfer learning when weights
    are available.

    Falls back to random initialization if pretrained weights can't be
    downloaded (e.g. offline/restricted-network training environment).
    In that case `freeze_backbone` is forced off, since freezing random
    weights would prevent the model from learning anything useful.
    """
    if pretrained:
        try:
            model = models.resnet18(weights=models.ResNet18_Weights.IMAGENET1K_V1)
        except Exception as e:
            print(f"[warn] Could not download pretrained weights ({e}). "
                  f"Falling back to random initialization — backbone will NOT be frozen.")
            model = models.resnet18(weights=None)
            freeze_backbone = False
    else:
        model = models.resnet18(weights=None)
        freeze_backbone = False

    if freeze_backbone:
        for param in model.parameters():
            param.requires_grad = False

    # Replace the final FC layer for our class count
    in_features = model.fc.in_features
    model.fc = nn.Linear(in_features, n_classes)  # only this layer trains initially if frozen

    return model, freeze_backbone


def evaluate(model, loader, device, criterion):
    model.eval()
    total, correct, loss_sum = 0, 0, 0.0
    all_preds, all_labels = [], []

    with torch.no_grad():
        for images, labels in loader:
            images, labels = images.to(device), labels.to(device)
            outputs = model(images)
            loss = criterion(outputs, labels)
            loss_sum += loss.item() * images.size(0)

            _, preds = torch.max(outputs, 1)
            correct += (preds == labels).sum().item()
            total += labels.size(0)

            all_preds.extend(preds.cpu().tolist())
            all_labels.extend(labels.cpu().tolist())

    return {
        "loss": loss_sum / total,
        "accuracy": correct / total,
        "preds": all_preds,
        "labels": all_labels,
    }


def confusion_matrix(preds, labels, n_classes):
    cm = [[0] * n_classes for _ in range(n_classes)]
    for p, l in zip(preds, labels):
        cm[l][p] += 1
    return cm


def per_class_metrics(preds, labels, classes):
    """Precision/recall/F1 per class — critical for imbalanced phishing data."""
    metrics = {}
    for idx, cls in enumerate(classes):
        tp = sum(1 for p, l in zip(preds, labels) if p == idx and l == idx)
        fp = sum(1 for p, l in zip(preds, labels) if p == idx and l != idx)
        fn = sum(1 for p, l in zip(preds, labels) if p != idx and l == idx)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        metrics[cls] = {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)}
    return metrics


def train(args):
    device = torch.device("cpu")  # explicit — no GPU in this environment
    print(f"Device: {device}")

    train_loader, test_loader, classes = build_dataloaders(args.data_root, args.batch_size)
    n_classes = len(classes)
    print(f"Classes ({n_classes}): {classes}")
    print(f"Train samples: {len(train_loader.dataset)}  Test samples: {len(test_loader.dataset)}")

    model, backbone_frozen = build_model(n_classes, freeze_backbone=True, pretrained=args.pretrained)
    model = model.to(device)
    criterion = nn.CrossEntropyLoss()

    # Phase 1: train only the head if backbone is frozen (transfer learning case).
    # If training from scratch (no pretrained weights available), train everything
    # from epoch 0 — freezing random weights would prevent any learning.
    if backbone_frozen:
        optimizer = torch.optim.Adam(model.fc.parameters(), lr=args.lr)
        print("Mode: transfer learning (frozen backbone → fine-tune head, then unfreeze)")
    else:
        optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
        print("Mode: training from scratch (random init, full network trainable from epoch 0)")

    history = {"train_loss": [], "train_acc": [], "val_loss": [], "val_acc": []}

    for epoch in range(args.epochs):
        # Unfreeze backbone halfway through for fine-tuning (Phase 2) — only relevant
        # in the transfer-learning case; no-op if already fully trainable.
        if backbone_frozen and epoch == args.epochs // 2:
            print(f"\n[Epoch {epoch}] Unfreezing backbone for fine-tuning…")
            for param in model.parameters():
                param.requires_grad = True
            optimizer = torch.optim.Adam(model.parameters(), lr=args.lr * 0.1)

        model.train()
        start = time.time()
        running_loss, correct, total = 0.0, 0, 0

        for images, labels in train_loader:
            images, labels = images.to(device), labels.to(device)

            optimizer.zero_grad()
            outputs = model(images)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()

            running_loss += loss.item() * images.size(0)
            _, preds = torch.max(outputs, 1)
            correct += (preds == labels).sum().item()
            total += labels.size(0)

        train_loss = running_loss / total
        train_acc = correct / total

        val_result = evaluate(model, test_loader, device, criterion)
        elapsed = time.time() - start

        history["train_loss"].append(train_loss)
        history["train_acc"].append(train_acc)
        history["val_loss"].append(val_result["loss"])
        history["val_acc"].append(val_result["accuracy"])

        print(f"Epoch {epoch+1}/{args.epochs} "
              f"train_loss={train_loss:.4f} train_acc={train_acc:.3f} "
              f"val_loss={val_result['loss']:.4f} val_acc={val_result['accuracy']:.3f} "
              f"({elapsed:.1f}s)")

    # Final evaluation with full metrics
    final = evaluate(model, test_loader, device, criterion)
    cm = confusion_matrix(final["preds"], final["labels"], n_classes)
    pc_metrics = per_class_metrics(final["preds"], final["labels"], classes)

    print("\n=== Final Test Results ===")
    print(f"Accuracy: {final['accuracy']:.3f}")
    print("\nPer-class metrics:")
    for cls, m in pc_metrics.items():
        print(f"  {cls:12s} precision={m['precision']:.2f}  recall={m['recall']:.2f}  f1={m['f1']:.2f}")

    # Save model + training report
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    torch.save({
        "model_state_dict": model.state_dict(),
        "classes": classes,
        "img_size": 224,
    }, out_dir / "phishing_resnet18.pt")

    report = {
        "classes": classes,
        "n_train": len(train_loader.dataset),
        "n_test": len(test_loader.dataset),
        "epochs": args.epochs,
        "training_mode": "transfer_learning" if backbone_frozen else "from_scratch",
        "final_accuracy": final["accuracy"],
        "history": history,
        "confusion_matrix": cm,
        "per_class_metrics": pc_metrics,
    }
    with open(out_dir / "training_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nModel saved → {out_dir / 'phishing_resnet18.pt'}")
    print(f"Report saved → {out_dir / 'training_report.json'}")

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", required=True, help="Dataset root with train/ and test/ subdirs")
    parser.add_argument("--output-dir", default="../models", help="Where to save model + report")
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--pretrained", action="store_true", default=True,
                         help="Attempt to use ImageNet-pretrained weights (falls back to random init if unreachable)")
    parser.add_argument("--no-pretrained", dest="pretrained", action="store_false",
                         help="Force random initialization (no transfer learning)")
    args = parser.parse_args()

    train(args)
