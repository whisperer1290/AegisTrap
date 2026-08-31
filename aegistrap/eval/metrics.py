"""Small metric helpers used by the Section 9 evaluation harness."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from typing import Any


def set_f1(predicted: Iterable[str], truth: Iterable[str]) -> dict[str, float]:
    """Precision, recall, and F1 of a predicted identifier set against truth."""
    pred = {x for x in predicted if x}
    gold = {x for x in truth if x}
    tp = len(pred & gold)
    fp = len(pred - gold)
    fn = len(gold - pred)
    precision = tp / (tp + fp) if (tp + fp) else 1.0 if not gold else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0 if not pred else 0.0
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positives": float(tp),
        "false_positives": float(fp),
        "false_negatives": float(fn),
    }


def classification_report(
    pairs: Sequence[tuple[str, str]],
    labels: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Per-class precision/recall plus a confusion matrix.

    ``pairs`` is ``(truth, predicted)``.
    """
    if labels is None:
        labels = sorted({t for t, _ in pairs} | {p for _, p in pairs})
    label_set = list(labels)
    matrix = {truth: dict.fromkeys(label_set, 0) for truth in label_set}
    for truth, predicted in pairs:
        if truth not in matrix:
            matrix[truth] = dict.fromkeys(label_set, 0)
        if predicted not in matrix[truth]:
            for row in matrix.values():
                row[predicted] = 0
            label_set.append(predicted)
        matrix[truth][predicted] = matrix[truth].get(predicted, 0) + 1

    totals = Counter(t for t, _ in pairs)
    predicted_totals = Counter(p for _, p in pairs)
    per_class: dict[str, dict[str, float]] = {}
    correct = 0
    for label in label_set:
        tp = matrix.get(label, {}).get(label, 0)
        support = totals.get(label, 0)
        pred_n = predicted_totals.get(label, 0)
        precision = tp / pred_n if pred_n else 0.0
        recall = tp / support if support else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        per_class[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": float(support),
        }
        correct += tp

    n = len(pairs)
    return {
        "accuracy": round(correct / n, 4) if n else 0.0,
        "n": n,
        "per_class": per_class,
        "confusion": matrix,
    }


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * (p / 100.0)
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    frac = rank - lo
    return float(ordered[lo] * (1 - frac) + ordered[hi] * frac)
