"""Section 9 evaluation harness: profiling accuracy, report tags, consistency."""

from aegistrap.eval.harness import EvaluationResult, run_evaluation
from aegistrap.eval.metrics import classification_report, set_f1

__all__ = ["EvaluationResult", "classification_report", "run_evaluation", "set_f1"]
