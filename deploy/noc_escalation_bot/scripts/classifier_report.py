"""Phase 3 shadow-eval — run classify() on labeled posts, compute metrics,
apply gate, emit markdown + CSV.

Usage:
    python deploy/noc_escalation_bot/scripts/classifier_report.py \\
        --in shadow_eval_out/labeled_posts_2026-04-23.csv \\
        --out-csv shadow_eval_out/eval_results_2026-04-23.csv \\
        --out-md shadow_eval_out/eval_report_2026-04-23.md
"""
from __future__ import annotations

import argparse
import csv
import logging
import os
import sys
import time
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

# Classes appearing in ground truth
GROUND_TRUTH_CLASSES = ["incident", "change_with_cr", "change_no_cr", "fyi"]
# Classes the classifier can actually emit (Phase 4b: fyi added)
CLASSIFIER_CLASSES = ["incident", "change_with_cr", "change_no_cr", "fyi"]


def confusion_matrix(rows: list[dict]) -> dict[str, dict[str, int]]:
    """Build cm[truth][verdict] = count. Initializes all cells to 0 so
    downstream code can index safely."""
    cm = {t: {v: 0 for v in CLASSIFIER_CLASSES} for t in GROUND_TRUTH_CLASSES}
    for row in rows:
        t = row.get("heuristic_label")
        v = row.get("classifier_verdict")
        if t in cm and v in cm[t]:
            cm[t][v] += 1
    return cm


def per_class_metrics(
    cm: dict[str, dict[str, int]], cls: str,
) -> tuple[float, float, float]:
    """Return (precision, recall, f1) for class `cls`. Degenerate cases
    (no predictions, no positives) return 0.0 for the affected metric."""
    tp = cm.get(cls, {}).get(cls, 0)
    fp = sum(
        cm.get(other_truth, {}).get(cls, 0)
        for other_truth in GROUND_TRUTH_CLASSES
        if other_truth != cls
    )
    fn = sum(
        cm.get(cls, {}).get(other_verdict, 0)
        for other_verdict in CLASSIFIER_CLASSES
        if other_verdict != cls
    )
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return (precision, recall, f1)


def classify_error_type(truth: str, verdict: str) -> str:
    """Return the canonical error_type column value for a row."""
    if truth == verdict:
        return ""
    if truth == "fyi":
        return "fyi_misroute"
    # Classify by verdict first (FP errors), then by truth (FN errors).
    if verdict == "incident" and truth != "incident":
        return "fp_incident"
    if verdict == "change_with_cr" and truth != "change_with_cr":
        return "fp_change_with_cr"
    if truth == "incident" and verdict != "incident":
        return "fn_incident"
    if truth == "change_with_cr" and verdict != "change_with_cr":
        return "fn_change_with_cr"
    # All 4x3 truth/verdict combinations are covered above; this fallback
    # only fires for unexpected verdict strings (e.g., classifier returned
    # an empty string after an exception).
    return "other"


from dataclasses import dataclass, field

GATE = {
    "min_total": 200,
    "min_incident_count": 15,
    "min_change_with_cr_count": 15,
    "min_fyi_count": 15,
    "min_precision_incident": 0.90,
    "min_recall_incident": 0.80,
    "min_precision_change_with_cr": 0.90,
    "min_precision_fyi": 0.90,
}


@dataclass
class GateResult:
    passed: bool
    reason: str  # "pass" | "insufficient_data" | "metric_threshold"
    conditions: list[tuple[str, bool, str]] = field(default_factory=list)


def _total_in_class(cm: dict, cls: str) -> int:
    return sum(cm.get(cls, {}).values())


def apply_gate(cm: dict[str, dict[str, int]]) -> GateResult:
    """Apply the Phase 4b gate. Returns GateResult with per-condition breakdown."""
    total = sum(_total_in_class(cm, t) for t in GROUND_TRUTH_CLASSES)
    n_incident = _total_in_class(cm, "incident")
    n_cr = _total_in_class(cm, "change_with_cr")
    n_fyi = _total_in_class(cm, "fyi")

    p_inc, r_inc, _ = per_class_metrics(cm, "incident")
    p_cr, _, _ = per_class_metrics(cm, "change_with_cr")
    p_fyi, _, _ = per_class_metrics(cm, "fyi")

    conds = [
        (f"total_labeled >= {GATE['min_total']}",
         total >= GATE["min_total"], str(total)),
        (f"count(incident) >= {GATE['min_incident_count']}",
         n_incident >= GATE["min_incident_count"], str(n_incident)),
        (f"count(change_with_cr) >= {GATE['min_change_with_cr_count']}",
         n_cr >= GATE["min_change_with_cr_count"], str(n_cr)),
        (f"count(fyi) >= {GATE['min_fyi_count']}",
         n_fyi >= GATE["min_fyi_count"], str(n_fyi)),
        (f"precision(incident) >= {GATE['min_precision_incident']:.2f}",
         p_inc >= GATE["min_precision_incident"], f"{p_inc:.3f}"),
        (f"recall(incident) >= {GATE['min_recall_incident']:.2f}",
         r_inc >= GATE["min_recall_incident"], f"{r_inc:.3f}"),
        (f"precision(change_with_cr) >= {GATE['min_precision_change_with_cr']:.2f}",
         p_cr >= GATE["min_precision_change_with_cr"], f"{p_cr:.3f}"),
        (f"precision(fyi) >= {GATE['min_precision_fyi']:.2f}",
         p_fyi >= GATE["min_precision_fyi"], f"{p_fyi:.3f}"),
    ]

    # First 4 conditions are sample-size, remaining 4 are metric thresholds.
    sample_ok = all(ok for _, ok, _ in conds[:4])
    metric_ok = all(ok for _, ok, _ in conds[4:])

    if not sample_ok:
        return GateResult(passed=False, reason="insufficient_data", conditions=conds)
    if not metric_ok:
        return GateResult(passed=False, reason="metric_threshold", conditions=conds)
    return GateResult(passed=True, reason="pass", conditions=conds)


def render_markdown(
    *,
    cm: dict[str, dict[str, int]],
    gate_result: GateResult,
    fallback_rate: float,
    failure_cases: list[dict],
    model: str,
    rows_total: int,
) -> str:
    """Render the eval report as markdown."""
    lines: list[str] = []
    lines.append("# Escalation Classifier Shadow Eval")
    lines.append("")
    lines.append(f"- **Model:** `{model}`")
    lines.append(f"- **Rows evaluated:** {rows_total}")
    lines.append(f"- **Fallback rate:** {fallback_rate:.1%} (reported only; not gated)")
    status_str = "PASS" if gate_result.passed else f"FAIL ({gate_result.reason})"
    lines.append(f"- **Overall:** **{status_str}**")
    lines.append("")

    # Gate conditions
    lines.append("## Gate Conditions")
    lines.append("")
    lines.append("| Condition | Actual | Result |")
    lines.append("|---|---|---|")
    for label, ok, actual in gate_result.conditions:
        mark = "PASS" if ok else "FAIL"
        lines.append(f"| {label} | {actual} | {mark} |")
    lines.append("")

    # Confusion matrix
    lines.append("## Confusion Matrix")
    lines.append("")
    header = "| truth \\ verdict | " + " | ".join(CLASSIFIER_CLASSES) + " |"
    sep = "|" + "---|" * (len(CLASSIFIER_CLASSES) + 1)
    lines.append(header)
    lines.append(sep)
    for t in GROUND_TRUTH_CLASSES:
        row = [t] + [str(cm.get(t, {}).get(v, 0)) for v in CLASSIFIER_CLASSES]
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")

    # Per-class metrics
    lines.append("## Per-Class Metrics")
    lines.append("")
    lines.append("| Class | Precision | Recall | F1 |")
    lines.append("|---|---|---|---|")
    for cls in CLASSIFIER_CLASSES:
        p, r, f = per_class_metrics(cm, cls)
        lines.append(f"| {cls} | {p:.3f} | {r:.3f} | {f:.3f} |")
    lines.append("")

    # Failure cases
    lines.append("## Failure Cases (top 20 by error_type)")
    lines.append("")
    if not failure_cases:
        lines.append("_(no errors in sample, or failure list truncated)_")
    else:
        lines.append("| error_type | truth | verdict | permalink | text |")
        lines.append("|---|---|---|---|---|")
        for fc in failure_cases[:20]:
            # Escape pipes and collapse newlines so multi-line Slack posts
            # don't break the markdown table row.
            text_preview = (
                (fc.get("text") or "")
                .replace("|", "\\|")
                .replace("\r\n", " ")
                .replace("\n", " ")
                .replace("\r", " ")
            )[:100]
            lines.append(
                f"| {fc.get('error_type', '')} | {fc.get('heuristic_label', '')} | "
                f"{fc.get('classifier_verdict', '')} | {fc.get('permalink', '')} | "
                f"{text_preview} |")
    lines.append("")
    return "\n".join(lines)


def evaluate_rows(
    rows: list[dict],
    classify_fn: Callable[[dict], tuple[str, bool, int]],
) -> tuple[list[dict], dict, float, list[dict]]:
    """For each row call classify_fn(row) -> (verdict, is_fallback, latency_ms).

    Returns (enriched_rows, confusion_matrix, fallback_rate, failure_cases).
    Failure cases are rows where match=false, sorted by severity:
    fp_incident first, then fn_incident, then others.
    """
    enriched: list[dict] = []
    fallback_hits = 0
    for row in rows:
        try:
            verdict, is_fb, latency_ms = classify_fn(row)
            err = "fallback" if is_fb else ""
        except Exception as e:
            verdict = ""
            is_fb = False
            latency_ms = 0
            err = f"exception:{e}"
        if is_fb:
            fallback_hits += 1
        truth = row.get("heuristic_label", "")
        match_bool = (verdict == truth)
        row_out = dict(row)
        row_out["classifier_verdict"] = verdict
        row_out["classifier_latency_ms"] = str(latency_ms)
        row_out["classifier_error"] = err
        row_out["match"] = "true" if match_bool else "false"
        row_out["error_type"] = classify_error_type(truth, verdict)
        enriched.append(row_out)

    cm = confusion_matrix(enriched)
    total = len(enriched) or 1
    fallback_rate = fallback_hits / total

    # Sort failure cases by priority
    priority = {"fp_incident": 0, "fn_incident": 1, "fyi_misroute": 2,
                "fp_change_with_cr": 3, "fn_change_with_cr": 4, "other": 5}
    failures = [r for r in enriched if r["match"] == "false"]
    failures.sort(key=lambda r: priority.get(r.get("error_type", ""), 99))

    return enriched, cm, fallback_rate, failures


def _read_prod_ollama_model() -> str:
    """Read escalation_classifier_ollama_model from the same path prod uses.

    api.py exposes get_config() which returns the merged config. Fall back
    to env OLLAMA_MODEL if api.py cannot be loaded (e.g. running the script
    outside /app on a dev laptop)."""
    try:
        from api import get_config  # type: ignore[attr-defined]
        cfg = get_config()
        model = cfg.get("escalation_classifier_ollama_model") or ""
        if model:
            return model
    except Exception as e:
        logger.warning("could not read escalation_classifier_ollama_model "
                       "from api.get_config: %s", e)
    return os.environ.get("OLLAMA_MODEL", "qwen2.5:32b")


class _FallbackSniffer(logging.Handler):
    """Watches the escalation_classifier logger for fallback log lines
    during a classify() call. One sniffer per call; reset via .saw."""

    def __init__(self) -> None:
        super().__init__()
        self.saw = False

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if "fallback reason=" in record.getMessage():
                self.saw = True
        except Exception:  # defensive: never let a log handler crash classify
            pass


def _call_classify_with_fallback_detection(
    *,
    classify_callable: Callable,
    ec_logger: logging.Logger,
    text: str,
    cr_data,
    ollama_url: str,
    ollama_model: str,
) -> tuple[str, bool, int]:
    """Invoke escalation_classifier.classify with a temporary log handler
    attached so we can distinguish genuine verdicts from fallback verdicts.

    Returns (verdict_value, is_fallback, latency_ms).
    """
    sniffer = _FallbackSniffer()
    ec_logger.addHandler(sniffer)
    try:
        start = time.monotonic()
        verdict = classify_callable(
            text=text, cr_data=cr_data,
            ollama_url=ollama_url, ollama_model=ollama_model,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
    finally:
        ec_logger.removeHandler(sniffer)
    return (verdict.value, sniffer.saw, elapsed_ms)


def _build_classifier(ollama_url: str, ollama_model: str):
    """Factory returning classify_fn(row) -> (verdict, is_fallback, latency_ms).

    Wires two prod dependencies to match what ``bot.py`` would do at a real
    mention:

    * **Jira CR lookup** — for every ``CR-###`` in ``linked_tickets`` we call
      ``JiraCRClient.fetch_cr`` to confirm the CR exists and fetch its
      real summary. Only if Jira confirms the CR do we pass a ``CRRef`` to
      ``classify``. This matches prod: ``bot.py`` only hands a CRRef to the
      classifier when the CR is real. A phantom / stale CR-### in text is
      treated as having no CR context.
    * **Fallback detection** — ``escalation_classifier.classify`` returns a
      Verdict on every path (including error fallback) and logs
      ``"fallback reason=..."`` when it fell back. We attach a temporary log
      handler per call so the ``fallback_rate`` in the final report
      reflects reality instead of always being 0%.

    If ``JIRA_BASE_URL`` is unset, CR lookups are disabled and every row is
    classified with ``cr_data=None`` — the factory logs a warning so the
    operator knows the eval is running degraded.
    """
    from escalation_classifier import classify, CRRef
    from escalation_classifier import logger as ec_logger

    base_url = os.environ.get("JIRA_BASE_URL")
    if base_url:
        from jira_cr import JiraCRClient
        jira_client = JiraCRClient(
            base_url=base_url,
            email=os.environ.get("JIRA_EMAIL", ""),
            api_token=os.environ.get("JIRA_API_TOKEN", ""),
        )
    else:
        jira_client = None
        logger.warning(
            "JIRA_BASE_URL not set; CR lookups disabled. Rows will be "
            "classified without CR context, which may skew change_with_cr "
            "recall versus prod behavior."
        )

    def _lookup_cr(key: str):
        if jira_client is None:
            return None
        try:
            return jira_client.fetch_cr(key)
        except Exception as e:
            logger.warning("jira fetch_cr(%s) error: %s", key, e)
            return None

    def classify_fn(row):
        text = row.get("text", "")
        tickets = [
            t for t in (row.get("linked_tickets") or "").split(",")
            if t.startswith("CR-")
        ]
        cr_data = None
        for key in tickets:
            data = _lookup_cr(key)
            if data is not None:
                cr_data = CRRef(
                    key=getattr(data, "key", key),
                    summary=getattr(data, "summary", "") or "",
                )
                break
        return _call_classify_with_fallback_detection(
            classify_callable=classify,
            ec_logger=ec_logger,
            text=text,
            cr_data=cr_data,
            ollama_url=ollama_url,
            ollama_model=ollama_model,
        )

    return classify_fn


def _write_results_csv(path: str, rows: list[dict]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        Path(path).write_text("")
        return
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run classifier on labeled corpus, emit report.")
    p.add_argument("--in", dest="in_path", required=True)
    p.add_argument("--out-csv", dest="out_csv", required=True)
    p.add_argument("--out-md", dest="out_md", required=True)
    p.add_argument("--ollama-url", default=os.environ.get("OLLAMA_URL", "http://ollama:11434"))
    p.add_argument("--ollama-model", default=None,
                   help="override; default = api.py prod config")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    # Make bot module imports work
    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".."))

    model = args.ollama_model or _read_prod_ollama_model()
    logger.info("using ollama model: %s", model)

    with open(args.in_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    classify_fn = _build_classifier(args.ollama_url, model)
    enriched, cm, fallback_rate, failures = evaluate_rows(rows, classify_fn)

    _write_results_csv(args.out_csv, enriched)

    gate_result = apply_gate(cm)
    md = render_markdown(
        cm=cm, gate_result=gate_result, fallback_rate=fallback_rate,
        failure_cases=failures, model=model, rows_total=len(enriched),
    )
    Path(args.out_md).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_md).write_text(md, encoding="utf-8")

    logger.info("wrote %d rows to %s", len(enriched), args.out_csv)
    logger.info("wrote report to %s: %s",
                args.out_md,
                "PASS" if gate_result.passed else f"FAIL ({gate_result.reason})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
