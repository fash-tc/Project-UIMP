"""P3 classifier smoke test — one-off, not wired into the bot.

Pulls the last N top-level messages from #ops-noc and runs each through
escalation_classifier.classify() to eyeball how the existing prompt
would behave on untagged posts.

Run inside the noc bot container:
    docker exec -it uip-noc-escalation-bot-1 python /app/scripts/p3_smoke.py 50

Extended flags:
    --n N           number of posts to fetch (default 50)
    --p3            use classify_p3 instead of the three-way classify
    --labeled PATH  TSV corpus: ts<TAB>label<TAB>text; skips Slack fetch,
                    runs classify_p3 and reports confusion matrix / precision / recall
"""
from __future__ import annotations

import os
import re
import sys

# Allow running as `python scripts/p3_smoke.py` from /app — the bot
# modules live in /app, not /app/scripts, so prepend /app to sys.path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from slack_sdk import WebClient
from escalation_classifier import classify, Verdict
from jira_cr import JiraCRClient


MENTION_RE = re.compile(r"<!subteam\^[A-Z0-9]+>")  # any @subteam mention
CR_RE = re.compile(r"\bCR-(\d+)\b")


def fetch_until(slack: WebClient, channel: str, want: int) -> list[dict]:
    """Page through channel history until we have `want` top-level human posts."""
    out: list[dict] = []
    cursor = None
    scanned = 0
    while len(out) < want and scanned < 3000:
        resp = slack.conversations_history(
            channel=channel, limit=200, cursor=cursor,
        )
        page = resp.get("messages", [])
        scanned += len(page)
        for m in page:
            if m.get("bot_id") or m.get("subtype") or m.get("thread_ts"):
                continue
            out.append(m)
            if len(out) >= want:
                break
        cursor = (resp.get("response_metadata") or {}).get("next_cursor") or ""
        if not cursor:
            break
    print(f"Scanned {scanned} raw messages to collect {len(out)} human top-level posts")
    return out


def _run_labeled(path: str, ollama_url: str, ollama_model: str) -> None:
    """Score classify_p3 against a labeled TSV corpus.

    Corpus format (one post per line):
        <ts>\\t<incident|not_incident>\\t<text>

    Reports confusion matrix + precision + recall. Acceptance gate
    (spec §'Acceptance gate before live'): precision >= 0.90 AND
    recall >= 0.70 on >= 200 rows with >= 15 true-positives.
    """
    from escalation_classifier import classify_p3, P3Verdict

    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t", 2)
            if len(parts) != 3:
                continue
            ts, label, text = parts
            if label not in ("incident", "not_incident"):
                continue
            rows.append((ts, label, text))

    if not rows:
        print(f"No valid rows in {path}")
        return

    tp = fp = tn = fn = 0
    for i, (ts, label, text) in enumerate(rows, 1):
        v = classify_p3(text=text,
                        ollama_url=ollama_url, ollama_model=ollama_model)
        pred = v.value  # "incident" | "not_incident"
        correct = "✔" if pred == label else "✘"
        if label == "incident" and pred == "incident":
            tp += 1
        elif label == "not_incident" and pred == "incident":
            fp += 1
        elif label == "not_incident" and pred == "not_incident":
            tn += 1
        else:
            fn += 1
        first = text.replace("\n", " ")[:80]
        print(f"{correct} [{i:03d}] gt={label:13s} pred={pred:13s} | {first}")

    total = tp + fp + tn + fn
    gt_positives = tp + fn  # ground-truth incidents in corpus
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / gt_positives if gt_positives else 0.0
    print("=" * 72)
    print(f"N                   {total}")
    print(f"Ground-truth TPs    {gt_positives}   (gate: >= 15)")
    print(f"Model true pos      {tp}")
    print(f"False positives     {fp}")
    print(f"True negatives      {tn}")
    print(f"False negatives     {fn}")
    print(f"Precision           {precision:.3f}  (gate: >= 0.90)")
    print(f"Recall              {recall:.3f}  (gate: >= 0.70)")
    gate_ok = (total >= 200 and gt_positives >= 15
               and precision >= 0.90 and recall >= 0.70)
    print(f"Acceptance gate     {'PASS' if gate_ok else 'FAIL'}")


def main(argv: list[str]) -> None:
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=50,
                   help="posts to fetch when no --labeled corpus is given")
    p.add_argument("--p3", action="store_true",
                   help="use classify_p3 instead of the three-way classify")
    p.add_argument("--labeled", default="",
                   help="path to a TSV corpus: ts<TAB>label<TAB>text "
                        "where label is 'incident' or 'not_incident'. "
                        "When set, skips Slack fetch and runs classify_p3 "
                        "against every row. Required for precision/recall.")
    args = p.parse_args(argv)

    ollama_url = os.environ["OLLAMA_URL"]
    ollama_model = os.environ["OLLAMA_MODEL"]

    if args.labeled:
        _run_labeled(args.labeled, ollama_url, ollama_model)
        return

    token = os.environ["SLACK_BOT_TOKEN"]
    channel = os.environ["OPS_NOC_CHANNEL_ID"]
    slack = WebClient(token=token)
    msgs = fetch_until(slack, channel, args.n)
    untagged = [m for m in msgs if not MENTION_RE.search(m.get("text", ""))]
    print(f"{len(msgs)} human top-level, {len(untagged)} untagged")

    if args.p3:
        from escalation_classifier import classify_p3, P3Verdict
        counts = {v: 0 for v in P3Verdict}
        for i, m in enumerate(untagged, 1):
            text = m.get("text", "")
            v = classify_p3(text=text,
                            ollama_url=ollama_url, ollama_model=ollama_model)
            counts[v] += 1
            marker = "🚨" if v == P3Verdict.INCIDENT else "  "
            first = text.replace("\n", " ")[:100]
            print(f"{marker} [{i:02d}] {v.value:14s} | {first}")
        print("=" * 72)
        print("Verdict summary:")
        for v, n in counts.items():
            print(f"  {v.value:14s} {n}")
        return

    # Else: existing three-way classifier run
    jira = JiraCRClient(
        base_url=os.environ.get("JIRA_BASE_URL", ""),
        email=os.environ.get("JIRA_EMAIL", ""),
        api_token=os.environ.get("JIRA_API_TOKEN", ""),
    ) if os.environ.get("JIRA_BASE_URL") else None

    tagged = [m for m in msgs if MENTION_RE.search(m.get("text", ""))]

    print(f"{len(tagged)} tagged, {len(untagged)} untagged")
    print("=" * 72)

    # Only classify the untagged ones — that's the P3 candidate set
    verdict_counts = {v: 0 for v in Verdict}
    for i, m in enumerate(untagged, 1):
        text = m.get("text", "")
        cr_data = None
        cr_match = CR_RE.search(text)
        if cr_match and jira is not None:
            try:
                cr_data = jira.fetch_cr(f"CR-{cr_match.group(1)}")
            except Exception as e:
                print(f"  (cr fetch failed: {e})")
        verdict = classify(
            text=text, cr_data=cr_data,
            ollama_url=ollama_url, ollama_model=ollama_model,
        )
        verdict_counts[verdict] += 1
        marker = "🚨" if verdict == Verdict.INCIDENT else "  "
        cr_flag = f"+CR" if cr_data else "   "
        first_line = text.replace("\n", " ")[:100]
        print(f"{marker} [{i:02d}] {verdict.value:14s} {cr_flag} | {first_line}")

    print("=" * 72)
    print("Verdict summary:")
    for v, n in verdict_counts.items():
        print(f"  {v.value:14s} {n}")


if __name__ == "__main__":
    main(sys.argv[1:])
