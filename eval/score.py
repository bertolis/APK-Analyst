#!/usr/bin/env python3
"""Step 5 eval — scorer (LLM-as-judge).

Reads eval/results/baseline.json (from run_baseline.py) and ground_truth.yaml,
then for each app asks a cheap judge model whether each graded `must_find` issue
is COVERED by any of the agent's findings. Discovery bar, not exploitation.

Findings that map to no graded issue are listed as `unlabeled` for human
adjudication (real secondary issue vs. false positive) — never auto-scored.

    python3 eval/score.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List

import yaml
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from apk_analyst.ai.analyst import load_client   # noqa: E402

JUDGE_MODEL = "claude-haiku-4-5"


class Coverage(BaseModel):
    must_find_id: str
    covered: bool = Field(description="True if some agent finding clearly addresses this graded issue.")
    finding_index: int = Field(description="Index of the covering finding, or -1 if none.")
    reason: str = Field(description="One sentence: why it's covered or what's missing.")


class Judgement(BaseModel):
    coverage: List[Coverage]
    unlabeled_finding_indexes: List[int] = Field(
        description="Indexes of agent findings that address NONE of the graded issues."
    )


JUDGE_SYSTEM = (
    "You are grading a static Android security agent's output against a known "
    "answer key for a deliberately-vulnerable app. For each graded issue, decide "
    "whether ANY of the agent's findings clearly covers the same vulnerable "
    "surface. Match on substance, not wording — the agent flagging the vulnerable "
    "component/behavior counts as covered even if it says runtime confirmation is "
    "needed and even if severity differs. Be fair but strict: a vague or unrelated "
    "finding does not count."
)


def _judge(client, app_name: str, must_find: list, findings: list) -> Judgement:
    gt_txt = "\n".join(f"- id={m['id']} (OWASP {m['owasp']}): {m['desc'].strip()}"
                       for m in must_find)
    fx = "\n".join(
        f"[{i}] {f['title']} | sev={f['severity']} conf={f['confidence']} | "
        f"{f['owasp_mobile']} | where={f['location']}\n"
        f"     evidence: {f['evidence'][:300]}\n"
        f"     exploit : {f['exploit_path'][:300]}"
        for i, f in enumerate(findings)
    ) or "(no findings)"
    resp = client.messages.parse(
        model=JUDGE_MODEL, max_tokens=2000, system=JUDGE_SYSTEM,
        messages=[{"role": "user", "content": (
            f"App: {app_name}\n\nGRADED ISSUES (answer key):\n{gt_txt}\n\n"
            f"AGENT FINDINGS:\n{fx}\n\nGrade each graded issue."
        )}],
        output_format=Judgement,
    )
    return resp.parsed_output


def main() -> None:
    gt = yaml.safe_load((ROOT / "eval" / "ground_truth.yaml").read_text())["apps"]
    results_path = ROOT / "eval" / "results" / "baseline.json"
    if not results_path.exists():
        sys.exit("No baseline.json — run: python3 eval/run_baseline.py")
    results = json.loads(results_path.read_text())
    client = load_client()

    total_gt = total_caught = 0
    scorecard: dict = {}
    rows = []

    for key, app in results.items():
        must = gt[key]["must_find"]
        if not app.get("ok"):
            rows.append((key, app["name"], "ERROR", app.get("error", "")[:40]))
            scorecard[key] = {"error": app.get("error")}
            total_gt += len(must)
            continue
        findings = app["findings"]
        j = _judge(client, app["name"], must, findings)
        caught = sum(1 for c in j.coverage if c.covered)
        total_gt += len(must)
        total_caught += caught

        unlabeled = [findings[i]["title"] for i in j.unlabeled_finding_indexes
                     if 0 <= i < len(findings)]
        scorecard[key] = {
            "name": app["name"],
            "caught": caught, "graded": len(must),
            "coverage": [c.model_dump() for c in j.coverage],
            "n_findings": len(findings),
            "unlabeled": unlabeled,
        }
        verdict = "✓" if caught == len(must) else ("~" if caught else "✗")
        rows.append((key, app["name"], f"{verdict} {caught}/{len(must)}",
                     f"{len(findings)} findings, {len(unlabeled)} unlabeled"))

    (ROOT / "eval" / "results" / "scorecard.json").write_text(json.dumps(scorecard, indent=2))

    print("\n" + "=" * 66)
    print(f"{'APP':<5}{'NAME':<20}{'RECALL':<12}{'NOTES'}")
    print("-" * 66)
    for k, n, r, note in rows:
        print(f"{k:<5}{n:<20}{r:<12}{note}")
    print("-" * 66)
    pct = f"{100 * total_caught / total_gt:.0f}%" if total_gt else "n/a"
    print(f"RECALL on graded issues: {total_caught}/{total_gt}  ({pct})")
    print("=" * 66)
    print("Per-issue detail + unlabeled findings -> eval/results/scorecard.json")
    print("'unlabeled' = agent findings not matching a graded issue; you decide "
          "real vs. false-positive.")


if __name__ == "__main__":
    main()
