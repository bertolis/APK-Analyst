#!/usr/bin/env python3
"""Step 5 eval — BLIND baseline runner.

Runs the Step 3 agent on every app in ground_truth.yaml with the agent's
CURRENT knowledge (no test-course ingested), saves each agent report, and
writes one consolidated results file for the scorer.

The agent never sees ground_truth.yaml — this only *runs* it. Scoring is
score.py.

    python3 eval/run_baseline.py            # all apps
    python3 eval/run_baseline.py IL EA      # a subset
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from apk_analyst.pipeline import analyze                    # noqa: E402
from apk_analyst.ai.agent import analyze_agentic            # noqa: E402
from apk_analyst.ai.analyst import report_to_dict           # noqa: E402

GT_PATH = ROOT / "eval" / "ground_truth.yaml"
RESULTS_DIR = ROOT / "eval" / "results"


def main() -> None:
    gt = yaml.safe_load(GT_PATH.read_text())["apps"]
    wanted = [a.upper() for a in sys.argv[1:]] or list(gt)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    # Merge into any existing results so per-app runs don't clobber each other.
    baseline_path = RESULTS_DIR / "baseline.json"
    results: dict = json.loads(baseline_path.read_text()) if baseline_path.exists() else {}

    for key in wanted:
        if key not in gt:
            print(f"!! {key} not in ground truth, skipping")
            continue
        app = gt[key]
        apk = ROOT / app["apk"]
        print(f"\n{'=' * 60}\n{key} — {app['name']}  ({apk.name})\n{'=' * 60}")

        entry: dict = {"name": app["name"], "apk": app["apk"]}
        t0 = time.time()
        try:
            summary = analyze(str(apk))
            res = analyze_agentic(summary, verbose=True)
            report = report_to_dict(res.report)
            entry.update(
                ok=True,
                iterations=res.iterations,
                tool_calls=res.tool_calls,
                n_tool_calls=len(res.tool_calls),
                findings=report["findings"],
                summary=report["summary"],
                seconds=round(time.time() - t0, 1),
            )
            # also drop the report next to the other workspace artifacts
            (Path(summary["workspace"]) / "agent_report.json").write_text(
                json.dumps({**report, "_meta": {
                    "iterations": res.iterations, "tool_calls": res.tool_calls}}, indent=2)
            )
            print(f"\n-> {len(report['findings'])} findings in "
                  f"{res.iterations} iters / {len(res.tool_calls)} tool calls "
                  f"({entry['seconds']}s)")
        except Exception as e:  # keep the batch alive if one app fails
            entry.update(ok=False, error=f"{type(e).__name__}: {e}",
                         seconds=round(time.time() - t0, 1))
            print(f"\n!! FAILED: {entry['error']}")

        results[key] = entry
        # write after each app so a crash doesn't lose completed runs
        baseline_path.write_text(json.dumps(results, indent=2))

    ok = sum(1 for r in results.values() if r.get("ok"))
    print(f"\n{'=' * 60}\nDONE — {ok}/{len(results)} apps analyzed. "
          f"Results -> eval/results/baseline.json\nRun: python3 eval/score.py")


if __name__ == "__main__":
    main()
