"""``python -m app.ai.eval [--suite all|nlq|alerts|narrative|chat|scripts|injection]
[--provider fixture|fake|live] [--out report.json] [--record replies.json]``

Exits 1 when any target is missed. ``fixture``/``fake`` never touch the network; ``live`` sends
the datasets to the configured provider (LLM_* settings) and is meant for manual runs only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.ai.eval.harness import SUITES, Evaluator, RecordingProvider


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.ai.eval", description=__doc__)
    ap.add_argument("--suite", default="all", choices=("all", *SUITES))
    ap.add_argument("--provider", default="fixture", choices=("fixture", "fake", "live"))
    ap.add_argument("--out", type=Path, help="write the JSON report here")
    ap.add_argument("--record", type=Path, help="live only: save provider replies here")
    args = ap.parse_args(argv)

    evaluator = Evaluator(provider_kind=args.provider)
    recorder: RecordingProvider | None = None
    if args.provider == "live":
        from app.ai.gateway import build_provider
        from app.config import get_settings

        settings = get_settings()
        recorder = RecordingProvider(build_provider(settings))
        evaluator.live_provider = recorder
        evaluator.model_fast = settings.llm_model_fast
        evaluator.model_strong = settings.llm_model_strong
    suites = list(SUITES) if args.suite == "all" else [args.suite]
    report = evaluator.run(suites)

    for suite in report["suites"]:
        status = "PASS" if suite["passed"] else "FAIL"
        print(f"[{status}] {suite['suite']}")  # noqa: T201 - CLI output
        for check in suite["targets"]:
            mark = "ok " if check["ok"] else "MISS"
            print(f"    {mark} {check['metric']} = {check['value']} (target {check['target']})")  # noqa: T201
    if args.out:
        args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if recorder is not None and args.record:
        args.record.write_text(json.dumps(recorder.replies, indent=2), encoding="utf-8")
    print("AI EVAL PASSED" if report["passed"] else "AI EVAL FAILED")  # noqa: T201
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
