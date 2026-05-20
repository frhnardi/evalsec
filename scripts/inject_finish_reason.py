#!/usr/bin/env python3
"""Inject finish_reason and error from responses JSON into scores JSON.

Usage:
    python scripts/inject_finish_reason.py \\
        --scores outputs/scores_trivy_triage_20260515_102702.json \\
        --responses outputs/responses_trivy_triage_20260515_102645.json \\
        --output outputs/scores_injected.json
"""

import json
import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inject finish_reason from responses into scores JSON."
    )
    parser.add_argument("--scores", required=True, help="Path to scores JSON")
    parser.add_argument("--responses", required=True, help="Path to responses JSON")
    parser.add_argument("--output", required=True, help="Output scores JSON path")
    args = parser.parse_args()

    # Load scores
    with open(args.scores) as f:
        scores = json.load(f)

    # Load responses
    with open(args.responses) as f:
        responses_raw = json.load(f)

    # Build lookup: (case_id, model_id) -> finish_reason, error
    lookup: dict[tuple[str, str], dict[str, str]] = {}
    for resp in responses_raw.get("responses", []):
        case_id = resp.get("case_id", "")
        model_id = resp.get("model_id", "")
        rdata = resp.get("response", {})
        lookup[(case_id, model_id)] = {
            "finish_reason": rdata.get("finish_reason", ""),
            "error": rdata.get("error") or "",
        }

    # Inject into each grade entry
    injected = 0
    for grade in scores.get("grades", []):
        case_id = grade.get("case_id", "")
        model_id = grade.get("model_id", "")
        key = (case_id, model_id)
        if key in lookup:
            info = lookup[key]
            # Ensure validation dict exists
            score = grade.get("score", {})
            if not isinstance(score, dict):
                continue
            if "validation" not in score or not isinstance(score["validation"], dict):
                score["validation"] = {}
            score["validation"]["finish_reason"] = info["finish_reason"]
            score["validation"]["error"] = info["error"]
            injected += 1

    # Save
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(scores, f, indent=2)

    print(f"Injected finish_reason into {injected} grade entries")
    print(f"Saved to {args.output}")


if __name__ == "__main__":
    main()
