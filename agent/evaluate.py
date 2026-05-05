"""Compare static and adaptive session datasets for project evaluation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


METRICS = [
    "session_duration",
    "command_count",
    "unique_commands",
    "ttp_count",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare two ShadowMesh datasets")
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--adaptive", required=True)
    return parser.parse_args()


def _load(path: str) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _average(items: list[dict], key: str) -> float:
    if not items:
        return 0.0
    return sum(float(item.get(key, 0.0) or 0.0) for item in items) / len(items)


def main() -> int:
    args = parse_args()
    baseline = _load(args.baseline)
    adaptive = _load(args.adaptive)

    print("| metric | baseline | adaptive | delta |")
    print("|---|---:|---:|---:|")
    for metric in METRICS:
        base_value = _average(baseline, metric)
        adaptive_value = _average(adaptive, metric)
        print(
            f"| {metric} | {base_value:.2f} | {adaptive_value:.2f} | "
            f"{adaptive_value - base_value:+.2f} |"
        )

    base_payloads = sum(len(item.get("files_downloaded", []) or []) for item in baseline)
    adaptive_payloads = sum(
        len(item.get("files_downloaded", []) or []) for item in adaptive
    )
    print(
        f"| payload_attempts | {base_payloads} | {adaptive_payloads} | "
        f"{adaptive_payloads - base_payloads:+d} |"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
