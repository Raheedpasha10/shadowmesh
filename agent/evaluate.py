"""Compare static and adaptive session datasets for project evaluation."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


METRICS = [
    "session_duration",
    "command_count",
    "unique_commands",
    "ttp_count",
]

BAIT_MARKERS = (
    "cat /home/admin/loot/system_audit.txt",
    "cat /home/admin/.aws/credentials",
    "grep AWS /opt/novapay/.env",
    "grep -E 'backupsvc|cloudsync' /etc/passwd",
    "grep -E 'backupsvc|cloudsync' /etc/shadow",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare two ShadowMesh datasets")
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--adaptive", required=True)
    parser.add_argument(
        "--format",
        choices=("markdown", "csv"),
        default="markdown",
        help="Output format for the comparison table",
    )
    parser.add_argument(
        "--output",
        help="Optional file path to also save the rendered comparison table",
    )
    return parser.parse_args()


def _load(path: str) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _average(items: list[dict], key: str) -> float:
    if not items:
        return 0.0
    return sum(float(item.get(key, 0.0) or 0.0) for item in items) / len(items)


def _command_list(item: dict) -> list[str]:
    commands = item.get("commands", []) or []
    return [str(command) for command in commands if command]


def _bait_access_sessions(items: list[dict]) -> int:
    total = 0
    for item in items:
        joined_commands = "\n".join(_command_list(item))
        if any(marker in joined_commands for marker in BAIT_MARKERS):
            total += 1
    return total


def _payload_attempts(items: list[dict]) -> int:
    return sum(len(item.get("files_downloaded", []) or []) for item in items)


def _metric_rows(baseline: list[dict], adaptive: list[dict]) -> list[tuple[str, float, float]]:
    rows: list[tuple[str, float, float]] = []
    for metric in METRICS:
        rows.append((metric, _average(baseline, metric), _average(adaptive, metric)))
    rows.append(
        (
            "bait_access_sessions",
            float(_bait_access_sessions(baseline)),
            float(_bait_access_sessions(adaptive)),
        )
    )
    rows.append(
        (
            "payload_attempts",
            float(_payload_attempts(baseline)),
            float(_payload_attempts(adaptive)),
        )
    )
    return rows


def _render_markdown(rows: list[tuple[str, float, float]]) -> str:
    lines = [
        "| metric | baseline | adaptive | delta |",
        "|---|---:|---:|---:|",
    ]
    for metric, base_value, adaptive_value in rows:
        delta = adaptive_value - base_value
        lines.append(
            f"| {metric} | {base_value:.2f} | {adaptive_value:.2f} | "
            f"{delta:+.2f} |"
        )
    return "\n".join(lines)


def _print_text(text: str) -> None:
    print(text)


def _write_output(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content + "\n", encoding="utf-8")


def _render_csv(rows: list[tuple[str, float, float]]) -> str:
    from io import StringIO

    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["metric", "baseline", "adaptive", "delta"])
    for metric, base_value, adaptive_value in rows:
        writer.writerow(
            [
                metric,
                f"{base_value:.2f}",
                f"{adaptive_value:.2f}",
                f"{adaptive_value - base_value:+.2f}",
            ]
        )
    return buffer.getvalue().rstrip("\n")


def main() -> int:
    args = parse_args()
    baseline = _load(args.baseline)
    adaptive = _load(args.adaptive)
    rows = _metric_rows(baseline, adaptive)
    if args.format == "csv":
        rendered = _render_csv(rows)
    else:
        rendered = _render_markdown(rows)
    _print_text(rendered)
    if args.output:
        _write_output(args.output, rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
