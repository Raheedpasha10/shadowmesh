"""Build a reviewer-friendly summary report for one evidence directory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Package one ShadowMesh evidence directory into a summary report"
    )
    parser.add_argument(
        "--evidence-dir",
        required=True,
        help="Directory containing baseline_sessions.json, adaptive_sessions.json, evaluation.md, and optionally policy_comparison.md",
    )
    parser.add_argument(
        "--output",
        help="Optional report output path. Defaults to <evidence-dir>/summary_report.md",
    )
    parser.add_argument(
        "--title",
        default="ShadowMesh Evidence Summary",
        help="Title used at the top of the generated report",
    )
    return parser.parse_args()


def _read_json(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def _session_stats(sessions: list[dict[str, Any]]) -> dict[str, float]:
    count = len(sessions)
    if not sessions:
        return {
            "count": 0,
            "login_success_count": 0,
            "avg_duration": 0.0,
            "avg_command_count": 0.0,
            "avg_unique_commands": 0.0,
        }
    return {
        "count": count,
        "login_success_count": sum(1 for item in sessions if item.get("login_success")),
        "avg_duration": sum(float(item.get("session_duration", 0.0) or 0.0) for item in sessions) / count,
        "avg_command_count": sum(float(item.get("command_count", 0) or 0) for item in sessions) / count,
        "avg_unique_commands": sum(float(item.get("unique_commands", 0) or 0) for item in sessions) / count,
    }


def _extract_bait_access(adaptive_sessions: list[dict[str, Any]]) -> int:
    markers = (
        "grep -E 'backupsvc|cloudsync' /etc/passwd",
        "grep -E 'backupsvc|cloudsync' /etc/shadow",
    )
    total = 0
    for session in adaptive_sessions:
        commands = "\n".join(str(command) for command in session.get("commands", []) or [])
        if any(marker in commands for marker in markers):
            total += 1
    return total


def _top_commands(sessions: list[dict[str, Any]], limit: int = 5) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for session in sessions:
        for command in session.get("commands", []) or []:
            command_str = str(command)
            counts[command_str] = counts.get(command_str, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]


def _report_text(
    *,
    title: str,
    baseline_sessions: list[dict[str, Any]],
    adaptive_sessions: list[dict[str, Any]],
    evaluation_markdown: str,
    policy_markdown: str | None,
) -> str:
    baseline = _session_stats(baseline_sessions)
    adaptive = _session_stats(adaptive_sessions)
    bait_access = _extract_bait_access(adaptive_sessions)
    top_adaptive_commands = _top_commands(adaptive_sessions)

    lines = [
        f"# {title}",
        "",
        "## Overview",
        "",
        f"- Baseline sessions analyzed: `{baseline['count']}`",
        f"- Adaptive sessions analyzed: `{adaptive['count']}`",
        f"- Adaptive bait-follow-up sessions observed: `{bait_access}`",
        f"- Baseline average command count: `{baseline['avg_command_count']:.2f}`",
        f"- Adaptive average command count: `{adaptive['avg_command_count']:.2f}`",
        "",
        "## Reviewer Summary",
        "",
        "This evidence batch compares a static SSH honeypot run against the current adaptive ShadowMesh flow.",
        "In the adaptive run, attackers not only logged in and performed the same baseline recon, but also followed the planted bait accounts exposed through `/etc/passwd` and `/etc/shadow`.",
        "",
        "## Dataset Snapshot",
        "",
        f"- Baseline login-success sessions: `{baseline['login_success_count']}`",
        f"- Adaptive login-success sessions: `{adaptive['login_success_count']}`",
        f"- Baseline average duration: `{baseline['avg_duration']:.2f}` seconds",
        f"- Adaptive average duration: `{adaptive['avg_duration']:.2f}` seconds",
        f"- Baseline average unique commands: `{baseline['avg_unique_commands']:.2f}`",
        f"- Adaptive average unique commands: `{adaptive['avg_unique_commands']:.2f}`",
        "",
        "## Evaluation Table",
        "",
        evaluation_markdown.strip(),
        "",
        "## Adaptive Command Highlights",
        "",
    ]

    for command, count in top_adaptive_commands:
        lines.append(f"- `{command}` appeared in `{count}` adaptive sessions")

    if policy_markdown:
        lines.extend(
            [
                "",
                "## Policy Comparison",
                "",
                policy_markdown.strip(),
            ]
        )

    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    evidence_dir = Path(args.evidence_dir)
    baseline_path = evidence_dir / "baseline_sessions.json"
    adaptive_path = evidence_dir / "adaptive_sessions.json"
    evaluation_path = evidence_dir / "evaluation.md"
    policy_path = evidence_dir / "policy_comparison.md"

    baseline_sessions = _read_json(baseline_path)
    adaptive_sessions = _read_json(adaptive_path)
    evaluation_markdown = evaluation_path.read_text(encoding="utf-8")
    policy_markdown = (
        policy_path.read_text(encoding="utf-8") if policy_path.exists() else None
    )

    report = _report_text(
        title=args.title,
        baseline_sessions=baseline_sessions,
        adaptive_sessions=adaptive_sessions,
        evaluation_markdown=evaluation_markdown,
        policy_markdown=policy_markdown,
    )

    output_path = Path(args.output) if args.output else evidence_dir / "summary_report.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
