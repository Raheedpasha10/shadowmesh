"""Collect paired baseline/adaptive replay datasets and save evaluation output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agent.evaluate import _metric_rows, _render_markdown
from agent.runtime import create_es_client, fetch_session_summaries, load_settings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect paired ShadowMesh evidence datasets from Elasticsearch"
    )
    parser.add_argument("--baseline-since", required=True)
    parser.add_argument("--baseline-until", required=True)
    parser.add_argument("--adaptive-since", required=True)
    parser.add_argument("--adaptive-until", required=True)
    parser.add_argument(
        "--output-dir",
        default="scratch/evidence/latest",
        help="Directory where dataset exports and the evaluation report are written",
    )
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--min-command-count", type=int, default=1)
    parser.add_argument(
        "--login-success-only",
        action="store_true",
        help="Only export sessions that reached a successful login",
    )
    return parser.parse_args()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _export_dataset(
    *,
    client: Any,
    index_name: str,
    since: str,
    until: str,
    limit: int,
    min_command_count: int,
    login_success_only: bool,
) -> list[dict[str, Any]]:
    return sorted(
        fetch_session_summaries(
            client,
            index_name,
            active_only=False,
            closed_only=True,
            since=since,
            until=until,
            min_command_count=min_command_count,
            login_success_only=login_success_only,
            limit=limit,
        ),
        key=lambda item: (item.get("@timestamp", ""), item.get("session_id", "")),
    )


def _dataset_summary(name: str, sessions: list[dict[str, Any]], since: str, until: str) -> dict[str, Any]:
    return {
        "name": name,
        "since": since,
        "until": until,
        "session_count": len(sessions),
        "login_success_count": sum(1 for item in sessions if item.get("login_success")),
        "average_command_count": (
            sum(float(item.get("command_count", 0) or 0) for item in sessions) / len(sessions)
            if sessions
            else 0.0
        ),
    }


def _manifest(
    *,
    baseline: list[dict[str, Any]],
    adaptive: list[dict[str, Any]],
    args: argparse.Namespace,
    baseline_path: Path,
    adaptive_path: Path,
    evaluation_path: Path,
) -> dict[str, Any]:
    return {
        "collection": {
            "limit": args.limit,
            "min_command_count": args.min_command_count,
            "login_success_only": args.login_success_only,
        },
        "baseline": {
            **_dataset_summary(
                "baseline",
                baseline,
                args.baseline_since,
                args.baseline_until,
            ),
            "path": str(baseline_path),
        },
        "adaptive": {
            **_dataset_summary(
                "adaptive",
                adaptive,
                args.adaptive_since,
                args.adaptive_until,
            ),
            "path": str(adaptive_path),
        },
        "evaluation_path": str(evaluation_path),
    }


def main() -> int:
    args = parse_args()
    settings = load_settings()
    client = create_es_client(settings["es_url"])

    output_dir = Path(args.output_dir)
    baseline_path = output_dir / "baseline_sessions.json"
    adaptive_path = output_dir / "adaptive_sessions.json"
    evaluation_path = output_dir / "evaluation.md"
    manifest_path = output_dir / "manifest.json"

    baseline = _export_dataset(
        client=client,
        index_name=settings["sessions_index"],
        since=args.baseline_since,
        until=args.baseline_until,
        limit=args.limit,
        min_command_count=args.min_command_count,
        login_success_only=args.login_success_only,
    )
    adaptive = _export_dataset(
        client=client,
        index_name=settings["sessions_index"],
        since=args.adaptive_since,
        until=args.adaptive_until,
        limit=args.limit,
        min_command_count=args.min_command_count,
        login_success_only=args.login_success_only,
    )

    _write_json(baseline_path, baseline)
    _write_json(adaptive_path, adaptive)

    rows = _metric_rows(baseline, adaptive)
    evaluation_path.parent.mkdir(parents=True, exist_ok=True)
    evaluation_path.write_text(_render_markdown(rows) + "\n", encoding="utf-8")

    manifest = _manifest(
        baseline=baseline,
        adaptive=adaptive,
        args=args,
        baseline_path=baseline_path,
        adaptive_path=adaptive_path,
        evaluation_path=evaluation_path,
    )
    _write_json(manifest_path, manifest)

    print(output_dir)
    print(f"baseline_sessions={len(baseline)}")
    print(f"adaptive_sessions={len(adaptive)}")
    print(evaluation_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
