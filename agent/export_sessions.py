"""Export recent honeypot sessions into a deterministic replay dataset."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent.runtime import create_es_client, fetch_session_summaries, load_settings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export ShadowMesh session replay data")
    parser.add_argument("--output", default="scratch/session_replays/latest_sessions.json")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--include-active", action="store_true")
    parser.add_argument("--since", help="ISO-8601 lower bound for @timestamp")
    parser.add_argument("--until", help="ISO-8601 upper bound for @timestamp")
    parser.add_argument(
        "--min-command-count",
        type=int,
        default=1,
        help="Only export sessions with at least this many commands",
    )
    parser.add_argument(
        "--login-success-only",
        action="store_true",
        help="Only export sessions that reached a successful login",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    settings = load_settings()
    client = create_es_client(settings["es_url"])
    sessions = fetch_session_summaries(
        client,
        settings["sessions_index"],
        active_only=False,
        closed_only=not args.include_active,
        since=args.since,
        until=args.until,
        min_command_count=args.min_command_count,
        login_success_only=args.login_success_only,
        limit=args.limit,
    )
    sessions = sorted(
        sessions,
        key=lambda item: (item.get("@timestamp", ""), item.get("session_id", "")),
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sessions, indent=2) + "\n", encoding="utf-8")
    print(f"{output_path} ({len(sessions)} sessions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
