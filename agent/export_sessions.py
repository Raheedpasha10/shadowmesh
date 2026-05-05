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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    settings = load_settings()
    client = create_es_client(settings["es_url"])
    sessions = fetch_session_summaries(
        client,
        settings["sessions_index"],
        active_only=not args.include_active,
        limit=args.limit,
    )
    sessions = sorted(
        sessions,
        key=lambda item: (item.get("@timestamp", ""), item.get("session_id", "")),
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sessions, indent=2) + "\n", encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
