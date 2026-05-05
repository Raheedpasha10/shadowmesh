"""Poll live session summaries and emit baseline RL actions."""

from __future__ import annotations

import argparse
import logging
import time

from agent.policies import get_policy
from agent.runtime import (
    ActionLogger,
    create_es_client,
    fetch_action_names_for_session,
    fetch_session_summaries,
    load_settings,
)

logger = logging.getLogger("shadowmesh-agent-runner")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ShadowMesh baseline agent runner")
    parser.add_argument("--policy", help="Policy name override")
    parser.add_argument("--session-id", help="Only process a single session ID")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--include-closed", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    settings = load_settings()
    policy = get_policy(args.policy or settings["agent_policy"])
    client = create_es_client(settings["es_url"])
    action_logger = ActionLogger(client, settings["actions_index"])

    logger.info("Agent runner starting with policy=%s", policy.name)

    while True:
        sessions = fetch_session_summaries(
            client,
            settings["sessions_index"],
            session_id=args.session_id,
            active_only=not args.include_closed,
            limit=args.limit,
        )
        logger.debug("Fetched %d candidate sessions", len(sessions))

        for episode, session in enumerate(reversed(sessions)):
            existing_actions = fetch_action_names_for_session(
                client,
                settings["actions_index"],
                session["session_id"],
            )
            decision = policy.decide(session, existing_actions, episode=episode)
            if decision is None:
                continue

            if args.dry_run:
                logger.info("Dry-run decision: %s", decision.to_document())
                continue

            action_logger.log(decision)

        if args.once:
            return 0

        time.sleep(settings["agent_poll_interval"])


if __name__ == "__main__":
    raise SystemExit(main())
