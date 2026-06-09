"""Explain deterministic policy and reward output on replay datasets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent.contracts import SessionState, action_name
from agent.policies import get_policy
from agent.reward import heuristic_reward


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Print session state, chosen action, and reward for replay data"
    )
    parser.add_argument(
        "--dataset",
        default="scratch/session_replays/latest_sessions.json",
        help="Replay dataset JSON exported from Elasticsearch",
    )
    parser.add_argument(
        "--policy",
        default="show_fake_credentials_after_successful_session",
        help="Built-in deterministic policy to inspect",
    )
    parser.add_argument("--limit", type=int, default=10)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sessions = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    policy = get_policy(args.policy)

    for session in sessions[: args.limit]:
        state = SessionState.from_session_summary(session).to_numpy().tolist()
        replay_session = dict(session)
        replay_session.setdefault("session_active", False)
        decision = policy.decide(replay_session, existing_actions=set())
        action_id = decision.action_id if decision is not None else 0
        reward = heuristic_reward(session, action_id)
        print(
            json.dumps(
                {
                    "session_id": session.get("session_id"),
                    "state_vector": state,
                    "selected_action": action_name(action_id),
                    "computed_reward": round(reward, 4),
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
