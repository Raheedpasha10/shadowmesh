"""Run inference-only policy comparison on replay datasets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent.contracts import SessionState, action_name
from agent.environment import ShadowMeshSessionEnv
from agent.policies import get_policy
from agent.reward import heuristic_reward


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run offline policy inference on ShadowMesh replay sessions"
    )
    parser.add_argument(
        "--dataset",
        default="scratch/session_replays/latest_sessions.json",
        help="Replay dataset JSON exported from Elasticsearch",
    )
    parser.add_argument(
        "--policy",
        choices=(
            "do_nothing",
            "show_fake_credentials_on_login_success",
            "show_fake_credentials_after_successful_session",
            "ppo",
        ),
        default="ppo",
    )
    parser.add_argument(
        "--model",
        help="Path to a saved PPO model; required when --policy=ppo",
    )
    parser.add_argument("--limit", type=int, default=10)
    return parser.parse_args()


def _run_builtin_policy(sessions: list[dict], policy_name: str, limit: int) -> int:
    policy = get_policy(policy_name)
    for session in sessions[:limit]:
        replay_session = dict(session)
        replay_session.setdefault("session_active", False)
        decision = policy.decide(replay_session, existing_actions=set())
        action_id = decision.action_id if decision is not None else 0
        reward = heuristic_reward(session, action_id)
        print(
            json.dumps(
                {
                    "session_id": session.get("session_id"),
                    "action_id": action_id,
                    "action_name": action_name(action_id),
                    "reward": round(reward, 4),
                    "policy_name": policy_name,
                }
            )
        )
    return 0


def _run_ppo_policy(sessions: list[dict], model_path: str, limit: int) -> int:
    try:
        from stable_baselines3 import PPO
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "stable-baselines3 is not installed. Install the full agent "
            "dependencies with `pip install -r agent/requirements.txt`."
        ) from exc

    env = ShadowMeshSessionEnv(session_summaries=sessions, reward_fn=heuristic_reward)
    model = PPO.load(model_path)
    observation, info = env.reset()

    for _ in range(min(limit, len(sessions))):
        action, _ = model.predict(observation, deterministic=True)
        observation, reward, terminated, truncated, step_info = env.step(int(action))
        print(
            json.dumps(
                {
                    "session_id": step_info.get("session_id") or info.get("session_id"),
                    "action_id": int(action),
                    "action_name": step_info.get("action_name", action_name(int(action))),
                    "reward": round(float(reward), 4),
                    "policy_name": "ppo",
                }
            )
        )
        if terminated or truncated:
            observation, info = env.reset()
    return 0


def main() -> int:
    args = parse_args()
    sessions = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    if not sessions:
        raise SystemExit("Replay dataset is empty. Export sessions first.")

    if args.policy == "ppo":
        if not args.model:
            raise SystemExit("--model is required when --policy=ppo")
        return _run_ppo_policy(sessions, args.model, args.limit)

    return _run_builtin_policy(sessions, args.policy, args.limit)


if __name__ == "__main__":
    raise SystemExit(main())
