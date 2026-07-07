"""Compare deterministic and PPO policies on the same replay dataset."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from agent.contracts import action_name
from agent.policies import get_policy
from agent.reward import heuristic_reward


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare ShadowMesh policy behavior on replay datasets"
    )
    parser.add_argument(
        "--dataset",
        default="scratch/session_replays/latest_sessions.json",
        help="Replay dataset JSON exported from Elasticsearch",
    )
    parser.add_argument(
        "--policies",
        nargs="+",
        default=[
            "do_nothing",
            "show_fake_credentials_after_successful_session",
        ],
        help="Policies to compare. Use 'ppo' to include a trained PPO model.",
    )
    parser.add_argument(
        "--model",
        help="Path to a saved PPO model; required when 'ppo' is included",
    )
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
    )
    parser.add_argument("--output", help="Optional file path for the rendered report")
    return parser.parse_args()


def _load_sessions(path: str) -> list[dict[str, Any]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _normalize_session(session: dict[str, Any]) -> dict[str, Any]:
    replay_session = dict(session)
    replay_session.setdefault("session_active", False)
    return replay_session


def _builtin_policy_summary(
    sessions: list[dict[str, Any]],
    policy_name: str,
    limit: int,
) -> dict[str, Any]:
    policy = get_policy(policy_name)
    selected = sessions[:limit]
    action_counter: Counter[str] = Counter()
    rewards: list[float] = []

    for session in selected:
        replay_session = _normalize_session(session)
        decision = policy.decide(replay_session, existing_actions=set())
        action_id = decision.action_id if decision is not None else 0
        action_counter[action_name(action_id)] += 1
        rewards.append(heuristic_reward(session, action_id))

    return {
        "policy_name": policy_name,
        "sessions_evaluated": len(selected),
        "average_reward": round(sum(rewards) / len(rewards), 4) if rewards else 0.0,
        "top_action": action_counter.most_common(1)[0][0] if action_counter else "none",
        "action_breakdown": dict(sorted(action_counter.items())),
    }


def _ppo_policy_summary(
    sessions: list[dict[str, Any]],
    model_path: str,
    limit: int,
) -> dict[str, Any]:
    try:
        from stable_baselines3 import PPO
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "stable-baselines3 is not installed. Run PPO comparisons with the "
            "Python 3.11 RL environment, for example `.venv311/bin/python`."
        ) from exc

    from agent.environment import ShadowMeshSessionEnv

    selected = sessions[:limit]
    env = ShadowMeshSessionEnv(session_summaries=selected, reward_fn=heuristic_reward)
    model = PPO.load(model_path)

    action_counter: Counter[str] = Counter()
    rewards: list[float] = []
    observation, _info = env.reset()

    for _ in range(len(selected)):
        action, _ = model.predict(observation, deterministic=True)
        observation, reward, terminated, truncated, step_info = env.step(int(action))
        action_counter[step_info["action_name"]] += 1
        rewards.append(float(reward))
        if terminated or truncated:
            observation, _info = env.reset()

    return {
        "policy_name": "ppo",
        "sessions_evaluated": len(selected),
        "average_reward": round(sum(rewards) / len(rewards), 4) if rewards else 0.0,
        "top_action": action_counter.most_common(1)[0][0] if action_counter else "none",
        "action_breakdown": dict(sorted(action_counter.items())),
    }


def _render_markdown(results: list[dict[str, Any]]) -> str:
    lines = [
        "| policy | sessions | avg_reward | top_action | action_breakdown |",
        "|---|---:|---:|---|---|",
    ]
    for item in results:
        breakdown = ", ".join(
            f"{name}:{count}" for name, count in item["action_breakdown"].items()
        )
        lines.append(
            f"| {item['policy_name']} | {item['sessions_evaluated']} | "
            f"{item['average_reward']:.2f} | {item['top_action']} | {breakdown} |"
        )
    return "\n".join(lines)


def _write_output(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    sessions = _load_sessions(args.dataset)
    if not sessions:
        raise SystemExit("Replay dataset is empty. Export sessions first.")

    results: list[dict[str, Any]] = []
    for policy_name in args.policies:
        if policy_name == "ppo":
            if not args.model:
                raise SystemExit("--model is required when 'ppo' is included")
            results.append(_ppo_policy_summary(sessions, args.model, args.limit))
            continue
        results.append(_builtin_policy_summary(sessions, policy_name, args.limit))

    if args.format == "json":
        rendered = json.dumps(results, indent=2)
    else:
        rendered = _render_markdown(results)

    print(rendered)
    if args.output:
        _write_output(args.output, rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
