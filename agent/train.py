"""Offline PPO training entry point for ShadowMesh replay sessions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env

from agent.environment import ShadowMeshSessionEnv
from agent.reward import heuristic_reward
from agent.runtime import ActionLogger, create_es_client, load_settings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train PPO on replayed ShadowMesh sessions")
    parser.add_argument(
        "--dataset",
        default="scratch/session_replays/latest_sessions.json",
        help="Replay dataset JSON exported from Elasticsearch",
    )
    parser.add_argument("--timesteps", type=int, default=1000)
    parser.add_argument("--model-name", default="shadowmesh_ppo_demo")
    parser.add_argument("--log-actions", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dataset_path = Path(args.dataset)
    sessions = json.loads(dataset_path.read_text(encoding="utf-8"))
    if not sessions:
        raise SystemExit("Replay dataset is empty. Export sessions first.")

    settings = load_settings()
    action_logger = None
    if args.log_actions:
        client = create_es_client(settings["es_url"])
        action_logger = ActionLogger(client, settings["actions_index"])

    env = ShadowMeshSessionEnv(
        session_summaries=sessions,
        action_logger=action_logger,
        reward_fn=heuristic_reward,
    )
    check_env(env, warn=True)

    model = PPO("MlpPolicy", env, verbose=1)
    model.learn(total_timesteps=args.timesteps)

    model_dir = Path(settings["ppo_model_dir"])
    model_dir.mkdir(parents=True, exist_ok=True)
    output_path = model_dir / args.model_name
    model.save(output_path)
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
