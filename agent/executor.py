"""Execute a small subset of RL actions by materializing bait files."""

from __future__ import annotations

import argparse
import logging
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path

from agent.runtime import create_es_client, fetch_recent_actions, load_settings

logger = logging.getLogger("shadowmesh-action-executor")

SUPPORTED_ACTIONS = {"show_fake_file", "show_fake_credentials"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ShadowMesh action executor")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    settings = load_settings()
    client = create_es_client(settings["es_url"])
    loot_dir = Path(settings["action_loot_dir"])
    aws_dir = Path(settings["action_aws_dir"])
    loot_dir.mkdir(parents=True, exist_ok=True)
    aws_dir.mkdir(parents=True, exist_ok=True)

    seen_ids: set[str] = set()

    while True:
        actions = fetch_recent_actions(
            client,
            settings["actions_index"],
            action_names=sorted(SUPPORTED_ACTIONS),
            limit=50,
        )
        for action in reversed(actions):
            action_id = action["_id"]
            if action_id in seen_ids:
                continue
            _apply_action(action, loot_dir=loot_dir, aws_dir=aws_dir)
            seen_ids.add(action_id)

        if args.once:
            return 0

        time.sleep(settings["action_executor_poll_interval"])


def _apply_action(action: dict, *, loot_dir: Path, aws_dir: Path) -> None:
    action_name = action["action_name"]
    params = action.get("parameters", {})
    file_path = params.get("file_path", "")
    session_id = action.get("session_id", "unknown")

    if action_name == "show_fake_file":
        target = loot_dir / Path(file_path).name
        target.write_text(_audit_report(session_id), encoding="utf-8")
        logger.info("Materialized fake file at %s", target)
        return

    if action_name == "show_fake_credentials":
        target = aws_dir / "credentials"
        target.write_text(_aws_credentials(session_id), encoding="utf-8")
        logger.info("Materialized fake credentials at %s", target)
        return

    logger.debug("Ignoring unsupported action: %s", action_name)


def _audit_report(session_id: str) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    return textwrap.dedent(
        f"""\
        NOVAPAY INTERNAL SYSTEM AUDIT
        generated_at={generated_at}
        session_ref={session_id}
        owner=platform-security
        note=Temporary export of service accounts for weekend DR validation

        mysql:
          user=novapay_ro
          password=N0vaPay_ReadOnly_2026!

        redis:
          endpoint=redis://:N0vaPayRedis!@10.10.24.12:6379/0
        """
    )


def _aws_credentials(session_id: str) -> str:
    return textwrap.dedent(
        f"""\
        [default]
        aws_access_key_id = AKIA7NOVAPAYDEMO2026
        aws_secret_access_key = 0nlyF4k3ButL00ksRealForShadowMeshDemo2026
        region = us-east-1
        session_reference = {session_id}
        """
    )


if __name__ == "__main__":
    raise SystemExit(main())
