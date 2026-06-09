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
    generated_dir = Path(settings["action_generated_dir"])
    loot_dir.mkdir(parents=True, exist_ok=True)
    aws_dir.mkdir(parents=True, exist_ok=True)
    generated_dir.mkdir(parents=True, exist_ok=True)

    seen_ids: set[str] = set()
    started_at = datetime.now(timezone.utc)

    while True:
        actions = fetch_recent_actions(
            client,
            settings["actions_index"],
            action_names=sorted(SUPPORTED_ACTIONS),
            limit=50,
        )
        for action in reversed(actions):
            action_id = action["_id"]
            if action_id in seen_ids or not _is_fresh_action(action, started_at):
                continue
            _apply_action(
                action,
                loot_dir=loot_dir,
                aws_dir=aws_dir,
                generated_dir=generated_dir,
            )
            seen_ids.add(action_id)

        if args.once:
            return 0

        time.sleep(settings["action_executor_poll_interval"])


def _is_fresh_action(action: dict, started_at: datetime) -> bool:
    """Process only actions created after the current executor started.

    Without this guard, a restart replays old Elasticsearch action documents
    and pollutes the bait state before a fresh validation run even begins.
    """

    raw_timestamp = action.get("@timestamp")
    if not raw_timestamp:
        return False

    try:
        action_time = datetime.fromisoformat(
            str(raw_timestamp).replace("Z", "+00:00")
        )
    except ValueError:
        logger.warning("Skipping action with invalid timestamp: %s", raw_timestamp)
        return False

    return action_time >= started_at


def _apply_action(
    action: dict,
    *,
    loot_dir: Path,
    aws_dir: Path,
    generated_dir: Path,
) -> None:
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
        env_target = generated_dir / ".env"
        env_target.write_text(_adaptive_env_credentials(session_id), encoding="utf-8")
        logger.info("Materialized adaptive env credentials at %s", env_target)

        loot_target = loot_dir / "system_audit.txt"
        loot_target.write_text(_audit_report(session_id), encoding="utf-8")
        logger.info("Materialized adaptive audit report at %s", loot_target)

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


def _adaptive_env_credentials(session_id: str) -> str:
    return textwrap.dedent(
        f"""\
        APP_ENV=production
        DB_HOST=10.10.24.12
        DB_NAME=novapay
        DB_USER=novapay_app
        DB_PASSWORD=N0vaPay-ShadowMesh-2026!
        AWS_ACCESS_KEY_ID=AKIA7NOVAPAYDEMO2026
        AWS_SECRET_ACCESS_KEY=0nlyF4k3ButL00ksRealForShadowMeshDemo2026
        rotation_marker=shadowmesh_live_credentials
        session_reference={session_id}
        """
    )


if __name__ == "__main__":
    raise SystemExit(main())
