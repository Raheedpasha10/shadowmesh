"""Deterministic baseline policies for ShadowMesh."""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

_DATACLASS_KWARGS = {"slots": True} if sys.version_info >= (3, 10) else {}

from agent.runtime import ActionDecision

logger = logging.getLogger("shadowmesh-agent-policies")


class Policy(Protocol):
    """A baseline policy that may emit one action for a session."""

    name: str
    consumes_active_sessions: bool
    consumes_closed_sessions: bool

    def decide(
        self,
        session_summary: dict,
        existing_actions: set[str],
        episode: int = 0,
    ) -> ActionDecision | None: ...


@dataclass(**_DATACLASS_KWARGS)
class DoNothingPolicy:
    name: str = "do_nothing"
    consumes_active_sessions: bool = True
    consumes_closed_sessions: bool = False

    def decide(
        self,
        session_summary: dict,
        existing_actions: set[str],
        episode: int = 0,
    ) -> ActionDecision | None:
        if "do_nothing" in existing_actions:
            return None
        return ActionDecision(
            session_id=session_summary["session_id"],
            action_id=0,
            episode=episode,
            policy_name=self.name,
        )


@dataclass(**_DATACLASS_KWARGS)
class AlwaysShowFakeFilePolicy:
    name: str = "always_show_fake_file"
    consumes_active_sessions: bool = True
    consumes_closed_sessions: bool = False

    def decide(
        self,
        session_summary: dict,
        existing_actions: set[str],
        episode: int = 0,
    ) -> ActionDecision | None:
        if not session_summary.get("login_success"):
            return None
        if "show_fake_file" in existing_actions:
            return None
        return ActionDecision(
            session_id=session_summary["session_id"],
            action_id=2,
            parameters={
                "file_path": "/home/admin/loot/system_audit.txt",
                "file_type": "audit_report",
            },
            episode=episode,
            policy_name=self.name,
        )


@dataclass(**_DATACLASS_KWARGS)
class ShowFakeCredentialsOnLoginSuccessPolicy:
    name: str = "show_fake_credentials_on_login_success"
    consumes_active_sessions: bool = True
    consumes_closed_sessions: bool = False

    def decide(
        self,
        session_summary: dict,
        existing_actions: set[str],
        episode: int = 0,
    ) -> ActionDecision | None:
        if not session_summary.get("session_active", False):
            return None
        if not session_summary.get("login_success"):
            return None
        if "show_fake_credentials" in existing_actions:
            return None
        return ActionDecision(
            session_id=session_summary["session_id"],
            action_id=4,
            parameters={
                "file_path": "/etc/passwd",
                "file_type": "user_database",
                "activation_scope": "live_session",
            },
            episode=episode,
            policy_name=self.name,
        )


@dataclass(**_DATACLASS_KWARGS)
class ShowFakeCredentialsAfterSuccessfulSessionPolicy:
    """Seed higher-value bait for the next attacker session.

    Cowrie does not reliably surface newly materialized bait inside the same
    live session. This policy reacts after a successful session has closed and
    prepares richer artifacts for the following session, which is much more
    deterministic and measurable.
    """

    name: str = "show_fake_credentials_after_successful_session"
    consumes_active_sessions: bool = False
    consumes_closed_sessions: bool = True

    def decide(
        self,
        session_summary: dict,
        existing_actions: set[str],
        episode: int = 0,
    ) -> ActionDecision | None:
        if session_summary.get("session_active", False):
            return None
        if not session_summary.get("login_success"):
            return None
        if session_summary.get("command_count", 0) <= 0:
            return None
        if "show_fake_credentials" in existing_actions:
            return None
        return ActionDecision(
            session_id=session_summary["session_id"],
            action_id=4,
            parameters={
                "file_path": "/etc/passwd",
                "file_type": "user_database",
                "activation_scope": "next_session",
            },
            episode=episode,
            policy_name=self.name,
        )


@dataclass(**_DATACLASS_KWARGS)
class PPOPolicy:
    """Trained PPO agent policy for live and replay decision making.

    Evaluates the contract-defined 10-dimensional state vector from session
    summaries and predicts optimal adaptive deception actions using a trained
    Stable-Baselines3 PPO model.
    """

    name: str = "ppo"
    model_path: str | None = None
    consumes_active_sessions: bool = False
    consumes_closed_sessions: bool = True
    _model: Any = None
    _load_attempted: bool = False

    def get_model(self) -> Any | None:
        """Lazily load and cache the trained PPO model."""
        if self._model is not None:
            return self._model
        if self._load_attempted:
            return None

        self._load_attempted = True
        try:
            from stable_baselines3 import PPO
        except ImportError:
            logger.warning(
                "stable-baselines3 is not installed; PPOPolicy cannot predict actions."
            )
            return None

        candidates: list[Path] = []
        if self.model_path:
            candidates.append(Path(self.model_path))
        else:
            env_path = os.getenv("PPO_MODEL_PATH")
            if env_path:
                candidates.append(Path(env_path))

            base_dir = Path(__file__).resolve().parent
            candidates.extend([
                base_dir / "models" / "shadowmesh_ppo_adaptive.zip",
                base_dir / "models" / "shadowmesh_ppo_demo.zip",
                base_dir / "models" / "shadowmesh_ppo_smoke.zip",
                base_dir.parent / "agent" / "models" / "shadowmesh_ppo_adaptive.zip",
                base_dir.parent / "agent" / "models" / "shadowmesh_ppo_demo.zip",
            ])

        for path in candidates:
            if path.is_file():
                try:
                    self._model = PPO.load(str(path))
                    logger.info("Successfully loaded PPO model from %s", path)
                    return self._model
                except Exception as exc:
                    logger.warning("Could not load PPO model from %s: %s", path, exc)

        logger.warning(
            "No trained PPO model found among candidate paths: %s",
            [str(p) for p in candidates],
        )
        return None

    def decide(
        self,
        session_summary: dict,
        existing_actions: set[str],
        episode: int = 0,
    ) -> ActionDecision | None:
        is_active = bool(session_summary.get("session_active", False))
        if is_active and not self.consumes_active_sessions:
            return None
        if not is_active and not self.consumes_closed_sessions:
            return None

        model = self.get_model()
        if model is None:
            return None

        from agent.contracts import SessionState, action_name
        from agent.reward import heuristic_reward

        state_vector = SessionState.from_session_summary(session_summary).to_numpy()
        action, _ = model.predict(state_vector, deterministic=True)
        action_id = int(action)
        act_name = action_name(action_id)

        if act_name in existing_actions:
            return None

        parameters = self._suggest_parameters(action_id)
        reward = heuristic_reward(session_summary, action_id)

        return ActionDecision(
            session_id=session_summary["session_id"],
            action_id=action_id,
            parameters=parameters,
            reward=round(float(reward), 4),
            episode=episode,
            policy_name=self.name,
        )

    def _suggest_parameters(self, action_id: int) -> dict[str, Any]:
        if action_id == 2:
            return {
                "file_path": "/home/admin/loot/system_audit.txt",
                "file_type": "audit_report",
            }
        if action_id == 4:
            return {
                "file_path": "/etc/passwd",
                "file_type": "user_database",
                "activation_scope": "next_session",
            }
        if action_id == 5:
            return {
                "port": 3306,
                "service": "mysql",
            }
        if action_id == 3:
            return {
                "delay_seconds": 2.0,
            }
        return {}


POLICIES: dict[str, Policy] = {
    "do_nothing": DoNothingPolicy(),
    "always_show_fake_file": AlwaysShowFakeFilePolicy(),
    "show_fake_credentials_on_login_success": ShowFakeCredentialsOnLoginSuccessPolicy(),
    "show_fake_credentials_after_successful_session": (
        ShowFakeCredentialsAfterSuccessfulSessionPolicy()
    ),
    "ppo": PPOPolicy(),
}


def get_policy(name: str) -> Policy:
    """Return one of the built-in baseline policies."""
    try:
        return POLICIES[name]
    except KeyError as exc:
        options = ", ".join(sorted(POLICIES))
        raise KeyError(f"Unknown policy '{name}'. Available: {options}") from exc
