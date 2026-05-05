"""A lightweight Gymnasium environment stub for ShadowMesh sessions."""

from __future__ import annotations

from typing import Any

import gymnasium as gym
import numpy as np

from agent.contracts import SessionState, action_name, action_space, observation_space
from agent.runtime import ActionDecision, ActionLogger


class ShadowMeshSessionEnv(gym.Env):
    """Replay-like environment used to wire the RL contract before training.

    This environment is intentionally simple for Phase 1. It accepts a list of
    session summaries, exposes the documented observation/action spaces, and
    logs agent actions without yet mutating live Cowrie behavior.
    """

    metadata = {"render_modes": []}

    def __init__(
        self,
        session_summaries: list[dict],
        action_logger: ActionLogger | None = None,
    ) -> None:
        super().__init__()
        self.session_summaries = session_summaries
        self.action_logger = action_logger
        self.observation_space = observation_space
        self.action_space = action_space
        self._index = -1
        self._current_summary: dict[str, Any] | None = None

    def reset(
        self,
        *,
        seed: int | None = None,
        options: dict[str, Any] | None = None,
    ) -> tuple[np.ndarray, dict[str, Any]]:
        super().reset(seed=seed)
        del options
        self._index += 1
        if self._index >= len(self.session_summaries):
            self._index = 0

        self._current_summary = self.session_summaries[self._index]
        state = SessionState.from_session_summary(self._current_summary).to_numpy()
        info = {
            "session_id": self._current_summary.get("session_id"),
            "service": self._current_summary.get("service", "ssh"),
        }
        return state, info

    def step(
        self,
        action: int,
    ) -> tuple[np.ndarray, float, bool, bool, dict[str, Any]]:
        if self._current_summary is None:
            raise RuntimeError("reset() must be called before step().")

        if not self.action_space.contains(action):
            raise ValueError(f"Action {action} is outside the defined action space.")

        decision_document = None
        if self.action_logger is not None:
            decision = ActionDecision(
                session_id=self._current_summary["session_id"],
                action_id=action,
                parameters=self._suggest_parameters(action),
                reward=0.0,
                episode=self._index,
            )
            decision_document = self.action_logger.log(decision)

        next_state = SessionState.from_session_summary(self._current_summary).to_numpy()
        info = {
            "session_id": self._current_summary["session_id"],
            "action_name": action_name(action),
            "action_record": decision_document,
        }
        reward = 0.0
        terminated = True
        truncated = False
        return next_state, reward, terminated, truncated, info

    def _suggest_parameters(self, action: int) -> dict[str, Any]:
        if action == 2:
            return {
                "file_path": "/home/admin/bank_credentials.txt",
                "file_type": "credentials",
            }
        if action == 4:
            return {
                "file_path": "/home/admin/.aws/credentials",
                "file_type": "cloud_credentials",
            }
        if action == 5:
            return {
                "port": 3306,
                "service": "mysql",
            }
        return {}
