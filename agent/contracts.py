"""Contract-aligned agent state and action definitions.

This file mirrors the RL interface documented in `data_contracts.md` so the
team can start integrating action logging and environment wiring before PPO
training begins.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from gymnasium import spaces

STATE_SIZE = 10

OBSERVATION_LOW = np.zeros(STATE_SIZE, dtype=np.float32)
OBSERVATION_HIGH = np.array(
    [3600, 100, 100, 50, 1, 1, 20, 20, 1, 1],
    dtype=np.float32,
)

observation_space = spaces.Box(
    low=OBSERVATION_LOW,
    high=OBSERVATION_HIGH,
    dtype=np.float32,
)

action_space = spaces.Discrete(6)

ACTION_MAP = {
    0: "do_nothing",
    1: "fake_login_success",
    2: "show_fake_file",
    3: "slow_response",
    4: "show_fake_credentials",
    5: "open_fake_port",
}


@dataclass(slots=True)
class SessionState:
    """Typed view of the fields the agent consumes from `honeypot-sessions`."""

    session_duration: float
    command_count: int
    unique_commands: int
    login_attempts: int
    login_success: bool
    brute_force_detected: bool
    files_downloaded_count: int
    ttp_count: int
    service_ssh: bool
    service_web: bool

    def to_numpy(self) -> np.ndarray:
        """Convert the state into the contract-defined numpy vector."""
        return np.array(
            [
                self.session_duration,
                self.command_count,
                self.unique_commands,
                self.login_attempts,
                float(self.login_success),
                float(self.brute_force_detected),
                self.files_downloaded_count,
                self.ttp_count,
                float(self.service_ssh),
                float(self.service_web),
            ],
            dtype=np.float32,
        )

    @classmethod
    def from_session_summary(cls, summary: dict) -> "SessionState":
        """Build the agent state from one session summary document."""
        service = summary.get("service", "ssh")
        return cls(
            session_duration=float(summary.get("session_duration", 0.0) or 0.0),
            command_count=int(summary.get("command_count", 0) or 0),
            unique_commands=int(summary.get("unique_commands", 0) or 0),
            login_attempts=int(summary.get("login_attempts", 0) or 0),
            login_success=bool(summary.get("login_success", False)),
            brute_force_detected=bool(summary.get("brute_force_detected", False)),
            files_downloaded_count=len(summary.get("files_downloaded", []) or []),
            ttp_count=int(summary.get("ttp_count", 0) or 0),
            service_ssh=service == "ssh",
            service_web=service == "web",
        )


def action_name(action_id: int) -> str:
    """Return the symbolic name for a discrete action ID."""
    if action_id not in ACTION_MAP:
        raise KeyError(f"Unknown action_id: {action_id}")
    return ACTION_MAP[action_id]
