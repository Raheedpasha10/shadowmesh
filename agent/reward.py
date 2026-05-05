"""Offline reward shaping helpers for PPO experimentation."""

from __future__ import annotations


def heuristic_reward(session_summary: dict, action: int) -> float:
    """Score an action against a replayed session summary.

    This is intentionally simple for the first offline PPO pass. The reward
    favors long, high-signal sessions and gives a small bonus when the action
    matches the current session stage.
    """
    reward = 0.0
    reward += min(float(session_summary.get("session_duration", 0.0)), 600.0) * 0.01
    reward += float(session_summary.get("command_count", 0)) * 0.5
    reward += float(session_summary.get("ttp_count", 0)) * 3.0
    reward += len(session_summary.get("files_downloaded", []) or []) * 2.0

    if session_summary.get("login_success") and action == 4:
        reward += 5.0
    if session_summary.get("login_success") and action == 2:
        reward += 3.0
    if not session_summary.get("login_success") and action == 0:
        reward += 1.0

    return reward
