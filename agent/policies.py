"""Deterministic baseline policies for ShadowMesh."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agent.runtime import ActionDecision


class Policy(Protocol):
    """A baseline policy that may emit one action for a session."""

    name: str

    def decide(
        self,
        session_summary: dict,
        existing_actions: set[str],
        episode: int = 0,
    ) -> ActionDecision | None: ...


@dataclass(slots=True)
class DoNothingPolicy:
    name: str = "do_nothing"

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


@dataclass(slots=True)
class AlwaysShowFakeFilePolicy:
    name: str = "always_show_fake_file"

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


@dataclass(slots=True)
class ShowFakeCredentialsOnLoginSuccessPolicy:
    name: str = "show_fake_credentials_on_login_success"

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
                "file_path": "/home/admin/.aws/credentials",
                "file_type": "cloud_credentials",
            },
            episode=episode,
            policy_name=self.name,
        )


POLICIES: dict[str, Policy] = {
    "do_nothing": DoNothingPolicy(),
    "always_show_fake_file": AlwaysShowFakeFilePolicy(),
    "show_fake_credentials_on_login_success": ShowFakeCredentialsOnLoginSuccessPolicy(),
}


def get_policy(name: str) -> Policy:
    """Return one of the built-in baseline policies."""
    try:
        return POLICIES[name]
    except KeyError as exc:
        options = ", ".join(sorted(POLICIES))
        raise KeyError(f"Unknown policy '{name}'. Available: {options}") from exc
