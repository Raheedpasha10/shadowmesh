"""Deterministic baseline policies for ShadowMesh."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agent.runtime import ActionDecision


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


@dataclass(slots=True)
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


@dataclass(slots=True)
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


@dataclass(slots=True)
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


@dataclass(slots=True)
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


POLICIES: dict[str, Policy] = {
    "do_nothing": DoNothingPolicy(),
    "always_show_fake_file": AlwaysShowFakeFilePolicy(),
    "show_fake_credentials_on_login_success": ShowFakeCredentialsOnLoginSuccessPolicy(),
    "show_fake_credentials_after_successful_session": (
        ShowFakeCredentialsAfterSuccessfulSessionPolicy()
    ),
}


def get_policy(name: str) -> Policy:
    """Return one of the built-in baseline policies."""
    try:
        return POLICIES[name]
    except KeyError as exc:
        options = ", ".join(sorted(POLICIES))
        raise KeyError(f"Unknown policy '{name}'. Available: {options}") from exc
