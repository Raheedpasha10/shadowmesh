from agent.policies import (
    ShowFakeCredentialsAfterSuccessfulSessionPolicy,
    ShowFakeCredentialsOnLoginSuccessPolicy,
)
from agent.runner import _session_scope


def test_session_scope_uses_active_sessions_for_live_policy():
    active_only, closed_only = _session_scope(
        ShowFakeCredentialsOnLoginSuccessPolicy(),
        include_closed=False,
    )

    assert active_only is True
    assert closed_only is False


def test_session_scope_uses_closed_sessions_for_next_session_policy():
    active_only, closed_only = _session_scope(
        ShowFakeCredentialsAfterSuccessfulSessionPolicy(),
        include_closed=False,
    )

    assert active_only is False
    assert closed_only is True


def test_session_scope_returns_both_when_include_closed_is_enabled():
    active_only, closed_only = _session_scope(
        ShowFakeCredentialsAfterSuccessfulSessionPolicy(),
        include_closed=True,
    )

    assert active_only is False
    assert closed_only is False


def test_session_scope_uses_closed_sessions_for_ppo_policy():
    from agent.policies import PPOPolicy

    active_only, closed_only = _session_scope(
        PPOPolicy(),
        include_closed=False,
    )
    assert active_only is False
    assert closed_only is True


def test_runner_main_with_ppo_policy(monkeypatch):
    import argparse
    from agent import runner
    from agent.policies import PPOPolicy

    class FakeModel:
        def predict(self, observation, deterministic=True):
            return 4, None

    fake_sessions = [
        {
            "session_id": "sess-ppo-1",
            "session_duration": 25.0,
            "command_count": 5,
            "unique_commands": 4,
            "login_attempts": 2,
            "login_success": True,
            "brute_force_detected": False,
            "files_downloaded": [],
            "ttp_count": 3,
            "session_active": False,
            "service": "ssh",
        }
    ]

    logged_decisions = []

    class FakeActionLogger:
        def __init__(self, client, index):
            pass

        def log(self, decision):
            logged_decisions.append(decision)
            return decision.to_document()

    ppo_policy = PPOPolicy()
    monkeypatch.setattr(ppo_policy, "get_model", lambda: FakeModel())
    monkeypatch.setattr(runner, "get_policy", lambda name: ppo_policy)
    monkeypatch.setattr(runner, "create_es_client", lambda url: None)
    monkeypatch.setattr(runner, "ActionLogger", FakeActionLogger)
    monkeypatch.setattr(runner, "fetch_session_summaries", lambda *a, **kw: fake_sessions)
    monkeypatch.setattr(runner, "fetch_action_names_for_session", lambda *a, **kw: set())
    monkeypatch.setattr(
        runner,
        "parse_args",
        lambda: argparse.Namespace(
            policy="ppo",
            session_id=None,
            limit=10,
            once=True,
            dry_run=False,
            include_closed=False,
            verbose=False,
        ),
    )

    exit_code = runner.main()
    assert exit_code == 0
    assert len(logged_decisions) == 1
    assert logged_decisions[0].policy_name == "ppo"
    assert logged_decisions[0].action_id == 4
    assert logged_decisions[0].session_id == "sess-ppo-1"

