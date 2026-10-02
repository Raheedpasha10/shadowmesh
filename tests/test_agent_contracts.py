import numpy as np
import pytest

from agent.contracts import SessionState, action_name
from agent.policies import (
    AlwaysShowFakeFilePolicy,
    ShowFakeCredentialsAfterSuccessfulSessionPolicy,
    ShowFakeCredentialsOnLoginSuccessPolicy,
)
from agent.runtime import ActionDecision


def sample_session_summary(**overrides):
    data = {
        "session_id": "sess-123",
        "service": "ssh",
        "session_duration": 25.0,
        "command_count": 4,
        "unique_commands": 4,
        "login_attempts": 2,
        "login_success": True,
        "brute_force_detected": False,
        "files_downloaded": [],
        "ttp_count": 3,
        "session_active": True,
    }
    data.update(overrides)
    return data


def test_session_state_from_summary_matches_contract_shape():
    state = SessionState.from_session_summary(sample_session_summary())

    vector = state.to_numpy()
    assert vector.shape == (10,)
    assert vector.dtype == np.float32
    assert vector.tolist() == [25.0, 4.0, 4.0, 2.0, 1.0, 0.0, 0.0, 3.0, 1.0, 0.0]


def test_action_name_rejects_unknown_ids():
    with pytest.raises(KeyError):
        action_name(99)


def test_fake_file_policy_emits_action_for_successful_login():
    policy = AlwaysShowFakeFilePolicy()
    decision = policy.decide(sample_session_summary(), set(), episode=7)
    assert decision is not None
    assert decision.action_id == 2
    assert decision.policy_name == policy.name


def test_fake_credentials_policy_requires_active_successful_session():
    policy = ShowFakeCredentialsOnLoginSuccessPolicy()
    decision = policy.decide(sample_session_summary(), set(), episode=2)
    assert decision is not None
    assert decision.action_id == 4

    no_decision = policy.decide(
        sample_session_summary(login_success=False),
        set(),
        episode=2,
    )
    assert no_decision is None


def test_next_session_credentials_policy_requires_closed_successful_session():
    policy = ShowFakeCredentialsAfterSuccessfulSessionPolicy()
    decision = policy.decide(
        sample_session_summary(session_active=False),
        set(),
        episode=3,
    )
    assert decision is not None
    assert decision.action_id == 4
    assert decision.parameters["activation_scope"] == "next_session"

    no_decision = policy.decide(sample_session_summary(session_active=True), set(), episode=3)
    assert no_decision is None


def test_action_decision_has_deterministic_document_id():
    decision = ActionDecision(
        session_id="sess-123",
        action_id=4,
        policy_name="show_fake_credentials_on_login_success",
    )
    assert decision.document_id() == (
        "sess-123:show_fake_credentials:show_fake_credentials_on_login_success"
    )


def test_ppo_policy_registered_in_policies():
    from agent.policies import PPOPolicy, get_policy

    policy = get_policy("ppo")
    assert isinstance(policy, PPOPolicy)
    assert policy.name == "ppo"
    assert policy.consumes_active_sessions is False
    assert policy.consumes_closed_sessions is True


def test_ppo_policy_decide_without_model_returns_none():
    from agent.policies import PPOPolicy

    policy = PPOPolicy(model_path="/nonexistent/model.zip")
    decision = policy.decide(sample_session_summary(session_active=False), set())
    assert decision is None


def test_ppo_policy_decide_with_mock_model(monkeypatch):
    from agent.policies import PPOPolicy

    class FakeModel:
        def predict(self, observation, deterministic=True):
            return 4, None

    policy = PPOPolicy()
    monkeypatch.setattr(policy, "get_model", lambda: FakeModel())

    decision = policy.decide(
        sample_session_summary(session_active=False, login_success=True),
        existing_actions=set(),
        episode=5,
    )
    assert decision is not None
    assert decision.action_id == 4
    assert decision.policy_name == "ppo"
    assert decision.parameters["activation_scope"] == "next_session"
    assert decision.parameters["file_path"] == "/etc/passwd"
    assert decision.episode == 5
    assert decision.reward > 0.0


def test_ppo_policy_skips_duplicate_action(monkeypatch):
    from agent.policies import PPOPolicy

    class FakeModel:
        def predict(self, observation, deterministic=True):
            return 4, None

    policy = PPOPolicy()
    monkeypatch.setattr(policy, "get_model", lambda: FakeModel())

    decision = policy.decide(
        sample_session_summary(session_active=False),
        existing_actions={"show_fake_credentials"},
    )
    assert decision is None


def test_ppo_policy_ignores_active_sessions(monkeypatch):
    from agent.policies import PPOPolicy

    class FakeModel:
        def predict(self, observation, deterministic=True):
            return 4, None

    policy = PPOPolicy()
    monkeypatch.setattr(policy, "get_model", lambda: FakeModel())

    decision = policy.decide(
        sample_session_summary(session_active=True),
        existing_actions=set(),
    )
    assert decision is None

