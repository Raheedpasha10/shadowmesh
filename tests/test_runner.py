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
