from agent.compare_policies import _builtin_policy_summary, _render_markdown


def _session(**overrides):
    data = {
        "session_id": "sess-1",
        "login_success": True,
        "session_active": False,
        "session_duration": 20.0,
        "command_count": 6,
        "ttp_count": 2,
        "files_downloaded": [],
    }
    data.update(overrides)
    return data


def test_builtin_policy_summary_counts_actions_and_rewards():
    summary = _builtin_policy_summary(
        [_session(), _session(session_id="sess-2")],
        "show_fake_credentials_after_successful_session",
        limit=2,
    )

    assert summary["policy_name"] == "show_fake_credentials_after_successful_session"
    assert summary["sessions_evaluated"] == 2
    assert summary["top_action"] == "show_fake_credentials"
    assert summary["action_breakdown"]["show_fake_credentials"] == 2
    assert summary["average_reward"] > 0


def test_render_markdown_contains_policy_rows():
    rendered = _render_markdown(
        [
            {
                "policy_name": "do_nothing",
                "sessions_evaluated": 2,
                "average_reward": 10.0,
                "top_action": "do_nothing",
                "action_breakdown": {"do_nothing": 2},
            }
        ]
    )

    assert "| policy | sessions | avg_reward | top_action | action_breakdown |" in rendered
    assert "| do_nothing | 2 | 10.00 | do_nothing | do_nothing:2 |" in rendered
