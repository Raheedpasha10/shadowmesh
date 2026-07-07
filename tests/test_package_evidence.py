from agent.package_evidence import _report_text


def _session(commands, **overrides):
    data = {
        "login_success": True,
        "session_duration": 20.0,
        "command_count": 6,
        "unique_commands": 6,
        "commands": commands,
    }
    data.update(overrides)
    return data


def test_report_text_includes_core_sections():
    baseline_sessions = [_session(["cat /etc/passwd"], command_count=5, unique_commands=5)]
    adaptive_sessions = [
        _session(
            [
                "cat /etc/passwd",
                "grep -E 'backupsvc|cloudsync' /etc/passwd",
            ],
            command_count=7,
            unique_commands=7,
        )
    ]

    report = _report_text(
        title="ShadowMesh Evidence Summary",
        baseline_sessions=baseline_sessions,
        adaptive_sessions=adaptive_sessions,
        evaluation_markdown="| metric | baseline | adaptive | delta |\n",
        policy_markdown="| policy | sessions | avg_reward | top_action | action_breakdown |\n",
    )

    assert "# ShadowMesh Evidence Summary" in report
    assert "Adaptive bait-follow-up sessions observed: `1`" in report
    assert "## Evaluation Table" in report
    assert "## Policy Comparison" in report
    assert "`grep -E 'backupsvc|cloudsync' /etc/passwd` appeared in `1` adaptive sessions" in report
