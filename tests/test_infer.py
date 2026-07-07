import json

from agent.infer import _run_builtin_policy


def test_run_builtin_policy_outputs_json_lines(capsys):
    sessions = [
        {
            "session_id": "sess-1",
            "login_success": True,
            "session_active": False,
            "session_duration": 20.0,
            "command_count": 6,
            "ttp_count": 2,
            "files_downloaded": [],
        }
    ]

    exit_code = _run_builtin_policy(
        sessions,
        "show_fake_credentials_after_successful_session",
        limit=1,
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert exit_code == 0
    assert payload["session_id"] == "sess-1"
    assert payload["action_name"] == "show_fake_credentials"
    assert payload["policy_name"] == "show_fake_credentials_after_successful_session"
