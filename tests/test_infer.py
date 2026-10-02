import json

from agent.infer import _run_builtin_policy, _run_ppo_policy


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


def test_run_ppo_policy_outputs_json_lines(capsys):
    sessions = [
        {
            "session_id": "sess-ppo-test",
            "login_success": True,
            "session_active": False,
            "session_duration": 20.0,
            "command_count": 6,
            "unique_commands": 6,
            "login_attempts": 2,
            "brute_force_detected": False,
            "ttp_count": 2,
            "files_downloaded": [],
            "service": "ssh",
        }
    ]

    exit_code = _run_ppo_policy(
        sessions,
        "agent/models/shadowmesh_ppo_adaptive.zip",
        limit=1,
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert exit_code == 0
    assert payload["session_id"] == "sess-ppo-test"
    assert payload["policy_name"] == "ppo"
    assert "action_name" in payload
    assert "reward" in payload

