from agent.evaluate import _bait_access_sessions, _metric_rows


def _session(**overrides):
    data = {
        "session_duration": 30.0,
        "command_count": 5,
        "unique_commands": 4,
        "ttp_count": 2,
        "commands": ["cat /etc/passwd"],
        "files_downloaded": [],
    }
    data.update(overrides)
    return data


def test_bait_access_sessions_detects_adaptive_loot_paths():
    sessions = [
        _session(commands=["grep AWS /opt/novapay/.env"]),
        _session(commands=["grep AWS /opt/novapay/.env", "ls /var/www"]),
        _session(commands=["cat /etc/passwd"]),
    ]

    assert _bait_access_sessions(sessions) == 2


def test_metric_rows_include_payload_and_bait_metrics():
    baseline = [_session(files_downloaded=[])]
    adaptive = [
        _session(
            commands=["cat /home/admin/.aws/credentials"],
            files_downloaded=["http://203.0.113.10/payload"],
        )
    ]

    rows = _metric_rows(baseline, adaptive)
    row_names = [row[0] for row in rows]

    assert "bait_access_sessions" in row_names
    assert "payload_attempts" in row_names
