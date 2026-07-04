from agent.evaluate import _bait_access_sessions, _metric_rows, _render_markdown, _write_output


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
        _session(commands=["grep -E 'backupsvc|cloudsync' /etc/passwd"]),
        _session(commands=["grep -E 'backupsvc|cloudsync' /etc/passwd", "ls -la /etc"]),
        _session(commands=["cat /home/admin/loot/system_audit.txt"]),
        _session(commands=["cat /etc/passwd"]),
    ]

    assert _bait_access_sessions(sessions) == 3


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


def test_markdown_output_can_be_written(tmp_path):
    rows = _metric_rows([_session()], [_session(command_count=7, unique_commands=6)])
    content = _render_markdown(rows)
    output = tmp_path / "evaluation.md"

    _write_output(str(output), content)

    saved = output.read_text(encoding="utf-8")
    assert "| metric | baseline | adaptive | delta |" in saved
    assert "command_count" in saved
