from argparse import Namespace
from pathlib import Path

from agent.collect_evidence import _dataset_summary, _manifest, _write_json


def _session(**overrides):
    data = {
        "@timestamp": "2026-07-04T10:00:00Z",
        "session_id": "abc123",
        "login_success": True,
        "command_count": 6,
    }
    data.update(overrides)
    return data


def test_dataset_summary_reports_basic_counts():
    summary = _dataset_summary(
        "baseline",
        [_session(command_count=4), _session(session_id="b", login_success=False, command_count=2)],
        "2026-07-04T10:00:00Z",
        "2026-07-04T10:05:00Z",
    )

    assert summary["name"] == "baseline"
    assert summary["session_count"] == 2
    assert summary["login_success_count"] == 1
    assert summary["average_command_count"] == 3.0


def test_manifest_includes_paths_and_collection_settings(tmp_path):
    args = Namespace(
        limit=25,
        min_command_count=1,
        login_success_only=True,
        baseline_since="2026-07-04T10:00:00Z",
        baseline_until="2026-07-04T10:05:00Z",
        adaptive_since="2026-07-04T10:10:00Z",
        adaptive_until="2026-07-04T10:15:00Z",
    )
    manifest = _manifest(
        baseline=[_session()],
        adaptive=[_session(session_id="def456", command_count=8)],
        args=args,
        baseline_path=tmp_path / "baseline_sessions.json",
        adaptive_path=tmp_path / "adaptive_sessions.json",
        evaluation_path=tmp_path / "evaluation.md",
    )

    assert manifest["collection"]["limit"] == 25
    assert manifest["baseline"]["session_count"] == 1
    assert manifest["adaptive"]["average_command_count"] == 8.0
    assert manifest["evaluation_path"].endswith("evaluation.md")


def test_write_json_creates_parent_directories(tmp_path):
    output = tmp_path / "nested" / "manifest.json"

    _write_json(output, {"status": "ok"})

    assert output.exists()
    assert '"status": "ok"' in output.read_text(encoding="utf-8")
