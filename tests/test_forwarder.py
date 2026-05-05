import importlib.util
from pathlib import Path


_FORWARDER_PATH = Path(__file__).resolve().parents[1] / "logging" / "forwarder.py"
_SPEC = importlib.util.spec_from_file_location("shadowmesh_forwarder", _FORWARDER_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
SessionAggregator = _MODULE.SessionAggregator


def _event(eventid, **extra):
    event = {
        "eventid": eventid,
        "session": "abc123",
        "src_ip": "172.18.0.5",
        "timestamp": "2026-05-05T10:00:00Z",
    }
    event.update(extra)
    return event


def test_session_aggregator_emits_live_and_final_summaries():
    aggregator = SessionAggregator()

    live_summary, closed = aggregator.ingest(_event("cowrie.session.connect"))
    assert closed is False
    assert live_summary["session_active"] is True
    assert live_summary["command_count"] == 0

    live_summary, closed = aggregator.ingest(
        _event("cowrie.login.success", username="admin")
    )
    assert closed is False
    assert live_summary["login_success"] is True

    live_summary, closed = aggregator.ingest(
        _event("cowrie.command.input", input="cat /etc/passwd")
    )
    assert closed is False
    assert live_summary["command_count"] == 1
    assert live_summary["ttp_count"] >= 1

    final_summary, closed = aggregator.ingest(
        _event("cowrie.session.closed", duration=12.5)
    )
    assert closed is True
    assert final_summary["session_active"] is False
    assert final_summary["session_end"] == "2026-05-05T10:00:00Z"
    assert final_summary["session_duration"] == 12.5
