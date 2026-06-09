from datetime import datetime, timedelta, timezone

from agent.executor import _is_fresh_action


def test_is_fresh_action_rejects_actions_older_than_executor_start():
    started_at = datetime(2026, 6, 9, 12, 0, 0, tzinfo=timezone.utc)
    stale_action = {
        "@timestamp": (started_at - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    }

    assert _is_fresh_action(stale_action, started_at) is False


def test_is_fresh_action_accepts_actions_created_after_executor_start():
    started_at = datetime(2026, 6, 9, 12, 0, 0, tzinfo=timezone.utc)
    fresh_action = {
        "@timestamp": (started_at + timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    }

    assert _is_fresh_action(fresh_action, started_at) is True
