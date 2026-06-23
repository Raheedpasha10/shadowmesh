from datetime import datetime, timedelta, timezone

from agent.executor import _adaptive_passwd, _is_fresh_action


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


def test_adaptive_passwd_adds_bait_accounts_only_once():
    base = "root:x:0:0:root:/root:/bin/bash\n"

    once = _adaptive_passwd(base, "sess-1")
    twice = _adaptive_passwd(once, "sess-2")

    assert once.count("backupsvc:x:1004:1004:Backup Service:/var/backups:/bin/bash") == 1
    assert once.count("cloudsync:x:1005:1005:Cloud Sync:/srv/cloudsync:/bin/bash") == 1
    assert twice.count("backupsvc:x:1004:1004:Backup Service:/var/backups:/bin/bash") == 1
    assert twice.count("cloudsync:x:1005:1005:Cloud Sync:/srv/cloudsync:/bin/bash") == 1
