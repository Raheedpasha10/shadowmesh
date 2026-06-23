import sys
import types


sys.modules.setdefault("nmap", types.SimpleNamespace(PortScanner=object))
sys.modules.setdefault(
    "paramiko",
    types.SimpleNamespace(
        SSHClient=object,
        AutoAddPolicy=object,
        AuthenticationException=Exception,
        SSHException=Exception,
    ),
)

from attacker.simulate import _drain_shell_output, _queue_follow_up_command


class FakeShell:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv_ready(self):
        return bool(self.chunks)

    def recv(self, size):
        return self.chunks.pop(0)


def test_queue_follow_up_command_only_adds_bait_read_when_discovered():
    commands = ["cat /etc/passwd", "ps aux"]
    queued_follow_ups: set[str] = set()

    _queue_follow_up_command(
        commands,
        queued_follow_ups,
        0,
        "cat /etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\nbackupsvc:x:1004:1004:Backup Service:/var/backups:/bin/bash\n",
    )

    assert commands[1] == "grep -E 'backupsvc|cloudsync' /etc/passwd"
    assert "grep -E 'backupsvc|cloudsync' /etc/passwd" in queued_follow_ups


def test_queue_follow_up_command_ignores_missing_bait():
    commands = ["cat /etc/passwd", "ps aux"]
    queued_follow_ups: set[str] = set()

    _queue_follow_up_command(
        commands,
        queued_follow_ups,
        0,
        "cat /etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\nmysql:x:105:105:MySQL Server:/var/lib/mysql:/usr/sbin/nologin\n",
    )

    assert commands == ["cat /etc/passwd", "ps aux"]


def test_drain_shell_output_collects_multiple_chunks():
    shell = FakeShell([b"backupsvc:x:1004:", b"1004:Backup Service:/var/backups:/bin/bash\n$ "])

    output = _drain_shell_output(shell, settle_seconds=0.0, max_wait_seconds=0.1)

    assert "backupsvc:x:1004:1004:Backup Service" in output
