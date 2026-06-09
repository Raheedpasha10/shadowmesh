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
    commands = ["cat /opt/novapay/.env", "ps aux"]
    queued_follow_ups: set[str] = set()

    _queue_follow_up_command(
        commands,
        queued_follow_ups,
        0,
        "cat /opt/novapay/.env",
        "AWS_ACCESS_KEY_ID=AKIA...\nrotation_marker=shadowmesh_live_credentials\n",
    )

    assert commands[1] == "grep AWS /opt/novapay/.env"
    assert "grep AWS /opt/novapay/.env" in queued_follow_ups


def test_queue_follow_up_command_ignores_missing_bait():
    commands = ["cat /opt/novapay/.env", "ps aux"]
    queued_follow_ups: set[str] = set()

    _queue_follow_up_command(
        commands,
        queued_follow_ups,
        0,
        "cat /opt/novapay/.env",
        "APP_ENV=production\nDB_HOST=10.10.24.12\n",
    )

    assert commands == ["cat /opt/novapay/.env", "ps aux"]


def test_drain_shell_output_collects_multiple_chunks():
    shell = FakeShell([b"rotation_marker=", b"shadowmesh_live_credentials\n$ "])

    output = _drain_shell_output(shell, settle_seconds=0.0, max_wait_seconds=0.1)

    assert "rotation_marker=shadowmesh_live_credentials" in output
