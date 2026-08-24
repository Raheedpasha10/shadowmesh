"""Plain-English explanation helpers for the ShadowMesh dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class BaitFile:
    """Reviewer-friendly metadata for one generated bait artifact."""

    name: str
    attacker_path: str
    local_path: Path
    explanation: str


BAIT_FILES = [
    BaitFile(
        name="Linux user list",
        attacker_path="/etc/passwd",
        local_path=Path("generative/cache/passwd"),
        explanation="Fake user accounts that make the decoy server look populated.",
    ),
    BaitFile(
        name="Password hash file",
        attacker_path="/etc/shadow",
        local_path=Path("generative/cache/shadow"),
        explanation="Fake password hashes that attackers usually try to steal and crack.",
    ),
    BaitFile(
        name="Admin command history",
        attacker_path="/root/.bash_history",
        local_path=Path("generative/cache/bash_history.txt"),
        explanation="Fake admin mistakes and maintenance commands for attacker curiosity.",
    ),
    BaitFile(
        name="Web app database config",
        attacker_path="/var/www/html/config.php",
        local_path=Path("generative/cache/db_config.php"),
        explanation="Fake database credentials placed where web attackers normally look.",
    ),
    BaitFile(
        name="Application environment file",
        attacker_path="/opt/novapay/.env",
        local_path=Path("generative/cache/.env"),
        explanation="Fake cloud/API secrets used as high-value deception bait.",
    ),
    BaitFile(
        name="SSH private key",
        attacker_path="/home/admin/.ssh/id_rsa",
        local_path=Path("generative/cache/id_rsa"),
        explanation="Fake private key that suggests possible lateral movement.",
    ),
]


def explain_event_type(event_type: str | None) -> str:
    """Translate Cowrie event names into review-panel language."""
    labels = {
        "cowrie.session.connect": "Attacker connected to the fake SSH server.",
        "cowrie.login.failed": "Attacker tried a username/password and failed.",
        "cowrie.login.success": "Attacker successfully logged into the decoy.",
        "cowrie.command.input": "Attacker executed a command inside the honeypot.",
        "cowrie.session.file_download": "Attacker attempted to download a payload.",
        "cowrie.session.closed": "Attacker disconnected and the session ended.",
    }
    return labels.get(event_type or "", "Honeypot recorded an activity event.")


def explain_command(command: str | None) -> str:
    """Explain attacker commands without assuming cybersecurity background."""
    if not command:
        return "No command captured for this event."

    lowered = command.lower()
    if "cat /etc/passwd" in lowered:
        return "Account discovery: the attacker is checking which users exist."
    if "cat /etc/shadow" in lowered:
        return "Credential theft attempt: the attacker is looking for password hashes."
    if "wget" in lowered or "curl" in lowered:
        return "Payload download attempt: the attacker is trying to fetch a script/tool."
    if "netstat" in lowered or "ss " in lowered or "ifconfig" in lowered:
        return "Network reconnaissance: the attacker is checking open connections."
    if "ps aux" in lowered or "ps -ef" in lowered:
        return "Process discovery: the attacker is checking running programs."
    if "uname" in lowered or "hostname" in lowered or "/proc/version" in lowered:
        return "System reconnaissance: the attacker is identifying the machine."
    if lowered.startswith("ls") or " find " in f" {lowered} ":
        return "File discovery: the attacker is exploring directories and files."
    if "grep -e" in lowered and ("backupsvc" in lowered or "cloudsync" in lowered):
        return "Bait follow-up: the attacker noticed fake users and is investigating them."
    return "Post-login activity: the attacker is exploring the decoy system."


def classify_session(session: dict) -> tuple[str, str]:
    """Return a short attack label and a simple reviewer explanation."""
    commands = " ".join(session.get("commands", [])).lower()
    command_count = int(session.get("command_count", 0) or 0)
    login_attempts = int(session.get("login_attempts", 0) or 0)
    brute_force = bool(session.get("brute_force_detected"))
    login_success = bool(session.get("login_success")) or command_count > 0

    if brute_force or login_attempts >= 3:
        label = "SSH brute force"
        explanation = "The attacker tried multiple username/password combinations."
    elif login_success:
        label = "Successful SSH intrusion"
        explanation = "The attacker entered the fake server and started exploring."
    else:
        label = "SSH probing"
        explanation = "The attacker connected to SSH but did not fully enter the decoy."

    if "wget" in commands or "curl" in commands:
        label += " + payload attempt"
        explanation += " Later, they tried downloading an external script or tool."
    elif "/etc/shadow" in commands or "/etc/passwd" in commands:
        label += " + credential discovery"
        explanation += " They also looked for user and password-related files."

    return label, explanation


def explain_action(action_name: str | None) -> str:
    """Explain an adaptive action in plain language."""
    labels = {
        "do_nothing": "The agent observed the session but chose not to change the decoy.",
        "show_fake_file": "The agent exposed an extra fake file to increase attacker curiosity.",
        "show_fake_credentials": "The agent exposed fake credentials as believable bait.",
        "slow_response": "The agent would slow responses to mimic a busy real server.",
        "open_fake_port": "The agent would expose another fake service to extend interaction.",
    }
    return labels.get(action_name or "", "Adaptive decision recorded by the agent.")


def safe_preview(text: str, limit: int = 4000) -> str:
    """Return a bounded preview so huge rule or bait files do not freeze the UI."""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n\n... truncated for dashboard preview ..."
