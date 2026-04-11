"""
logging/forwarder.py

Cowrie → Elasticsearch log forwarder.

Continuously tails cowrie.json, normalizes each event to the schema
defined in data_contracts.md (Section 3), and indexes it into Elasticsearch.

When a cowrie.session.closed event is received, it also builds and indexes
a session summary document into honeypot-sessions for the RL agent to read.

Usage:
  python forwarder.py

Environment variables (see .env.example):
  ES_HOST          Elasticsearch base URL  (default: http://localhost:9200)
  COWRIE_LOG_PATH  Path to cowrie.json     (default: /logs/cowrie.json)
"""

import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError as ESConnectionError
from elasticsearch.exceptions import TransportError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("logging.forwarder")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
COWRIE_LOG_PATH = Path(os.getenv("COWRIE_LOG_PATH", "/logs/cowrie.json"))

INDEX_EVENTS = "honeypot-cowrie-events"
INDEX_SESSIONS = "honeypot-sessions"

# How long to wait between polling cowrie.json for new lines (seconds)
POLL_INTERVAL = 2.0


# ---------------------------------------------------------------------------
# Elasticsearch setup
# ---------------------------------------------------------------------------

def connect_elasticsearch(host: str, retries: int = 10, delay: float = 5.0) -> Elasticsearch:
    """Connect to Elasticsearch with retry logic.

    Args:
        host: Elasticsearch base URL.
        retries: Maximum number of connection attempts.
        delay: Seconds to wait between attempts.

    Returns:
        Connected Elasticsearch client.

    Raises:
        SystemExit: If connection cannot be established after all retries.
    """
    for attempt in range(1, retries + 1):
        try:
            client = Elasticsearch(host)
            info = client.info()
            logger.info(
                "Connected to Elasticsearch %s (cluster: %s)",
                info["version"]["number"],
                info["cluster_name"],
            )
            return client
        except ESConnectionError as exc:
            logger.warning(
                "Elasticsearch not ready — attempt %d/%d: %s", attempt, retries, exc
            )
            time.sleep(delay)

    logger.error("Could not connect to Elasticsearch after %d attempts. Exiting.", retries)
    raise SystemExit(1)


def create_index_mappings(client: Elasticsearch) -> None:
    """Create Elasticsearch index mappings if they don't already exist.

    Explicit mappings prevent type conflicts and ensure fields like IP
    addresses and timestamps behave correctly in Kibana.

    Args:
        client: Connected Elasticsearch client.
    """
    # --- honeypot-cowrie-events mapping ---
    events_mapping = {
        "mappings": {
            "properties": {
                "@timestamp":   {"type": "date"},
                "event_type":   {"type": "keyword"},
                "session_id":   {"type": "keyword"},
                "attacker_ip":  {"type": "ip"},
                "service":      {"type": "keyword"},
                "sensor":       {"type": "keyword"},
                "command":      {"type": "text"},
                "username":     {"type": "keyword"},
                "password":     {"type": "keyword"},
                "duration":     {"type": "float"},
                "file_hash":    {"type": "keyword"},
                "raw_message":  {"type": "text"},
            }
        }
    }

    # --- honeypot-sessions mapping ---
    sessions_mapping = {
        "mappings": {
            "properties": {
                "@timestamp":           {"type": "date"},
                "session_id":           {"type": "keyword"},
                "attacker_ip":          {"type": "ip"},
                "service":              {"type": "keyword"},
                "session_duration":     {"type": "float"},
                "login_attempts":       {"type": "integer"},
                "login_success":        {"type": "boolean"},
                "commands":             {"type": "keyword"},
                "command_count":        {"type": "integer"},
                "unique_commands":      {"type": "integer"},
                "files_downloaded":     {"type": "keyword"},
                "file_hashes":          {"type": "keyword"},
                "brute_force_detected": {"type": "boolean"},
                "usernames_tried":      {"type": "keyword"},
                "session_start":        {"type": "date"},
                "session_end":          {"type": "date"},
            }
        }
    }

    for index, mapping in [
        (INDEX_EVENTS, events_mapping),
        (INDEX_SESSIONS, sessions_mapping),
    ]:
        if not client.indices.exists(index=index):
            client.indices.create(index=index, body=mapping)
            logger.info("Created index: %s", index)
        else:
            logger.info("Index already exists: %s", index)


# ---------------------------------------------------------------------------
# Event normalization — per data_contracts.md Section 3
# ---------------------------------------------------------------------------

def normalize_event(raw: dict) -> dict:
    """Normalize a raw Cowrie event to the data_contracts.md schema.

    Fields that don't apply to a specific event type are set to null
    (never omitted) so Elasticsearch queries don't break.

    Args:
        raw: Raw JSON event dict from cowrie.json.

    Returns:
        Normalized document ready for Elasticsearch indexing.
    """
    return {
        "@timestamp":  raw.get("timestamp"),
        "event_type":  raw.get("eventid"),
        "session_id":  raw.get("session"),
        "attacker_ip": raw.get("src_ip"),
        "service":     "ssh",   # extend to "web" when DVWA is added
        "sensor":      raw.get("sensor"),
        "command":     raw.get("input"),                          # cowrie.command.input only
        "username":    raw.get("username"),                       # login events only
        "password":    raw.get("password"),                       # login events only
        "duration":    _to_float(raw.get("duration")),            # session.closed only
        "file_hash":   raw.get("shasum"),                         # file download only
        "raw_message": raw.get("message"),
    }


def _to_float(value: object) -> float | None:
    """Safely convert a value to float.

    Args:
        value: Input value to convert.

    Returns:
        Float value or None if conversion fails.
    """
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Session aggregation — builds honeypot-sessions documents
# ---------------------------------------------------------------------------

class SessionAggregator:
    """Tracks in-progress sessions and emits summaries on session close.

    Accumulates events keyed by session_id until a cowrie.session.closed
    event is seen, then produces a session summary document for Elasticsearch.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, dict] = defaultdict(lambda: {
            "attacker_ip":      None,
            "service":          "ssh",
            "login_attempts":   0,
            "login_success":    False,
            "commands":         [],
            "files_downloaded": [],
            "file_hashes":      [],
            "usernames_tried":  [],
            "session_start":    None,
            "session_end":      None,
            "duration":         0.0,
        })

    def ingest(self, raw: dict) -> dict | None:
        """Process one raw Cowrie event and return a session summary if ready.

        Args:
            raw: Raw JSON event from cowrie.json.

        Returns:
            Session summary dict if the session just closed, else None.
        """
        event_id = raw.get("eventid", "")
        session_id = raw.get("session", "")
        state = self._sessions[session_id]

        if not state["attacker_ip"]:
            state["attacker_ip"] = raw.get("src_ip")

        if not state["session_start"]:
            state["session_start"] = raw.get("timestamp")

        if event_id == "cowrie.login.failed":
            state["login_attempts"] += 1
            username = raw.get("username")
            if username and username not in state["usernames_tried"]:
                state["usernames_tried"].append(username)

        elif event_id == "cowrie.login.success":
            state["login_attempts"] += 1
            state["login_success"] = True
            username = raw.get("username")
            if username and username not in state["usernames_tried"]:
                state["usernames_tried"].append(username)

        elif event_id == "cowrie.command.input":
            cmd = raw.get("input", "").strip()
            if cmd:
                state["commands"].append(cmd)

        elif event_id == "cowrie.session.file_download":
            url = raw.get("url", raw.get("outfile", ""))
            shasum = raw.get("shasum")
            if url:
                state["files_downloaded"].append(url)
            if shasum and shasum not in state["file_hashes"]:
                state["file_hashes"].append(shasum)

        elif event_id == "cowrie.session.closed":
            state["session_end"] = raw.get("timestamp")
            state["duration"] = _to_float(raw.get("duration")) or 0.0

            summary = self._build_summary(session_id, state)
            del self._sessions[session_id]
            return summary

        return None

    def _build_summary(self, session_id: str, state: dict) -> dict:
        """Build the final session summary document.

        Args:
            session_id: Unique session identifier.
            state: Accumulated session state.

        Returns:
            Session summary document matching data_contracts.md Section 3.
        """
        commands = state["commands"]
        return {
            "@timestamp":           state["session_end"] or datetime.now(timezone.utc).isoformat(),
            "session_id":           session_id,
            "attacker_ip":          state["attacker_ip"],
            "service":              state["service"],
            "session_duration":     state["duration"],
            "login_attempts":       state["login_attempts"],
            "login_success":        state["login_success"],
            "commands":             commands,
            "command_count":        len(commands),
            "unique_commands":      len(set(commands)),
            "files_downloaded":     state["files_downloaded"],
            "file_hashes":          state["file_hashes"],
            "brute_force_detected": state["login_attempts"] > 3,
            "ttp_count":            _estimate_ttp_count(commands),
            "usernames_tried":      state["usernames_tried"],
            "session_start":        state["session_start"],
            "session_end":          state["session_end"],
        }


def _estimate_ttp_count(commands: list[str]) -> int:
    """Estimate the number of distinct MITRE ATT&CK TTP categories observed.

    Maps command patterns to TTP categories. This is a heuristic for Phase 1;
    proper MITRE mapping is added in the rule generator module.

    Args:
        commands: List of commands the attacker ran.

    Returns:
        Count of distinct TTP categories detected.
    """
    ttp_patterns = {
        "T1059.004":  ["bash", "sh ", "python", "perl", "ruby"],   # scripting
        "T1087.001":  ["cat /etc/passwd", "cat /etc/shadow", "id", "whoami"],  # account discovery
        "T1082":      ["uname", "hostname", "cat /proc/version"],   # system info
        "T1049":      ["netstat", "ss ", "ifconfig", "ip addr"],    # network connections
        "T1057":      ["ps aux", "ps -ef", "top"],                  # process discovery
        "T1105":      ["wget", "curl", "scp", "ftp"],               # file transfer
        "T1053.003":  ["cron", "crontab"],                          # scheduled tasks
        "T1083":      ["ls ", "find ", "ls -la", "dir"],            # file discovery
    }

    detected = set()
    combined = " ".join(commands).lower()

    for ttp, patterns in ttp_patterns.items():
        if any(p in combined for p in patterns):
            detected.add(ttp)

    return len(detected)


# ---------------------------------------------------------------------------
# File tail — reads new lines from cowrie.json as they appear
# ---------------------------------------------------------------------------

def tail_file(path: Path):
    """Generator that yields new lines from a file as they are written.

    Seeks to the end of the file on first call, then polls for new content.
    Handles file rotation (cowrie rotates logs daily) by re-opening if needed.

    Args:
        path: Path to the log file to tail.

    Yields:
        New lines from the file as strings.
    """
    # Wait for the file to exist before starting
    while not path.exists():
        logger.info("Waiting for %s to appear...", path)
        time.sleep(5)

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        # Seek to end — don't re-process historical events on restart
        # (change to fh.seek(0) if you want to replay all existing logs)
        fh.seek(0, 2)
        logger.info("Tailing %s from current end-of-file", path)

        while True:
            line = fh.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    """Connect to Elasticsearch and forward Cowrie events indefinitely."""
    logger.info("Cowrie → Elasticsearch forwarder starting")
    logger.info("Log source : %s", COWRIE_LOG_PATH)
    logger.info("Destination: %s", ES_HOST)

    client = connect_elasticsearch(ES_HOST)
    create_index_mappings(client)
    aggregator = SessionAggregator()

    events_indexed = 0

    for line in tail_file(COWRIE_LOG_PATH):
        if not line:
            continue

        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning("Skipping malformed JSON line: %s — %s", exc, line[:80])
            continue

        # Index the normalized event
        try:
            doc = normalize_event(raw)
            client.index(index=INDEX_EVENTS, document=doc)
            events_indexed += 1

            if events_indexed % 50 == 0:
                logger.info("Events indexed so far: %d", events_indexed)

        except TransportError as exc:
            logger.error("Failed to index event: %s", exc)
            continue

        # Check if a session summary should be emitted
        session_summary = aggregator.ingest(raw)
        if session_summary:
            try:
                client.index(
                    index=INDEX_SESSIONS,
                    id=session_summary["session_id"],   # use session_id as doc ID
                    document=session_summary,
                )
                logger.info(
                    "Session summary indexed — id: %s | commands: %d | ttps: %d",
                    session_summary["session_id"],
                    session_summary["command_count"],
                    session_summary["ttp_count"],
                )
            except TransportError as exc:
                logger.error("Failed to index session summary: %s", exc)


if __name__ == "__main__":
    main()
