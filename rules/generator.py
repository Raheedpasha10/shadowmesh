"""Generate Snort and YARA rules from honeypot session summaries.

This module reads contract-aligned session summaries from Elasticsearch,
derives a small set of practical detection rules, writes `.rules` and `.yar`
artifacts to the filesystem, and optionally indexes the generation record
into `honeypot-generated-rules`.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

logger = logging.getLogger("shadowmesh-rule-generator")

ROOT_DIR = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT_DIR / ".env"

DEFAULT_ES_HOST = "localhost"
DEFAULT_ES_PORT = 9200
DEFAULT_INDEX_SESSIONS = "honeypot-sessions"
DEFAULT_INDEX_RULES = "honeypot-generated-rules"
DEFAULT_RULES_OUTPUT_DIR = ROOT_DIR / "rules" / "output"
DEFAULT_SSH_SID_BASE = 9_000_001
DEFAULT_WEB_SID_BASE = 9_001_001
DEFAULT_DB_SID_BASE = 9_002_001

YARA_GENERATOR_NAME = "honeypot-rule-generator-v1"


@dataclass(slots=True)
class SessionSummary:
    """Subset of `honeypot-sessions` fields used by the rule generator."""

    timestamp: str
    session_id: str
    attacker_ip: str
    service: str
    session_duration: float
    login_attempts: int
    login_success: bool
    commands: list[str]
    command_count: int
    unique_commands: int
    files_downloaded: list[str]
    file_hashes: list[str]
    brute_force_detected: bool
    ttp_count: int
    usernames_tried: list[str]
    session_start: str | None
    session_end: str | None

    @classmethod
    def from_document(cls, document: dict) -> "SessionSummary":
        """Build a typed session summary from an Elasticsearch document."""
        return cls(
            timestamp=document.get("@timestamp", _utc_now()),
            session_id=document["session_id"],
            attacker_ip=document.get("attacker_ip", "0.0.0.0"),
            service=document.get("service", "ssh"),
            session_duration=float(document.get("session_duration", 0.0) or 0.0),
            login_attempts=int(document.get("login_attempts", 0) or 0),
            login_success=bool(document.get("login_success", False)),
            commands=[cmd for cmd in document.get("commands", []) if cmd],
            command_count=int(document.get("command_count", 0) or 0),
            unique_commands=int(document.get("unique_commands", 0) or 0),
            files_downloaded=[item for item in document.get("files_downloaded", []) if item],
            file_hashes=[item for item in document.get("file_hashes", []) if item],
            brute_force_detected=bool(document.get("brute_force_detected", False)),
            ttp_count=int(document.get("ttp_count", 0) or 0),
            usernames_tried=[
                item for item in document.get("usernames_tried", []) if item
            ],
            session_start=document.get("session_start"),
            session_end=document.get("session_end"),
        )


class SidAllocator:
    """Allocate Snort SIDs while respecting category-specific base ranges."""

    def __init__(
        self,
        output_root: Path,
        ssh_base: int,
        web_base: int,
        db_base: int,
    ) -> None:
        self.output_root = output_root
        self.base_by_service = {
            "ssh": ssh_base,
            "web": web_base,
            "db": db_base,
        }
        self._cache: dict[str, int] = {}

    def next_sid(self, service: str) -> int:
        """Return the next unique SID for the given service family."""
        key = service if service in self.base_by_service else "ssh"
        if key not in self._cache:
            self._cache[key] = self._scan_existing_max_sid(key)
        self._cache[key] += 1
        return self._cache[key]

    def _scan_existing_max_sid(self, service: str) -> int:
        base = self.base_by_service[service]
        highest = base - 1

        if not self.output_root.exists():
            return highest

        for rule_file in self.output_root.rglob("*.rules"):
            try:
                text = rule_file.read_text(encoding="utf-8")
            except OSError:
                continue

            for match in re.finditer(r"sid:(\d+);", text):
                sid = int(match.group(1))
                if sid >= base:
                    if service == "ssh" and sid < self.base_by_service["web"]:
                        highest = max(highest, sid)
                    elif service == "web" and sid < self.base_by_service["db"]:
                        highest = max(highest, sid)
                    elif service == "db":
                        highest = max(highest, sid)

        return highest


class RuleGenerator:
    """Generate Snort and YARA outputs for one honeypot session."""

    def __init__(self, sid_allocator: SidAllocator) -> None:
        self.sid_allocator = sid_allocator

    def generate(self, session: SessionSummary) -> dict:
        """Generate all outputs for a single session summary."""
        snort_rules = self._build_snort_rules(session)
        yara_rule = self._build_yara_rule(session)
        ttps = sorted(_map_ttp_ids(session.commands))

        return {
            "@timestamp": _utc_now(),
            "session_id": session.session_id,
            "attacker_ip": session.attacker_ip,
            "snort_rules": snort_rules,
            "yara_rules": [yara_rule],
            "rule_count": len(snort_rules) + 1,
            "ttps_captured": ttps,
        }

    def _build_snort_rules(self, session: SessionSummary) -> list[str]:
        service = _canonical_service(session.service)
        port = _service_port(service)
        rules: list[str] = []
        seen_signatures: set[str] = set()

        def add_rule(signature: str, rule_text: str) -> None:
            if signature in seen_signatures:
                return
            seen_signatures.add(signature)
            rules.append(rule_text)

        if session.brute_force_detected or session.login_attempts >= 3:
            sid = self.sid_allocator.next_sid(service)
            add_rule(
                "ssh_bruteforce",
                (
                    f'alert tcp {session.attacker_ip} any -> $HOME_NET {port} '
                    f'(msg:"Honeypot: {service.upper()} brute force from '
                    f'{session.attacker_ip}"; flow:to_server; sid:{sid}; rev:1;)'
                ),
            )

        command_patterns = [
            ("wget", "outbound wget attempt"),
            ("curl", "outbound curl attempt"),
            ("scp", "SCP transfer attempt"),
            ("ftp", "FTP transfer attempt"),
            ("cat /etc/shadow", "shadow file access attempt"),
            ("cat /etc/passwd", "passwd file access attempt"),
        ]

        combined_commands = " ".join(cmd.lower() for cmd in session.commands)
        for pattern, description in command_patterns:
            if pattern not in combined_commands:
                continue

            sid = self.sid_allocator.next_sid(service)
            add_rule(
                pattern,
                (
                    f'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} '
                    f'(msg:"Honeypot: {service.upper()} session with {description}"; '
                    f'flow:established,to_server; content:"{_escape_snort_content(pattern)}"; '
                    f'nocase; sid:{sid}; rev:1;)'
                ),
            )

        recon_signatures = [
            (("uname", "cat /proc/version", "hostname"), "system reconnaissance"),
            (("ps aux", "ps -ef", "top"), "process reconnaissance"),
            (("netstat", "ss ", "ifconfig", "ip addr"), "network reconnaissance"),
            (("ls ", "find "), "filesystem reconnaissance"),
        ]
        for patterns, description in recon_signatures:
            if not any(pattern in combined_commands for pattern in patterns):
                continue
            sid = self.sid_allocator.next_sid(service)
            add_rule(
                description,
                (
                    f'alert tcp $EXTERNAL_NET any -> $HOME_NET {port} '
                    f'(msg:"Honeypot: {service.upper()} session with {description}"; '
                    f'flow:established,to_server; content:"{_escape_snort_content(patterns[0].strip())}"; '
                    f'nocase; sid:{sid}; rev:1;)'
                ),
            )

        return rules

    def _build_yara_rule(self, session: SessionSummary) -> str:
        rule_name = f"Honeypot_Session_{_sanitize_identifier(session.session_id[:12])}"
        description = _session_description(session)
        date_value = (session.session_end or session.timestamp or _utc_now())[:10]

        command_lines = []
        for index, command in enumerate(session.commands[:10], start=1):
            command_lines.append(
                f'        $cmd{index} = "{_escape_yara_string(command)}"'
            )
        command_lines.append(
            f'        $ip = "{_escape_yara_string(session.attacker_ip)}"'
        )

        strings_block = "\n".join(command_lines)

        return (
            f"rule {rule_name} {{\n"
            f"    meta:\n"
            f'        description  = "{_escape_yara_string(description)}"\n'
            f'        date         = "{date_value}"\n'
            f'        session_id   = "{_escape_yara_string(session.session_id)}"\n'
            f'        attacker_ip  = "{_escape_yara_string(session.attacker_ip)}"\n'
            f'        generated_by = "{YARA_GENERATOR_NAME}"\n'
            f"    strings:\n"
            f"{strings_block}\n"
            f"    condition:\n"
            f"        any of ($cmd*) or $ip\n"
            f"}}"
        )


def load_settings() -> dict:
    """Load environment-backed settings for Elasticsearch and output paths."""
    load_dotenv(ENV_PATH)
    return {
        "es_host": os.getenv("ES_HOST", DEFAULT_ES_HOST),
        "es_port": int(os.getenv("ES_PORT", str(DEFAULT_ES_PORT))),
        "index_sessions": os.getenv("ES_INDEX_SESSIONS", DEFAULT_INDEX_SESSIONS),
        "index_rules": os.getenv("ES_INDEX_RULES", DEFAULT_INDEX_RULES),
        "output_dir": Path(
            os.getenv("RULES_OUTPUT_DIR", str(DEFAULT_RULES_OUTPUT_DIR))
        ),
        "sid_ssh_base": int(
            os.getenv("SNORT_SID_SSH_BASE", str(DEFAULT_SSH_SID_BASE))
        ),
        "sid_web_base": int(
            os.getenv("SNORT_SID_WEB_BASE", str(DEFAULT_WEB_SID_BASE))
        ),
        "sid_db_base": int(os.getenv("SNORT_SID_DB_BASE", str(DEFAULT_DB_SID_BASE))),
    }


def create_es_client(host: str, port: int) -> Elasticsearch:
    """Create an Elasticsearch client using HTTP."""
    if host.startswith("http://") or host.startswith("https://"):
        return Elasticsearch(host)
    return Elasticsearch(f"http://{host}:{port}")


def ensure_rules_index(client: Elasticsearch, index_name: str) -> None:
    """Ensure the generated-rules index exists before indexing documents."""
    if client.indices.exists(index=index_name):
        return

    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "session_id": {"type": "keyword"},
                "attacker_ip": {"type": "ip"},
                "snort_rules": {"type": "keyword"},
                "yara_rules": {"type": "keyword"},
                "rule_count": {"type": "integer"},
                "snort_file": {"type": "keyword"},
                "yara_file": {"type": "keyword"},
                "ttps_captured": {"type": "keyword"},
            }
        }
    }
    client.indices.create(index=index_name, body=mapping)
    logger.info("Created index: %s", index_name)


def fetch_session_documents(
    client: Elasticsearch,
    index_name: str,
    session_id: str | None,
    limit: int,
    *,
    include_active: bool = False,
) -> list[SessionSummary]:
    """Fetch one or more session summaries from Elasticsearch."""
    filters: list[dict[str, Any]] = []
    if session_id:
        filters.append({"term": {"session_id": session_id}})
    if not include_active:
        filters.append({"term": {"session_active": False}})

    query: dict[str, Any]
    if filters:
        query = {"bool": {"filter": filters}}
    else:
        query = {"match_all": {}}

    response = client.search(
        index=index_name,
        size=limit,
        sort=[{"@timestamp": {"order": "desc"}}],
        query=query,
    )
    return [
        SessionSummary.from_document(hit["_source"])
        for hit in response["hits"]["hits"]
    ]


def write_rule_files(output_root: Path, record: dict) -> tuple[str, str]:
    """Write Snort and YARA artifacts to the contract-defined location."""
    timestamp = record["@timestamp"]
    date_segment = timestamp[:10]
    session_id = record["session_id"]
    directory = output_root / date_segment
    directory.mkdir(parents=True, exist_ok=True)

    snort_path = directory / f"session_{session_id}.rules"
    yara_path = directory / f"session_{session_id}.yar"

    snort_path.write_text("\n".join(record["snort_rules"]) + "\n", encoding="utf-8")
    yara_path.write_text("\n\n".join(record["yara_rules"]) + "\n", encoding="utf-8")

    return str(snort_path), str(yara_path)


def index_rule_record(
    client: Elasticsearch,
    index_name: str,
    record: dict,
) -> None:
    """Store the generation record in Elasticsearch."""
    client.index(index=index_name, id=record["session_id"], document=record)


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for rule generation."""
    parser = argparse.ArgumentParser(
        description="Generate Snort and YARA rules from honeypot session summaries."
    )
    parser.add_argument(
        "--session-id",
        help="Generate rules for a specific session ID. Defaults to the latest sessions.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=1,
        help="Number of sessions to fetch when --session-id is not provided.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the generated rule record instead of writing to Elasticsearch.",
    )
    parser.add_argument(
        "--include-active",
        action="store_true",
        help="Allow rule generation from still-active sessions.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args()


def main() -> int:
    """CLI entry point."""
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    settings = load_settings()
    client = create_es_client(settings["es_host"], settings["es_port"])
    ensure_rules_index(client, settings["index_rules"])

    sessions = fetch_session_documents(
        client=client,
        index_name=settings["index_sessions"],
        session_id=args.session_id,
        limit=args.limit,
        include_active=args.include_active,
    )
    if not sessions:
        logger.error("No session summaries found for rule generation.")
        return 1

    sid_allocator = SidAllocator(
        output_root=settings["output_dir"],
        ssh_base=settings["sid_ssh_base"],
        web_base=settings["sid_web_base"],
        db_base=settings["sid_db_base"],
    )
    generator = RuleGenerator(sid_allocator=sid_allocator)

    for session in sessions:
        record = generator.generate(session)
        snort_file, yara_file = write_rule_files(settings["output_dir"], record)
        record["snort_file"] = snort_file
        record["yara_file"] = yara_file

        if args.dry_run:
            print(json.dumps(record, indent=2))
            continue

        index_rule_record(client, settings["index_rules"], record)
        logger.info(
            "Generated %s rules for session %s",
            record["rule_count"],
            record["session_id"],
        )

    return 0


def _canonical_service(service: str) -> str:
    if service in {"ssh", "web", "db"}:
        return service
    return "ssh"


def _service_port(service: str) -> int:
    return {
        "ssh": 22,
        "web": 80,
        "db": 3306,
    }[_canonical_service(service)]


def _map_ttp_ids(commands: list[str]) -> set[str]:
    combined = " ".join(commands).lower()
    patterns = {
        "T1059.004": ["bash", "sh ", "python", "perl", "ruby"],
        "T1087.001": ["cat /etc/passwd", "cat /etc/shadow", "id", "whoami"],
        "T1082": ["uname", "hostname", "cat /proc/version"],
        "T1049": ["netstat", "ss ", "ifconfig", "ip addr"],
        "T1057": ["ps aux", "ps -ef", "top"],
        "T1105": ["wget", "curl", "scp", "ftp"],
        "T1053.003": ["cron", "crontab"],
        "T1083": ["ls ", "find ", "ls -la", "dir"],
    }
    return {
        ttp
        for ttp, options in patterns.items()
        if any(option in combined for option in options)
    }


def _session_description(session: SessionSummary) -> str:
    details = []
    if session.brute_force_detected:
        details.append("performed SSH brute force")
    if any("wget" in command or "curl" in command for command in session.commands):
        details.append("attempted to download a payload")
    if any("/etc/shadow" in command for command in session.commands):
        details.append("accessed credential material")
    if not details:
        details.append("performed post-login reconnaissance")
    return "Attacker " + " then ".join(details)


def _escape_snort_content(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _escape_yara_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _sanitize_identifier(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value)
    return cleaned or "unknown"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
