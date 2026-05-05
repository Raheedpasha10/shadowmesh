"""Runtime helpers for the Phase 1 adaptive layer."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

from agent.contracts import action_name

logger = logging.getLogger("shadowmesh-agent")

ROOT_DIR = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT_DIR / ".env"


@dataclass(slots=True)
class ActionDecision:
    """Serializable action record for `honeypot-rl-actions`."""

    session_id: str
    action_id: int
    parameters: dict[str, Any] = field(default_factory=dict)
    reward: float = 0.0
    episode: int = 0
    policy_name: str = "manual"

    def to_document(self) -> dict[str, Any]:
        """Convert the decision to the contract-defined Elasticsearch record."""
        return {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "action_id": self.action_id,
            "action_name": action_name(self.action_id),
            "parameters": self.parameters,
            "reward": self.reward,
            "episode": self.episode,
            "policy_name": self.policy_name,
        }

    def document_id(self) -> str:
        """Return a deterministic document ID for idempotent logging."""
        return f"{self.session_id}:{action_name(self.action_id)}:{self.policy_name}"


class ActionLogger:
    """Write action decisions to Elasticsearch or fall back to local logs."""

    def __init__(self, es_client: Elasticsearch | None, index_name: str) -> None:
        self.es_client = es_client
        self.index_name = index_name

    def log(self, decision: ActionDecision) -> dict[str, Any]:
        """Persist one decision and return the stored document."""
        document = decision.to_document()
        if self.es_client is None:
            logger.info("Agent decision: %s", document)
            return document

        self._ensure_index()
        self.es_client.index(
            index=self.index_name,
            id=decision.document_id(),
            document=document,
        )
        logger.info(
            "Logged RL action %s for session %s",
            document["action_name"],
            document["session_id"],
        )
        return document

    def _ensure_index(self) -> None:
        assert self.es_client is not None
        if self.es_client.indices.exists(index=self.index_name):
            return

        mapping = {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "session_id": {"type": "keyword"},
                    "action_id": {"type": "integer"},
                    "action_name": {"type": "keyword"},
                    "parameters": {"type": "object", "enabled": True},
                    "reward": {"type": "float"},
                    "episode": {"type": "integer"},
                    "policy_name": {"type": "keyword"},
                }
            }
        }
        self.es_client.indices.create(index=self.index_name, body=mapping)


def load_settings() -> dict[str, Any]:
    """Load shared adaptive-layer settings from the root .env file."""
    load_dotenv(ENV_PATH)
    es_host = os.getenv("ES_HOST", "localhost")
    if es_host.startswith("http://") or es_host.startswith("https://"):
        es_url = es_host
    else:
        es_url = f"http://{es_host}:{os.getenv('ES_PORT', '9200')}"
    return {
        "es_url": es_url,
        "sessions_index": os.getenv("ES_INDEX_SESSIONS", "honeypot-sessions"),
        "actions_index": os.getenv("ES_INDEX_ACTIONS", "honeypot-rl-actions"),
        "rules_index": os.getenv("ES_INDEX_RULES", "honeypot-generated-rules"),
        "agent_policy": os.getenv(
            "AGENT_POLICY",
            "show_fake_credentials_on_login_success",
        ),
        "agent_poll_interval": float(
            os.getenv("AGENT_POLL_INTERVAL_SECONDS", "1.0")
        ),
        "action_executor_poll_interval": float(
            os.getenv("ACTION_EXECUTOR_POLL_INTERVAL_SECONDS", "1.0")
        ),
        "action_loot_dir": os.getenv("ACTION_LOOT_DIR", "/actions/loot"),
        "action_aws_dir": os.getenv("ACTION_AWS_DIR", "/actions/aws"),
        "ppo_model_dir": os.getenv("PPO_MODEL_DIR", "agent/models"),
    }


def create_es_client(es_url: str) -> Elasticsearch:
    """Create an Elasticsearch client from a base URL."""
    return Elasticsearch(es_url)


def fetch_session_summaries(
    client: Elasticsearch,
    index_name: str,
    *,
    session_id: str | None = None,
    active_only: bool = False,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Fetch recent session summaries for rule generation or agent decisions."""
    filters: list[dict[str, Any]] = []
    if session_id:
        filters.append({"term": {"session_id": session_id}})
    if active_only:
        filters.append({"term": {"session_active": True}})

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
    return [hit["_source"] for hit in response["hits"]["hits"]]


def fetch_action_names_for_session(
    client: Elasticsearch,
    index_name: str,
    session_id: str,
) -> set[str]:
    """Return the set of action names already logged for a given session."""
    if not client.indices.exists(index=index_name):
        return set()

    response = client.search(
        index=index_name,
        size=100,
        query={"term": {"session_id": session_id}},
    )
    return {
        hit["_source"].get("action_name")
        for hit in response["hits"]["hits"]
        if hit["_source"].get("action_name")
    }


def fetch_recent_actions(
    client: Elasticsearch,
    index_name: str,
    *,
    limit: int = 50,
    action_names: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Fetch recent action documents, optionally filtered by action name."""
    if not client.indices.exists(index=index_name):
        return []

    query: dict[str, Any] = {"match_all": {}}
    if action_names:
        query = {"terms": {"action_name": action_names}}

    response = client.search(
        index=index_name,
        size=limit,
        sort=[{"@timestamp": {"order": "desc"}}],
        query=query,
    )
    return [
        {"_id": hit["_id"], **hit["_source"]}
        for hit in response["hits"]["hits"]
    ]
