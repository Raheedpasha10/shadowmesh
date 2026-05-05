"""Runtime helpers for the Phase 1 agent scaffold."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from elasticsearch import Elasticsearch

from agent.contracts import action_name

logger = logging.getLogger("shadowmesh-agent")


@dataclass(slots=True)
class ActionDecision:
    """Serializable action record for `honeypot-rl-actions`."""

    session_id: str
    action_id: int
    parameters: dict[str, Any] = field(default_factory=dict)
    reward: float = 0.0
    episode: int = 0

    def to_document(self) -> dict[str, Any]:
        """Convert the decision to the contract-defined Elasticsearch record."""
        return {
            "@timestamp": datetime.now(UTC).isoformat(),
            "session_id": self.session_id,
            "action_id": self.action_id,
            "action_name": action_name(self.action_id),
            "parameters": self.parameters,
            "reward": self.reward,
            "episode": self.episode,
        }


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
        self.es_client.index(index=self.index_name, document=document)
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
                }
            }
        }
        self.es_client.indices.create(index=self.index_name, body=mapping)
