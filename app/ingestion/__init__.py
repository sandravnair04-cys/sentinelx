"""Central log ingestion engine for SXUF forwarders.

This package is deliberately separate from the analyst-facing API. Agent
credentials are scoped to ``ingest`` and ``heartbeat`` only; they can never
read events, approve responses or modify users.
"""

from .auth import generate_agent_key, hash_agent_key, require_agent
from .service import ingest_forwarded_batch

__all__ = ["generate_agent_key", "hash_agent_key", "require_agent", "ingest_forwarded_batch"]
