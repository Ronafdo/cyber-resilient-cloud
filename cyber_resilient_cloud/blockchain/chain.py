"""Simple hash-linked blockchain for append-only audit logging.

This module provides a lightweight chain implementation that can be used by the
shield, vault, and API layers to record security events and audit trails.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any, Dict, List


def _hash_payload(payload: Dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def create_chain() -> Dict[str, Any]:
    """Create a new blockchain with a genesis block."""
    genesis = {"index": 0, "event": "genesis", "payload": {}, "previous_hash": "0"}
    genesis["hash"] = _hash_payload(genesis)
    return {"blocks": [genesis]}


def append_block(chain: Dict[str, Any], event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Append a new block to the chain using the previous block hash."""
    previous_block = chain["blocks"][-1]
    block = {
        "index": len(chain["blocks"]),
        "event": event,
        "payload": deepcopy(payload),
        "previous_hash": previous_block["hash"],
    }
    block["hash"] = _hash_payload(block)
    chain["blocks"].append(block)
    return block


def validate_chain(chain: Dict[str, Any]) -> bool:
    """Validate the chain by checking each block hash and previous hash linkage."""
    blocks = chain["blocks"]
    if not blocks:
        return False

    for index, block in enumerate(blocks):
        if index == 0:
            expected_hash = _hash_payload({
                "index": block["index"],
                "event": block["event"],
                "payload": block["payload"],
                "previous_hash": block["previous_hash"],
            })
        else:
            expected_hash = _hash_payload({
                "index": block["index"],
                "event": block["event"],
                "payload": block["payload"],
                "previous_hash": block["previous_hash"],
            })

        if block["hash"] != expected_hash:
            return False
        if index > 0 and blocks[index - 1]["hash"] != block["previous_hash"]:
            return False
    return True
