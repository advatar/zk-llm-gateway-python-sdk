from __future__ import annotations

import base64
import json
import os
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Deque, Dict, Optional

from .errors import TicketExhausted
from .token_class import TokenClass


@dataclass
class ZkTicket:
    """ZK-ready ticket payload.

    Fields are intentionally generic and opaque.
    """

    nullifier_b64: str
    proof_b64: str
    commitment_root_b64: Optional[str] = None
    extra: Optional[Any] = None
    ticket_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nullifier_b64": self.nullifier_b64,
            "proof_b64": self.proof_b64,
            "commitment_root_b64": self.commitment_root_b64,
            "extra": self.extra,
            "ticket_id": self.ticket_id,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ZkTicket":
        return cls(
            nullifier_b64=str(d["nullifier_b64"]),
            proof_b64=str(d.get("proof_b64", "")),
            commitment_root_b64=d.get("commitment_root_b64"),
            extra=d.get("extra"),
            ticket_id=d.get("ticket_id"),
        )

    @staticmethod
    def random_dummy() -> "ZkTicket":
        n = os.urandom(32)
        return ZkTicket(
            nullifier_b64=base64.b64encode(n).decode("ascii"),
            proof_b64=base64.b64encode(b"").decode("ascii"),
            commitment_root_b64=None,
            extra=None,
            ticket_id=None,
        )


class TicketSource:
    """Ticket source interface.

    Implementers can override:
    - next_ticket() for sync use
    - next_ticket_async() for async use (default calls next_ticket)

    This keeps the SDK ergonomic for both sync and async clients.
    """

    def next_ticket(self, token_class: TokenClass) -> ZkTicket:  # noqa: ARG002
        raise NotImplementedError

    async def next_ticket_async(self, token_class: TokenClass) -> ZkTicket:
        return self.next_ticket(token_class)


class DummyTicketSource(TicketSource):
    """Development-only ticket source."""

    def next_ticket(self, token_class: TokenClass) -> ZkTicket:  # noqa: ARG002
        return ZkTicket.random_dummy()


class FileTicketSource(TicketSource):
    """Ticket pool loaded from a JSON file (array of ZkTicket objects)."""

    def __init__(self, tickets: Deque[ZkTicket]):
        self._tickets = tickets

    @classmethod
    def from_path(cls, path: str | Path) -> "FileTicketSource":
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        tickets: Deque[ZkTicket] = deque()
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    tickets.append(ZkTicket.from_dict(item))
        return cls(tickets)

    def remaining(self) -> int:
        return len(self._tickets)

    def next_ticket(self, token_class: TokenClass) -> ZkTicket:  # noqa: ARG002
        try:
            return self._tickets.popleft()
        except IndexError as e:
            raise TicketExhausted("ticket pool exhausted") from e
