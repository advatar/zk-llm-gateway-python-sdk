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


def _b64_zeros(n: int) -> str:
    return base64.b64encode(bytes([0] * n)).decode("ascii")


@dataclass
class ZkTicket:
    """Canonical gateway ticket payload.

    Mirrors `zk-llm-gateway/common/src/zk.rs`:
    - commitment_root: base64 bytes
    - nullifier: base64 bytes (unique)
    - token_class: class bound by proof
    - proof: base64 bytes
    """

    commitment_root: str
    nullifier: str
    token_class: TokenClass
    proof: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment_root": self.commitment_root,
            "nullifier": self.nullifier,
            "token_class": self.token_class.value,
            "proof": self.proof,
        }

    @classmethod
    def from_dict(
        cls,
        d: Dict[str, Any],
        *,
        fallback_token_class: Optional[TokenClass] = None,
    ) -> "ZkTicket":
        commitment_root = d.get("commitment_root", d.get("commitment_root_b64"))
        if commitment_root is None:
            commitment_root = _b64_zeros(32)

        nullifier = d.get("nullifier", d.get("nullifier_b64"))
        if nullifier is None:
            raise ValueError("ticket missing nullifier/nullifier_b64")

        proof = d.get("proof", d.get("proof_b64"))
        if proof is None:
            proof = ""

        tc_raw = d.get("token_class")
        if tc_raw is None:
            if fallback_token_class is None:
                raise ValueError("ticket missing token_class")
            token_class = fallback_token_class
        elif isinstance(tc_raw, TokenClass):
            token_class = tc_raw
        else:
            token_class = TokenClass.parse(str(tc_raw))

        return cls(
            commitment_root=str(commitment_root),
            nullifier=str(nullifier),
            token_class=token_class,
            proof=str(proof),
        )

    @staticmethod
    def random_dummy(token_class: TokenClass) -> "ZkTicket":
        root = os.urandom(32)
        nullifier = os.urandom(32)
        proof = os.urandom(64)
        return ZkTicket(
            commitment_root=base64.b64encode(root).decode("ascii"),
            nullifier=base64.b64encode(nullifier).decode("ascii"),
            token_class=token_class,
            proof=base64.b64encode(proof).decode("ascii"),
        )


class TicketSource:
    """Ticket source interface.

    Implementers can override:
    - next_ticket() for sync use
    - next_ticket_async() for async use (default calls next_ticket)
    """

    def next_ticket(self, token_class: TokenClass) -> ZkTicket:  # noqa: ARG002
        raise NotImplementedError

    async def next_ticket_async(self, token_class: TokenClass) -> ZkTicket:
        return self.next_ticket(token_class)


class DummyTicketSource(TicketSource):
    """Development-only ticket source."""

    def next_ticket(self, token_class: TokenClass) -> ZkTicket:
        return ZkTicket.random_dummy(token_class)


class FileTicketSource(TicketSource):
    """Ticket pool loaded from a JSON file (array of ticket objects)."""

    def __init__(self, tickets: Deque[Dict[str, Any]]):
        self._tickets = tickets

    @classmethod
    def from_path(cls, path: str | Path) -> "FileTicketSource":
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        tickets: Deque[Dict[str, Any]] = deque()
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    tickets.append(dict(item))
        return cls(tickets)

    def remaining(self) -> int:
        return len(self._tickets)

    def next_ticket(self, token_class: TokenClass) -> ZkTicket:
        exact_index = None
        fallback_index = None

        for i, item in enumerate(self._tickets):
            raw_tc = item.get("token_class")
            if raw_tc is None:
                if fallback_index is None:
                    fallback_index = i
                continue

            try:
                parsed = raw_tc if isinstance(raw_tc, TokenClass) else TokenClass.parse(str(raw_tc))
            except Exception:  # noqa: BLE001
                continue

            if parsed == token_class:
                exact_index = i
                break

        idx = exact_index if exact_index is not None else fallback_index
        if idx is None:
            raise TicketExhausted("ticket pool exhausted")

        item = self._tickets[idx]
        del self._tickets[idx]

        try:
            ticket = ZkTicket.from_dict(item, fallback_token_class=token_class)
        except Exception as e:  # noqa: BLE001
            raise TicketExhausted(f"invalid ticket entry: {e}") from e

        if ticket.token_class != token_class:
            raise TicketExhausted("ticket token_class mismatch")

        return ticket
