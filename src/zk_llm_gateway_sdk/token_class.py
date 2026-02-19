from __future__ import annotations

from enum import Enum

from .errors import InvalidTokenClass


class TokenClass(str, Enum):
    """Coarse bucket for request/response size shaping.

    Values and sizing intentionally match the gateway's canonical protocol
    (`zk-llm-gateway/common/src/token.rs`).
    """

    C256 = "c256"
    C512 = "c512"
    C1024 = "c1024"
    C2048 = "c2048"
    C4096 = "c4096"

    @classmethod
    def parse(cls, value: str) -> "TokenClass":
        v = value.strip().lower()
        if v in {"c256", "256"}:
            return cls.C256
        if v in {"c512", "512"}:
            return cls.C512
        if v in {"c1024", "1024"}:
            return cls.C1024
        if v in {"c2048", "2048"}:
            return cls.C2048
        if v in {"c4096", "4096"}:
            return cls.C4096
        raise InvalidTokenClass(f"invalid token class: {value!r}")

    def max_prompt_bytes(self) -> int:
        return {
            TokenClass.C256: 2 * 1024,
            TokenClass.C512: 4 * 1024,
            TokenClass.C1024: 8 * 1024,
            TokenClass.C2048: 16 * 1024,
            TokenClass.C4096: 32 * 1024,
        }[self]

    def request_padded_len(self) -> int:
        return {
            TokenClass.C256: 8 * 1024,
            TokenClass.C512: 12 * 1024,
            TokenClass.C1024: 20 * 1024,
            TokenClass.C2048: 36 * 1024,
            TokenClass.C4096: 68 * 1024,
        }[self]

    def response_padded_len(self) -> int:
        return {
            TokenClass.C256: 8 * 1024,
            TokenClass.C512: 16 * 1024,
            TokenClass.C1024: 32 * 1024,
            TokenClass.C2048: 64 * 1024,
            TokenClass.C4096: 128 * 1024,
        }[self]

    def max_output_tokens_hint(self) -> int:
        return {
            TokenClass.C256: 256,
            TokenClass.C512: 512,
            TokenClass.C1024: 1024,
            TokenClass.C2048: 2048,
            TokenClass.C4096: 4096,
        }[self]

    def id_u8(self) -> int:
        return {
            TokenClass.C256: 1,
            TokenClass.C512: 2,
            TokenClass.C1024: 3,
            TokenClass.C2048: 4,
            TokenClass.C4096: 5,
        }[self]
