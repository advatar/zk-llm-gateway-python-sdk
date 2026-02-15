from __future__ import annotations

from enum import Enum

from .errors import InvalidTokenClass


class TokenClass(str, Enum):
    """Coarse bucket for request/response size shaping.

    Token classes map to fixed padded byte lengths for plaintext request/response.
    This reduces metadata leakage from variable request sizes.

    Note: these are pragmatic byte limits, not exact token counts.
    """

    C512 = "c512"
    C1024 = "c1024"
    C2048 = "c2048"
    C4096 = "c4096"

    @classmethod
    def parse(cls, value: str) -> "TokenClass":
        v = value.strip().lower()
        if v in {"c512", "512"}:
            return cls.C512
        if v in {"c1024", "1024"}:
            return cls.C1024
        if v in {"c2048", "2048"}:
            return cls.C2048
        if v in {"c4096", "4096"}:
            return cls.C4096
        raise InvalidTokenClass(f"invalid token class: {value!r}")

    def request_padded_len(self) -> int:
        return {
            TokenClass.C512: 8 * 1024,
            TokenClass.C1024: 16 * 1024,
            TokenClass.C2048: 32 * 1024,
            TokenClass.C4096: 64 * 1024,
        }[self]

    def response_padded_len(self) -> int:
        return {
            TokenClass.C512: 8 * 1024,
            TokenClass.C1024: 16 * 1024,
            TokenClass.C2048: 32 * 1024,
            TokenClass.C4096: 64 * 1024,
        }[self]

    def max_output_tokens_hint(self) -> int:
        return {
            TokenClass.C512: 512,
            TokenClass.C1024: 1024,
            TokenClass.C2048: 2048,
            TokenClass.C4096: 4096,
        }[self]
