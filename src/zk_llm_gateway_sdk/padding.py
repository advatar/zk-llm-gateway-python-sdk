from __future__ import annotations

from .errors import InvalidPadding, PayloadTooLarge

MAGIC = b"ZKLG"
HEADER_LEN = 8


def pad_payload(payload: bytes, target_len: int) -> bytes:
    """Pad plaintext payload to an exact target length.

    Format:
    - 4 bytes: magic "ZKLG"
    - 4 bytes: u32 payload length (little endian)
    - N bytes: payload
    - remaining: filler

    This mirrors the Rust SDK padding format for interoperability.
    """
    if target_len < HEADER_LEN:
        raise InvalidPadding("target length too small")

    max_payload = target_len - HEADER_LEN
    if len(payload) > max_payload:
        raise PayloadTooLarge(actual=len(payload), limit=max_payload)

    out = bytearray(target_len)
    out[0:4] = MAGIC
    out[4:8] = (len(payload)).to_bytes(4, "little")
    out[8 : 8 + len(payload)] = payload

    # Low-entropy filler (inside encrypted payload).
    filler = b" \n"
    i = 8 + len(payload)
    j = 0
    while i < target_len:
        out[i] = filler[j % len(filler)]
        i += 1
        j += 1

    return bytes(out)


def unpad_payload(padded: bytes) -> bytes:
    """Remove padding applied by `pad_payload`."""
    if len(padded) < HEADER_LEN:
        raise InvalidPadding("padded payload too small")
    if padded[0:4] != MAGIC:
        raise InvalidPadding("bad magic")
    length = int.from_bytes(padded[4:8], "little")
    if length > len(padded) - HEADER_LEN:
        raise InvalidPadding("invalid length")
    return padded[8 : 8 + length]
