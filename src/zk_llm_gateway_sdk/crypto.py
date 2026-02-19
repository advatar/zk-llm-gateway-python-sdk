from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import Base64Error, CryptoError, InvalidGatewayPublicKey
from .padding import pad_payload, unpad_payload
from .token_class import TokenClass


class GatewayPublicKey:
    """Base64-encoded gateway public key (X25519)."""

    def __init__(self, raw32: bytes):
        if len(raw32) != 32:
            raise InvalidGatewayPublicKey("gateway public key must be 32 bytes")
        self._raw = raw32

    @classmethod
    def from_base64(cls, s: str) -> "GatewayPublicKey":
        try:
            raw = base64.b64decode(s.strip(), validate=True)
        except Exception as e:  # noqa: BLE001
            raise Base64Error(str(e)) from e
        if len(raw) != 32:
            raise InvalidGatewayPublicKey("gateway public key must decode to 32 bytes")
        return cls(raw)

    def to_base64(self) -> str:
        return base64.b64encode(self._raw).decode("ascii")

    def as_public_key(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(self._raw)

    @property
    def raw(self) -> bytes:
        return self._raw


@dataclass(frozen=True)
class Envelope:
    """JSON wrapper sent to the gateway/relay."""

    v: int
    token_class: TokenClass
    eph_pubkey_b64: str
    nonce_b64: str
    ciphertext_b64: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "v": self.v,
            "token_class": self.token_class.value,
            "eph_pubkey_b64": self.eph_pubkey_b64,
            "nonce_b64": self.nonce_b64,
            "ciphertext_b64": self.ciphertext_b64,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Envelope":
        v = d.get("v", d.get("version"))
        if v is None:
            raise CryptoError("missing envelope version")

        eph = d.get("eph_pubkey_b64", d.get("kem_pub_b64"))
        if eph is None:
            raise CryptoError("missing eph_pubkey_b64")

        return cls(
            v=int(v),
            token_class=TokenClass.parse(str(d["token_class"])),
            eph_pubkey_b64=str(eph),
            nonce_b64=str(d["nonce_b64"]),
            ciphertext_b64=str(d["ciphertext_b64"]),
        )


@dataclass(frozen=True)
class SealState:
    token_class: TokenClass
    eph_pubkey: bytes  # 32 bytes
    req_key: bytes  # 32 bytes
    resp_key: bytes  # 32 bytes


class _KeyDirection(Enum):
    REQUEST = 1
    RESPONSE = 2


def _aad(v: int, token_class: TokenClass, direction: _KeyDirection) -> bytes:
    # Matches gateway/common: [version, token_class_id, direction]
    return bytes([v & 0xFF, token_class.id_u8() & 0xFF, direction.value & 0xFF])


def _hkdf_info(token_class: TokenClass, direction: _KeyDirection) -> bytes:
    info = bytearray(b"zk-llm-gateway-envelope-v1")
    if direction is _KeyDirection.REQUEST:
        info.extend(b"/req")
    else:
        info.extend(b"/resp")
    info.append(token_class.id_u8() & 0xFF)
    return bytes(info)


def _derive_key(shared_secret: bytes, token_class: TokenClass, direction: _KeyDirection) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_hkdf_info(token_class, direction),
    )
    return hkdf.derive(shared_secret)


def seal_json(
    gateway_pk: GatewayPublicKey,
    token_class: TokenClass,
    payload: Any,
) -> Tuple[Envelope, SealState]:
    """Encrypt + pad a JSON payload into an Envelope.

    Returns (envelope, seal_state). Keep seal_state to decrypt the response.
    """
    v = 1

    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    padded = pad_payload(raw, token_class.request_padded_len())

    eph_sk = X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    try:
        eph_pub_bytes = eph_pk.public_bytes_raw()
    except AttributeError:
        from cryptography.hazmat.primitives import serialization

        eph_pub_bytes = eph_pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    shared = eph_sk.exchange(gateway_pk.as_public_key())
    req_key = _derive_key(shared, token_class, _KeyDirection.REQUEST)
    resp_key = _derive_key(shared, token_class, _KeyDirection.RESPONSE)

    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(req_key)
    a = _aad(v, token_class, _KeyDirection.REQUEST)

    try:
        ct = cipher.encrypt(nonce, padded, a)
    except Exception as e:  # noqa: BLE001
        raise CryptoError("encrypt failed") from e

    env = Envelope(
        v=v,
        token_class=token_class,
        eph_pubkey_b64=base64.b64encode(eph_pub_bytes).decode("ascii"),
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        ciphertext_b64=base64.b64encode(ct).decode("ascii"),
    )
    st = SealState(
        token_class=token_class,
        eph_pubkey=eph_pub_bytes,
        req_key=req_key,
        resp_key=resp_key,
    )
    return env, st


def open_json(env: Envelope, st: SealState) -> Any:
    """Decrypt an Envelope response using the SealState from the request."""
    if env.v != 1:
        raise CryptoError("unsupported envelope version")
    if env.token_class != st.token_class:
        raise CryptoError("token_class mismatch")

    try:
        eph_pub = base64.b64decode(env.eph_pubkey_b64.strip(), validate=True)
        nonce = base64.b64decode(env.nonce_b64.strip(), validate=True)
        ct = base64.b64decode(env.ciphertext_b64.strip(), validate=True)
    except Exception as e:  # noqa: BLE001
        raise Base64Error(str(e)) from e

    if len(eph_pub) != 32 or len(nonce) != 12:
        raise CryptoError("invalid envelope fields")

    # Gateway should echo the request ephemeral pubkey.
    if eph_pub != st.eph_pubkey:
        raise CryptoError("unexpected eph_pubkey in response")

    cipher = ChaCha20Poly1305(st.resp_key)
    a = _aad(env.v, env.token_class, _KeyDirection.RESPONSE)

    try:
        padded = cipher.decrypt(nonce, ct, a)
    except Exception as e:  # noqa: BLE001
        raise CryptoError("decrypt failed") from e

    raw = unpad_payload(padded)
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        raise CryptoError("invalid decrypted JSON") from e
