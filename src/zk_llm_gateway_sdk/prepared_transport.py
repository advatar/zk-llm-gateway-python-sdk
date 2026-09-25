"""Opt-in envelope-v2 clients. No hidden retries, issuer, or TEE claims.

The legacy GatewayClient remains a v1 client and is not used by this path.
Runtime authority and provider eligibility must be enforced by the trusted host.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .prepared import (AuthorizedInference, CLASSES, PreparedError, decode_b64,
                       decode_json, encode_json)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _public(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)


def _binding(label: bytes, class_id: int, request_id: str, client_nonce: bytes,
             ephemeral: bytes, gateway: bytes) -> bytes:
    return (label + bytes((2, class_id)) + request_id.encode("ascii")
            + client_nonce + ephemeral + gateway)


def _key(shared: bytes, material: bytes, class_id: int, direction: int) -> bytes:
    suffix = b"/req" if direction == 1 else b"/resp"
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=hashlib.sha256(material).digest(),
                info=b"zk-llm-gateway-envelope-v2" + suffix + bytes((class_id,))).derive(shared)


@dataclass(frozen=True, repr=False)
class _ResponseContext:
    authorization: AuthorizedInference
    client_nonce: bytes
    ephemeral: bytes
    key: bytes
    aad: bytes


def seal_request(authorization: AuthorizedInference, gateway_public_key: bytes) -> tuple[dict[str, Any], _ResponseContext]:
    authorization.validate()
    if type(gateway_public_key) is not bytes or len(gateway_public_key) != 32:
        raise PreparedError("invalid_gateway_key")
    prepared = authorization.prepared
    class_id, _, request_size, _ = CLASSES[prepared.token_class]
    ephemeral_key = X25519PrivateKey.generate()
    ephemeral = _public(ephemeral_key)
    client_nonce = os.urandom(32)
    nonce = os.urandom(12)
    try:
        shared = ephemeral_key.exchange(X25519PublicKey.from_public_bytes(gateway_public_key))
    except ValueError:
        raise PreparedError("invalid_gateway_key") from None
    if shared == bytes(32):
        raise PreparedError("noncontributory_gateway_key")
    args = (class_id, prepared.request_id, client_nonce, ephemeral, gateway_public_key)
    material = _binding(b"zk-llm-gateway-envelope-kdf-v2", *args)
    aad = _binding(b"zk-llm-gateway-envelope-aad-v2", *args)
    request_key = _key(shared, material, class_id, 1)
    response_key = _key(shared, material, class_id, 2)
    padded = authorization._payload.ljust(request_size, b"\0")
    ciphertext = ChaCha20Poly1305(request_key).encrypt(nonce, padded, aad + b"\1")
    envelope = {
        "v": 2, "token_class": prepared.token_class, "request_id": prepared.request_id,
        "client_nonce_b64": _b64(client_nonce), "eph_pubkey_b64": _b64(ephemeral),
        "nonce_b64": _b64(nonce), "ciphertext_b64": _b64(ciphertext),
    }
    return envelope, _ResponseContext(authorization, client_nonce, ephemeral,
                                      response_key, aad + b"\2")


def open_response(envelope: Any, context: _ResponseContext) -> dict[str, Any]:
    prepared = context.authorization.prepared
    try:
        if type(envelope) is not dict or type(envelope.get("v")) is not int or envelope["v"] != 2:
            raise PreparedError("unsupported_envelope_version")
        if envelope.get("request_id") != prepared.request_id or envelope.get("token_class") != prepared.token_class:
            raise PreparedError("response_binding_mismatch")
        if decode_b64(envelope.get("client_nonce_b64"), length=32) != context.client_nonce:
            raise PreparedError("response_binding_mismatch")
        if decode_b64(envelope.get("eph_pubkey_b64"), length=32) != context.ephemeral:
            raise PreparedError("response_binding_mismatch")
        nonce = decode_b64(envelope.get("nonce_b64"), length=12)
        expected_size = CLASSES[prepared.token_class][3]
        ciphertext = decode_b64(envelope.get("ciphertext_b64"), length=expected_size + 16)
        raw = ChaCha20Poly1305(context.key).decrypt(nonce, ciphertext, context.aad)
        payload = decode_json(raw.rstrip(b"\0"))
        if type(payload) is not dict:
            raise PreparedError("invalid_response_shape")
        if payload.get("kind") == "err":
            error = payload.get("error")
            if type(error) is not dict or error.get("request_id") != prepared.request_id:
                raise PreparedError("response_binding_mismatch")
            # Do not reflect arbitrary provider-supplied messages, codes or raw content.
            raise PreparedError("gateway_rejected", "gateway_reported_error")
        response = payload.get("response")
        if payload.get("kind") != "ok" or type(response) is not dict:
            raise PreparedError("invalid_response_shape")
        if (response.get("request_id") != prepared.request_id
                or response.get("model") != prepared.model
                or response.get("billed_token_class") != prepared.token_class
                or type(response.get("output")) is not str):
            raise PreparedError("response_binding_mismatch")
        return response
    except PreparedError as error:
        if error.code == "gateway_rejected":
            raise
        raise PreparedError(error.code, "dispatched_unknown") from None
    except Exception:
        # Cryptography/parser exceptions must not expose content in ordinary errors.
        raise PreparedError("invalid_encrypted_response", "dispatched_unknown") from None


@dataclass(frozen=True, repr=False)
class PreparedEndpoint:
    """Exact endpoint and public key, configured out-of-band by the trusted host."""

    url: str
    public_key: bytes
    allow_http_loopback: bool = False
    timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.url)
            parsed.port  # force invalid port validation
            if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                    or parsed.query or parsed.fragment or any(c.isspace() for c in self.url)
                    or "\\" in self.url):
                raise ValueError
            if parsed.scheme != "https":
                if not (self.allow_http_loopback and parsed.scheme == "http"
                        and ipaddress.ip_address(parsed.hostname).is_loopback):
                    raise ValueError
            if parsed.path not in ("/v1/infer", "/relay"):
                raise ValueError
            if type(self.public_key) is not bytes or len(self.public_key) != 32:
                raise ValueError
            if not 0 < self.timeout_seconds <= 300:
                raise ValueError
        except (ValueError, TypeError):
            raise PreparedError("invalid_endpoint_configuration") from None

    def __repr__(self) -> str:
        return "PreparedEndpoint(<configured>)"


def _response_limit(context: _ResponseContext) -> int:
    return 4 * ((CLASSES[context.authorization.prepared.token_class][3] + 18) // 3) + 2048


def _check_headers(response: httpx.Response, limit: int) -> None:
    if response.status_code != 200:
        raise PreparedError("unexpected_http_status", "dispatched_unknown")
    if response.headers.get("content-encoding", "identity").lower() != "identity":
        raise PreparedError("compressed_response_not_supported", "dispatched_unknown")
    length = response.headers.get("content-length")
    if length is not None:
        try:
            if not 0 <= int(length) <= limit:
                raise ValueError
        except ValueError:
            raise PreparedError("response_too_large", "dispatched_unknown") from None


class _BorrowedSyncTransport(httpx.BaseTransport):
    """A caller-owned transport must survive per-request client cleanup."""

    def __init__(self, transport: httpx.BaseTransport):
        self._transport = transport

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._transport.handle_request(request)

    def close(self) -> None:
        # The caller owns lifecycle and any resource or destination policy.
        pass


class _BorrowedAsyncTransport(httpx.AsyncBaseTransport):
    def __init__(self, transport: httpx.AsyncBaseTransport):
        self._transport = transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._transport.handle_async_request(request)

    async def aclose(self) -> None:
        pass


class PreparedSyncClient:
    def __init__(self, endpoint: PreparedEndpoint, *, transport: httpx.BaseTransport | None = None):
        self._endpoint = endpoint
        self._transport = transport

    def send_prepared(self, authorization: AuthorizedInference) -> dict[str, Any]:
        env, ctx = seal_request(authorization, self._endpoint.public_key)
        limit = _response_limit(ctx)
        try:
            # A fresh client prevents response cookies from linking later calls.
            with httpx.Client(transport=(_BorrowedSyncTransport(self._transport)
                                         if self._transport is not None else None),
                              trust_env=False, follow_redirects=False,
                              timeout=self._endpoint.timeout_seconds) as client:
                with client.stream("POST", self._endpoint.url, json=env,
                                   headers={"accept": "application/json", "accept-encoding": "identity"}) as response:
                    _check_headers(response, limit)
                    chunks = bytearray()
                    for chunk in response.iter_raw():
                        if len(chunks) + len(chunk) > limit:
                            raise PreparedError("response_too_large", "dispatched_unknown")
                        chunks.extend(chunk)
            return open_response(decode_json(bytes(chunks)), ctx)
        except PreparedError as error:
            raise PreparedError(error.code, "dispatched_unknown" if error.outcome == "not_dispatched" else error.outcome) from None
        except Exception:
            raise PreparedError("transport_failed", "dispatched_unknown") from None


class PreparedClient:
    def __init__(self, endpoint: PreparedEndpoint, *, transport: httpx.AsyncBaseTransport | None = None):
        self._endpoint = endpoint
        self._transport = transport

    async def send_prepared(self, authorization: AuthorizedInference) -> dict[str, Any]:
        env, ctx = seal_request(authorization, self._endpoint.public_key)
        limit = _response_limit(ctx)
        async def exchange() -> bytes:
            async with httpx.AsyncClient(transport=(_BorrowedAsyncTransport(self._transport)
                                                    if self._transport is not None else None),
                                         trust_env=False,
                                         follow_redirects=False,
                                         timeout=self._endpoint.timeout_seconds) as client:
                async with client.stream("POST", self._endpoint.url, json=env,
                                         headers={"accept": "application/json", "accept-encoding": "identity"}) as response:
                    _check_headers(response, limit)
                    chunks = bytearray()
                    async for chunk in response.aiter_raw():
                        if len(chunks) + len(chunk) > limit:
                            raise PreparedError("response_too_large", "dispatched_unknown")
                        chunks.extend(chunk)
            return bytes(chunks)

        try:
            raw = await asyncio.wait_for(exchange(), timeout=self._endpoint.timeout_seconds)
            return open_response(decode_json(raw), ctx)
        except asyncio.CancelledError:
            # Caller cancellation propagates; dispatch may already have happened.
            raise
        except PreparedError as error:
            raise PreparedError(error.code, "dispatched_unknown" if error.outcome == "not_dispatched" else error.outcome) from None
        except Exception:
            raise PreparedError("transport_failed", "dispatched_unknown") from None
