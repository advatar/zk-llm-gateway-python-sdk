import asyncio
import base64
import json
import os
from enum import Enum

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zk_llm_gateway_sdk.client import GatewayClient, GatewaySyncClient
from zk_llm_gateway_sdk.crypto import Envelope, GatewayPublicKey
from zk_llm_gateway_sdk.openai_types import ChatCompletionsRequest, ChatMessage
from zk_llm_gateway_sdk.padding import pad_payload, unpad_payload
from zk_llm_gateway_sdk.tickets import TicketSource, ZkTicket
from zk_llm_gateway_sdk.token_class import TokenClass


class _Dir(Enum):
    REQUEST = 1
    RESPONSE = 2


class FixedTicketSource(TicketSource):
    def __init__(self, ticket: ZkTicket):
        self.ticket = ticket

    def next_ticket(self, token_class: TokenClass) -> ZkTicket:
        assert token_class == self.ticket.token_class
        return self.ticket

    async def next_ticket_async(self, token_class: TokenClass) -> ZkTicket:
        return self.next_ticket(token_class)


def _aad(v: int, token_class: TokenClass, direction: _Dir) -> bytes:
    return bytes([v, token_class.id_u8(), direction.value])


def _hkdf_info(token_class: TokenClass, direction: _Dir) -> bytes:
    out = bytearray(b"zk-llm-gateway-envelope-v1")
    out.extend(b"/req" if direction is _Dir.REQUEST else b"/resp")
    out.append(token_class.id_u8())
    return bytes(out)


def _derive_key(shared_secret: bytes, token_class: TokenClass, direction: _Dir) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_hkdf_info(token_class, direction))
    return hkdf.derive(shared_secret)


def _decrypt_request_payload(gateway_sk: X25519PrivateKey, envelope: Envelope) -> dict:
    eph_pub = X25519PublicKey.from_public_bytes(base64.b64decode(envelope.eph_pubkey_b64))
    shared = gateway_sk.exchange(eph_pub)
    req_key = _derive_key(shared, envelope.token_class, _Dir.REQUEST)
    nonce = base64.b64decode(envelope.nonce_b64)
    ct = base64.b64decode(envelope.ciphertext_b64)
    padded = ChaCha20Poly1305(req_key).decrypt(nonce, ct, _aad(envelope.v, envelope.token_class, _Dir.REQUEST))
    return json.loads(unpad_payload(padded).decode("utf-8"))


def _encrypt_response_payload(
    gateway_sk: X25519PrivateKey,
    request_envelope: Envelope,
    payload: dict,
) -> Envelope:
    eph_pub = X25519PublicKey.from_public_bytes(base64.b64decode(request_envelope.eph_pubkey_b64))
    shared = gateway_sk.exchange(eph_pub)
    resp_key = _derive_key(shared, request_envelope.token_class, _Dir.RESPONSE)
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    padded = pad_payload(raw, request_envelope.token_class.response_padded_len())
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(resp_key).encrypt(
        nonce,
        padded,
        _aad(request_envelope.v, request_envelope.token_class, _Dir.RESPONSE),
    )
    return Envelope(
        v=request_envelope.v,
        token_class=request_envelope.token_class,
        eph_pubkey_b64=request_envelope.eph_pubkey_b64,
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        ciphertext_b64=base64.b64encode(ct).decode("ascii"),
    )


def _raw_public_bytes(pk: X25519PublicKey) -> bytes:
    try:
        return pk.public_bytes_raw()
    except AttributeError:
        from cryptography.hazmat.primitives import serialization

        return pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def test_async_client_forwards_passthrough_fields_and_reconstructs_upstream_body() -> None:
    gateway_sk = X25519PrivateKey.generate()
    gateway_pk = GatewayPublicKey(_raw_public_bytes(gateway_sk.public_key()))
    ticket = ZkTicket.random_dummy(TokenClass.C2048)

    def handler(request: httpx.Request) -> httpx.Response:
        request_envelope = Envelope.from_dict(json.loads(request.content.decode("utf-8")))
        payload = _decrypt_request_payload(gateway_sk, request_envelope)

        assert payload["stream"] is False
        assert payload["top_p"] == pytest.approx(0.1)
        assert payload["response_format"] == {"type": "json_object"}
        assert payload["tools"][0]["function"]["name"] == "lookup_weather"
        assert payload["token_class"] == "c2048"
        assert payload["ticket"]["nullifier"] == ticket.nullifier

        response_envelope = _encrypt_response_payload(
            gateway_sk,
            request_envelope,
            {
                "kind": "ok",
                "response": {
                    "request_id": payload["request_id"],
                    "model": payload["model"],
                    "output": "",
                    "billed_token_class": payload["token_class"],
                    "upstream": {
                        "id": "chatcmpl-123",
                        "model": payload["model"],
                        "choices": [
                            {
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": None,
                                    "tool_calls": [
                                        {
                                            "id": "call_1",
                                            "type": "function",
                                            "function": {
                                                "name": "lookup_weather",
                                                "arguments": "{\"city\":\"Stockholm\"}",
                                            },
                                        }
                                    ],
                                },
                                "finish_reason": "tool_calls",
                            }
                        ],
                    },
                },
            },
        )
        return httpx.Response(200, json=response_envelope.to_dict())

    async def run() -> None:
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http:
            client = GatewayClient(
                "https://gateway.example.com",
                gateway_pk,
                FixedTicketSource(ticket),
                http=http,
            )
            response = await client.chat_completions(
                TokenClass.C2048,
                ChatCompletionsRequest(
                    model="gpt-4o-mini",
                    messages=[ChatMessage.user("hello")],
                    stream=False,
                    extra={
                        "top_p": 0.1,
                        "response_format": {"type": "json_object"},
                        "tools": [{"type": "function", "function": {"name": "lookup_weather"}}],
                    },
                ),
            )

        assert response.id == "chatcmpl-123"
        assert response.extra["billed_token_class"] == "c2048"
        assert response.choices[0].message is not None
        assert response.choices[0].message.content == ""
        assert response.choices[0].message.extra["tool_calls"][0]["function"]["name"] == "lookup_weather"

    asyncio.run(run())


def test_sync_client_rejects_stream_true_before_network() -> None:
    gateway_sk = X25519PrivateKey.generate()
    gateway_pk = GatewayPublicKey(_raw_public_bytes(gateway_sk.public_key()))
    ticket = ZkTicket.random_dummy(TokenClass.C512)
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        raise AssertionError(f"unexpected network request: {request.url}")

    client = GatewaySyncClient(
        "https://gateway.example.com",
        gateway_pk,
        FixedTicketSource(ticket),
        http=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(Exception, match="stream=true is not supported"):
        client.infer_json(
            TokenClass.C512,
            {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            },
        )

    assert called is False
